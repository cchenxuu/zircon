// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See the README.md in this directory for documentation.

#include <ddk/binding.h>
#include <ddk/debug.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <ddk/io-buffer.h>

#include <zircon/device/cpu-trace/intel-pm.h>
#include <zircon/mtrace.h>
#include <zircon/syscalls.h>
#include <zircon/syscalls/resource.h>
#include <zircon/types.h>

#include <assert.h>
#include <cpuid.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu-trace-private.h"

// TODO(dje): Having trouble getting this working, so just punt for now.
#define TRY_FREEZE_ON_PMI 0

// Individual bits in the fixed counter enable field.
// See Intel Volume 3, Figure 18-2 "Layout of IA32_FIXED_CTR_CTRL MSR".
#define FIXED_CTR_ENABLE_OS 1
#define FIXED_CTR_ENABLE_USR 2

// There's only a few fixed events, so handle them directly.
typedef enum {
#define DEF_FIXED_EVENT(symbol, id, regnum, flags, name, description) \
    symbol ## _ID = CPUPERF_MAKE_EVENT_ID(CPUPERF_UNIT_FIXED, id),
#include <zircon/device/cpu-trace/intel-pm-events.inc>
} fixed_event_id_t;

// Verify each fixed counter regnum < IPM_MAX_FIXED_COUNTERS.
#define DEF_FIXED_EVENT(symbol, id, regnum, flags, name, description) \
    && (regnum) < IPM_MAX_FIXED_COUNTERS
static_assert(1
#include <zircon/device/cpu-trace/intel-pm-events.inc>
    , "");

typedef enum {
#define DEF_ARCH_EVENT(symbol, id, ebx_bit, event, umask, flags, name, description) \
    symbol,
#include <zircon/device/cpu-trace/intel-pm-events.inc>
} arch_event_t;

typedef enum {
#define DEF_SKL_EVENT(symbol, id, event, umask, flags, name, description) \
    symbol,
#include <zircon/device/cpu-trace/skylake-pm-events.inc>
} model_event_t;

typedef struct {
    uint32_t event;
    uint32_t umask;
    uint32_t flags;
} event_details_t;

static const event_details_t kArchEvents[] = {
#define DEF_ARCH_EVENT(symbol, id, ebx_bit, event, umask, flags, name, description) \
    { event, umask, flags },
#include <zircon/device/cpu-trace/intel-pm-events.inc>
};

static const event_details_t kModelEvents[] = {
#define DEF_SKL_EVENT(symbol, id, event, umask, flags, name, description) \
    { event, umask, flags },
#include <zircon/device/cpu-trace/skylake-pm-events.inc>
};

static const uint16_t kArchEventMap[] = {
#define DEF_ARCH_EVENT(symbol, id, ebx_bit, event, umask, flags, name, description) \
    [id] = symbol,
#include <zircon/device/cpu-trace/intel-pm-events.inc>
};
static_assert(countof(kArchEventMap) <= CPUPERF_MAX_EVENT + 1, "");

static const uint16_t kModelEventMap[] = {
#define DEF_SKL_EVENT(symbol, id, event, umask, flags, name, description) \
    [id] = symbol,
#include <zircon/device/cpu-trace/skylake-pm-events.inc>
};
static_assert(countof(kModelEventMap) <= CPUPERF_MAX_EVENT + 1, "");

// All configuration data is staged here before writing any MSRs, etc.
// Then when ready the "START" ioctl will write all the necessary MSRS,
// and do whatever kernel operations are required for collecting data.

typedef struct ipm_per_trace_state {
    // true if |config| has been set.
    bool configured;

    // The trace configuration as given to us via the ioctl.
    cpuperf_config_t ioctl_config;

    // The internalized form of |config| that we pass to the kernel.
    zx_x86_ipm_config_t config;

    // # of entries in |buffers|.
    // TODO(dje): This is generally the number of cpus, but it could be
    // something else later.
    uint32_t num_buffers;

    // Each buffer is the same size (at least for now, KISS).
    // There is one buffer per cpu.
    // This is a uint32 instead of uint64 as there's no point in supporting
    // that large of a buffer.
    uint32_t buffer_size;

    io_buffer_t* buffers;
} ipm_per_trace_state_t;

typedef struct ipm_device {
    // Once tracing has started various things are not allowed until it stops.
    bool active;

    // one entry for each trace
    // TODO(dje): At the moment we only support one trace at a time.
    // "trace" == "data collection run"
    ipm_per_trace_state_t* per_trace_state;
} ipm_device_t;

static bool ipm_supported = false;
// This is only valid if |ipm_supported| is true.
static zx_x86_ipm_properties_t ipm_properties;

// maximum space, in bytes, for trace buffers (per cpu)
#define MAX_PER_TRACE_SPACE (256 * 1024 * 1024)

void ipm_init_once(void)
{
    zx_x86_ipm_properties_t props;
    zx_handle_t resource = get_root_resource();
    zx_status_t status =
        zx_mtrace_control(resource, MTRACE_KIND_IPM, MTRACE_IPM_GET_PROPERTIES,
                          0, &props, sizeof(props));
    if (status != ZX_OK) {
        if (status == ZX_ERR_NOT_SUPPORTED)
            zxlogf(INFO, "%s: No PM support\n", __func__);
        else
            zxlogf(INFO, "%s: Error %d fetching ipm properties\n",
                   __func__, status);
        return;
    }

    // Skylake supports version 4. KISS and begin with that.
    // Note: This should agree with the kernel driver's check.
    if (props.pm_version < 4) {
        zxlogf(INFO, "%s: PM version 4 or above is required\n", __func__);
        return;
    }

    ipm_supported = true;
    ipm_properties = props;

    zxlogf(TRACE, "Intel Performance Monitor configuration for this chipset:\n");
    zxlogf(TRACE, "IPM: version: %u\n", ipm_properties.pm_version);
    zxlogf(TRACE, "IPM: num_programmable_counters: %u\n",
           ipm_properties.num_programmable_counters);
    zxlogf(TRACE, "IPM: num_fixed_counters: %u\n",
           ipm_properties.num_fixed_counters);
    zxlogf(TRACE, "IPM: programmable_counter_width: %u\n",
           ipm_properties.programmable_counter_width);
    zxlogf(TRACE, "IPM: fixed_counter_width: %u\n",
           ipm_properties.fixed_counter_width);
    zxlogf(TRACE, "IPM: perf_capabilities: %lu\n",
           ipm_properties.perf_capabilities);
}


// Helper routines for the ioctls.

static void ipm_free_buffers_for_trace(ipm_per_trace_state_t* per_trace, uint32_t num_allocated) {
    // Note: This may be called with partially allocated buffers.
    assert(per_trace->buffers);
    assert(num_allocated <= per_trace->num_buffers);
    for (uint32_t i = 0; i < num_allocated; ++i)
        io_buffer_release(&per_trace->buffers[i]);
    free(per_trace->buffers);
    per_trace->buffers = NULL;
}

// Map a fixed counter event id to its h/w register number.
// Returns IPM_MAX_FIXED_COUNTERS if |id| is unknown.
static unsigned ipm_fixed_counter_number(cpuperf_event_id_t id) {
    enum {
#define DEF_FIXED_EVENT(symbol, id, regnum, flags, name, description) \
        symbol ## _NUMBER = regnum,
#include <zircon/device/cpu-trace/intel-pm-events.inc>
    };
    switch (id) {
    case FIXED_INSTRUCTIONS_RETIRED_ID:
        return FIXED_INSTRUCTIONS_RETIRED_NUMBER;
    case FIXED_UNHALTED_CORE_CYCLES_ID:
        return FIXED_UNHALTED_CORE_CYCLES_NUMBER;
    case FIXED_UNHALTED_REFERENCE_CYCLES_ID:
        return FIXED_UNHALTED_REFERENCE_CYCLES_NUMBER;
    default:
        return IPM_MAX_FIXED_COUNTERS;
    }
}


// The userspace side of the driver.

static zx_status_t ipm_get_properties(cpu_trace_device_t* dev,
                                      void* reply, size_t replymax,
                                      size_t* out_actual) {
    zxlogf(TRACE, "%s called\n", __func__);

    if (!ipm_supported)
        return ZX_ERR_NOT_SUPPORTED;

    cpuperf_properties_t props;
    if (replymax < sizeof(props))
        return ZX_ERR_BUFFER_TOO_SMALL;

    props.api_version = CPUPERF_API_VERSION;
    props.pm_version = ipm_properties.pm_version;
    props.num_fixed_counters = ipm_properties.num_fixed_counters;
    props.num_programmable_counters = ipm_properties.num_programmable_counters;
    props.fixed_counter_width = ipm_properties.fixed_counter_width;
    props.programmable_counter_width = ipm_properties.programmable_counter_width;

    memcpy(reply, &props, sizeof(props));
    *out_actual = sizeof(props);
    return ZX_OK;
}

static zx_status_t ipm_alloc_trace(cpu_trace_device_t* dev,
                                   const void* cmd, size_t cmdlen) {
    zxlogf(TRACE, "%s called\n", __func__);

    if (!ipm_supported)
        return ZX_ERR_NOT_SUPPORTED;
    if (dev->ipm)
        return ZX_ERR_BAD_STATE;

    // Note: The remaining API calls don't have to check |ipm_supported|
    // because this will never succeed otherwise, and they all require this
    // to be done first.

    ioctl_cpuperf_alloc_t alloc;
    if (cmdlen != sizeof(alloc))
        return ZX_ERR_INVALID_ARGS;
    memcpy(&alloc, cmd, sizeof(alloc));
    if (alloc.buffer_size > MAX_PER_TRACE_SPACE)
        return ZX_ERR_INVALID_ARGS;
    uint32_t num_cpus = zx_system_get_num_cpus();
    if (alloc.num_buffers != num_cpus) // TODO(dje): for now
        return ZX_ERR_INVALID_ARGS;

    ipm_device_t* ipm = calloc(1, sizeof(*dev->ipm));
    if (!ipm)
        return ZX_ERR_NO_MEMORY;

    ipm_per_trace_state_t* per_trace = calloc(1, sizeof(ipm->per_trace_state[0]));
    if (!per_trace) {
        free(ipm);
        return ZX_ERR_NO_MEMORY;
    }

    per_trace->buffers = calloc(num_cpus, sizeof(per_trace->buffers[0]));
    if (!per_trace->buffers) {
        free(per_trace);
        free(ipm);
        return ZX_ERR_NO_MEMORY;
    }

    uint32_t i = 0;
    for ( ; i < num_cpus; ++i) {
        zx_status_t status =
            io_buffer_init(&per_trace->buffers[i],
                           alloc.buffer_size, IO_BUFFER_RW);
        if (status != ZX_OK)
            break;
    }
    if (i != num_cpus) {
        ipm_free_buffers_for_trace(per_trace, i);
        free(per_trace);
        free(ipm);
        return ZX_ERR_NO_MEMORY;
    }

    per_trace->num_buffers = alloc.num_buffers;
    per_trace->buffer_size = alloc.buffer_size;
    ipm->per_trace_state = per_trace;
    dev->ipm = ipm;
    return ZX_OK;
}

static zx_status_t ipm_free_trace(cpu_trace_device_t* dev) {
    zxlogf(TRACE, "%s called\n", __func__);

    ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;
    if (ipm->active)
        return ZX_ERR_BAD_STATE;

    ipm_per_trace_state_t* per_trace = ipm->per_trace_state;
    ipm_free_buffers_for_trace(per_trace, per_trace->num_buffers);
    free(per_trace);
    free(ipm);
    dev->ipm = NULL;
    return ZX_OK;
}

static zx_status_t ipm_get_alloc(cpu_trace_device_t* dev,
                                 void* reply, size_t replymax,
                                 size_t* out_actual) {
    zxlogf(TRACE, "%s called\n", __func__);

    const ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;

    ioctl_cpuperf_alloc_t alloc;
    if (replymax < sizeof(alloc))
        return ZX_ERR_BUFFER_TOO_SMALL;

    alloc.num_buffers = ipm->per_trace_state->num_buffers;
    alloc.buffer_size = ipm->per_trace_state->buffer_size;
    memcpy(reply, &alloc, sizeof(alloc));
    *out_actual = sizeof(alloc);
    return ZX_OK;
}

static zx_status_t ipm_get_buffer_handle(cpu_trace_device_t* dev,
                                         const void* cmd, size_t cmdlen,
                                         void* reply, size_t replymax,
                                         size_t* out_actual) {
    zxlogf(TRACE, "%s called\n", __func__);

    ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;

    ioctl_cpuperf_buffer_handle_req_t req;
    zx_handle_t h;

    if (cmdlen != sizeof(req))
        return ZX_ERR_INVALID_ARGS;
    if (replymax < sizeof(h))
        return ZX_ERR_BUFFER_TOO_SMALL;
    const ipm_per_trace_state_t* per_trace = ipm->per_trace_state;
    memcpy(&req, cmd, sizeof(req));
    if (req.descriptor >= per_trace->num_buffers)
        return ZX_ERR_INVALID_ARGS;

    zx_status_t status = zx_handle_duplicate(per_trace->buffers[req.descriptor].vmo_handle, ZX_RIGHT_SAME_RIGHTS, &h);
    if (status < 0)
        return status;
    memcpy(reply, &h, sizeof(h));
    *out_actual = sizeof(h);
    return ZX_OK;
}

static zx_status_t ipm_stage_config(cpu_trace_device_t* dev,
                                    const void* cmd, size_t cmdlen) {
    zxlogf(TRACE, "%s called\n", __func__);

    ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;
    if (ipm->active)
        return ZX_ERR_BAD_STATE;

    // If we subsequently get an error, make sure any previous configuration
    // can't be used.
    ipm_per_trace_state_t* per_trace = ipm->per_trace_state;
    per_trace->configured = false;

    cpuperf_config_t ioctl_config;
    cpuperf_config_t* icfg = &ioctl_config;
    if (cmdlen != sizeof(*icfg))
        return ZX_ERR_INVALID_ARGS;
    memcpy(icfg, cmd, sizeof(*icfg));

    zx_x86_ipm_config_t* ocfg = &per_trace->config;
    memset(ocfg, 0, sizeof(*ocfg));

    // Validate the config and convert it to our internal form.
    // TODO(dje): Multiplexing support.
    const unsigned max_num_fixed = ipm_properties.num_fixed_counters;
    const unsigned max_num_programmable = ipm_properties.num_programmable_counters;
    unsigned num_fixed = 0;
    unsigned num_programmable = 0;

    const uint64_t max_fixed_value =
        (ipm_properties.fixed_counter_width < 64
         ? (1ul << ipm_properties.fixed_counter_width) - 1
         : ~0ul);
    const uint64_t max_programmable_value =
        (ipm_properties.programmable_counter_width < 64
         ? (1ul << ipm_properties.programmable_counter_width) - 1
         : ~0ul);

    // For catching duplicates of the fixed counters.
    bool have_fixed[max_num_fixed];
    for (unsigned i = 0; i < max_num_fixed; ++i)
        have_fixed[i] = false;

    bool have_timebase0 = false;
    unsigned i;
    for (i = 0; i < countof(icfg->counters); ++i) {
        cpuperf_event_id_t id = icfg->counters[i];
        zxlogf(TRACE, "%s: processing [%u] = %u\n", __func__, i, id);
        if (id == 0)
            break;
        unsigned unit = CPUPERF_EVENT_ID_UNIT(id);
        unsigned event = CPUPERF_EVENT_ID_EVENT(id);
        unsigned fixed = ipm_fixed_counter_number(id);
        bool uses_timebase0 = !!(icfg->flags[i] & CPUPERF_CONFIG_FLAG_TIMEBASE0);

        if (fixed != IPM_MAX_FIXED_COUNTERS) {
            assert(fixed < countof(ocfg->fixed_ids));
            assert(fixed < max_num_fixed);
            if (have_fixed[fixed]) {
                zxlogf(ERROR, "%s: Fixed counter %d already provided\n",
                       __func__, fixed);
                return ZX_ERR_INVALID_ARGS;
            }
            have_fixed[fixed] = true;
            ocfg->fixed_ids[num_fixed] = id;
            if (uses_timebase0 || icfg->rate[i] == 0) {
                ocfg->fixed_initial_value[num_fixed] = 0;
            } else {
                if (icfg->rate[i] > max_fixed_value) {
                    zxlogf(ERROR, "%s: Rate too large, counter %u\n",
                           __func__, i);
                    return ZX_ERR_INVALID_ARGS;
                }
                ocfg->fixed_initial_value[num_fixed] =
                    max_fixed_value - icfg->rate[i] + 1;
            }
            // KISS: For now don't generate PMI's for counters that use
            // another as the timebase.
            if (!uses_timebase0)
                ocfg->fixed_ctrl |= IA32_FIXED_CTR_CTRL_PMI_MASK(fixed);
            unsigned enable = 0;
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_OS)
                enable |= FIXED_CTR_ENABLE_OS;
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_USER)
                enable |= FIXED_CTR_ENABLE_USR;
            ocfg->fixed_ctrl |= enable << IA32_FIXED_CTR_CTRL_EN_SHIFT(fixed);
            ocfg->global_ctrl |= IA32_PERF_GLOBAL_CTRL_FIXED_EN_MASK(fixed);
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_TIMEBASE0)
                ocfg->fixed_flags[num_fixed] |= IPM_CONFIG_FLAG_TIMEBASE;
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_PC)
                ocfg->fixed_flags[num_fixed] |= IPM_CONFIG_FLAG_PC;
            ++num_fixed;
        } else {
            // TODO(dje): Verify no duplicates.
            if (num_programmable == max_num_programmable) {
                zxlogf(ERROR, "%s: Too many programmable counters provided\n",
                       __func__);
                return ZX_ERR_INVALID_ARGS;
            }
            ocfg->programmable_ids[num_programmable] = id;
            if (uses_timebase0 || icfg->rate[i] == 0) {
                ocfg->programmable_initial_value[num_programmable] = 0;
            } else {
                if (icfg->rate[i] > max_programmable_value) {
                    zxlogf(ERROR, "%s: Rate too large, counter %u\n",
                           __func__, i);
                    return ZX_ERR_INVALID_ARGS;
                }
                ocfg->programmable_initial_value[num_programmable] =
                    max_programmable_value - icfg->rate[i] + 1;
            }
            const event_details_t* details = NULL;
            switch (unit) {
                case CPUPERF_UNIT_ARCH:
                    if (event >= countof(kArchEventMap)) {
                        zxlogf(ERROR, "%s: Invalid event id, counter %u\n",
                               __func__, i);
                        return ZX_ERR_INVALID_ARGS;
                    }
                    details = &kArchEvents[kArchEventMap[event]];
                    break;
                case CPUPERF_UNIT_MODEL:
                    if (event >= countof(kModelEventMap)) {
                        zxlogf(ERROR, "%s: Invalid event id, counter %u\n",
                               __func__, i);
                        return ZX_ERR_INVALID_ARGS;
                    }
                    details = &kModelEvents[kModelEventMap[event]];
                    break;
                default:
                    zxlogf(ERROR, "%s: Invalid event id, counter %u\n",
                           __func__, i);
                    return ZX_ERR_INVALID_ARGS;
            }
            if (details->event == 0 && details->umask == 0) {
                zxlogf(ERROR, "%s: Invalid event id, counter %u\n",
                       __func__, i);
                return ZX_ERR_INVALID_ARGS;
            }
            uint64_t evtsel = 0;
            evtsel |= details->event << IA32_PERFEVTSEL_EVENT_SELECT_SHIFT;
            evtsel |= details->umask << IA32_PERFEVTSEL_UMASK_SHIFT;
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_OS)
                evtsel |= IA32_PERFEVTSEL_OS_MASK;
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_USER)
                evtsel |= IA32_PERFEVTSEL_USR_MASK;
            if (details->flags & IPM_REG_FLAG_EDG)
                evtsel |= IA32_PERFEVTSEL_E_MASK;
            if (details->flags & IPM_REG_FLAG_ANYT)
                evtsel |= IA32_PERFEVTSEL_ANY_MASK;
            if (details->flags & IPM_REG_FLAG_INV)
                evtsel |= IA32_PERFEVTSEL_INV_MASK;
            evtsel |= (details->flags & IPM_REG_FLAG_CMSK_MASK) << IA32_PERFEVTSEL_CMASK_SHIFT;
            // KISS: For now don't generate PMI's for counters that use
            // another as the timebase. We still generate interrupts in
            // "counting mode" in case the counter overflows.
            if (!uses_timebase0)
                evtsel |= IA32_PERFEVTSEL_INT_MASK;
            evtsel |= IA32_PERFEVTSEL_EN_MASK;
            ocfg->programmable_events[num_programmable] = evtsel;
            ocfg->global_ctrl |= IA32_PERF_GLOBAL_CTRL_PMC_EN_MASK(num_programmable);
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_TIMEBASE0)
                ocfg->programmable_flags[num_programmable] |= IPM_CONFIG_FLAG_TIMEBASE;
            if (icfg->flags[i] & CPUPERF_CONFIG_FLAG_PC)
                ocfg->programmable_flags[num_programmable] |= IPM_CONFIG_FLAG_PC;
            ++num_programmable;
        }

        if (uses_timebase0)
            have_timebase0 = true;
    }
    if (i == 0) {
        zxlogf(ERROR, "%s: No counters provided\n", __func__);
        return ZX_ERR_INVALID_ARGS;
    }

    // Ensure there are no holes.
    for (; i < countof(icfg->counters); ++i) {
        if (icfg->counters[i] != 0) {
            zxlogf(ERROR, "%s: Hole at counter %u\n", __func__, i);
            return ZX_ERR_INVALID_ARGS;
        }
    }

    if (have_timebase0) {
        ocfg->timebase_id = icfg->counters[0];
    }

#if TRY_FREEZE_ON_PMI
    ocfg->debug_ctrl |= IA32_DEBUGCTL_FREEZE_PERFMON_ON_PMI_MASK;
#endif

    // Require something to be enabled in order to start tracing.
    // This is mostly a sanity check.
    if (per_trace->config.global_ctrl == 0) {
        zxlogf(ERROR, "%s: Requested config doesn't collect any data\n",
               __func__);
        return ZX_ERR_INVALID_ARGS;
    }

    per_trace->ioctl_config = *icfg;
    per_trace->configured = true;
    return ZX_OK;
}

static zx_status_t ipm_get_config(cpu_trace_device_t* dev,
                                  void* reply, size_t replymax,
                                  size_t* out_actual) {
    zxlogf(TRACE, "%s called\n", __func__);

    const ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;

    const ipm_per_trace_state_t* per_trace = ipm->per_trace_state;
    if (!per_trace->configured)
        return ZX_ERR_BAD_STATE;

    const cpuperf_config_t* config = &per_trace->ioctl_config;
    if (replymax < sizeof(*config))
        return ZX_ERR_BUFFER_TOO_SMALL;

    memcpy(reply, config, sizeof(*config));
    *out_actual = sizeof(*config);
    return ZX_OK;
}

static zx_status_t ipm_start(cpu_trace_device_t* dev) {
    zxlogf(TRACE, "%s called\n", __func__);

    ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;
    if (ipm->active)
        return ZX_ERR_BAD_STATE;

    ipm_per_trace_state_t* per_trace = ipm->per_trace_state;
    if (!per_trace->configured)
        return ZX_ERR_BAD_STATE;

    // Step 1: Get the configuration data into the kernel for use by START.

    zxlogf(TRACE, "%s: global ctrl 0x%" PRIx64 ", fixed ctrl 0x%" PRIx64 "\n",
           __func__, per_trace->config.global_ctrl,
           per_trace->config.fixed_ctrl);

    // |per_trace->configured| should not have been set if there's nothing
    // to trace.
    assert(per_trace->config.global_ctrl != 0);

    zx_handle_t resource = get_root_resource();

    zx_status_t status =
        zx_mtrace_control(resource, MTRACE_KIND_IPM,
                          MTRACE_IPM_INIT, 0, NULL, 0);
    if (status != ZX_OK)
        return status;

    uint32_t num_cpus = zx_system_get_num_cpus();
    for (uint32_t cpu = 0; cpu < num_cpus; ++cpu) {
        zx_x86_ipm_buffer_t buffer;
        io_buffer_t* io_buffer = &per_trace->buffers[cpu];
        buffer.vmo = io_buffer->vmo_handle;
        status = zx_mtrace_control(resource, MTRACE_KIND_IPM,
                                   MTRACE_IPM_ASSIGN_BUFFER, cpu,
                                   &buffer, sizeof(buffer));
        if (status != ZX_OK)
            goto fail;
    }

    status = zx_mtrace_control(resource, MTRACE_KIND_IPM,
                               MTRACE_IPM_STAGE_CONFIG, 0,
                               &per_trace->config, sizeof(per_trace->config));
    if (status != ZX_OK)
        goto fail;

    // Step 2: Start data collection.

    status = zx_mtrace_control(resource, MTRACE_KIND_IPM, MTRACE_IPM_START,
                               0, NULL, 0);
    if (status != ZX_OK)
        goto fail;

    ipm->active = true;
    return ZX_OK;

  fail:
    {
        zx_status_t status2 =
            zx_mtrace_control(resource, MTRACE_KIND_IPM,
                              MTRACE_IPM_FINI, 0, NULL, 0);
        if (status2 != ZX_OK)
            zxlogf(TRACE, "%s: MTRACE_IPM_FINI failed: %d\n", __func__, status2);
        assert(status2 == ZX_OK);
        return status;
    }
}

static zx_status_t ipm_stop(cpu_trace_device_t* dev) {
    zxlogf(TRACE, "%s called\n", __func__);

    ipm_device_t* ipm = dev->ipm;
    if (!ipm)
        return ZX_ERR_BAD_STATE;

    zx_handle_t resource = get_root_resource();
    zx_status_t status =
        zx_mtrace_control(resource, MTRACE_KIND_IPM,
                          MTRACE_IPM_STOP, 0, NULL, 0);
    if (status == ZX_OK) {
        ipm->active = false;
        status = zx_mtrace_control(resource, MTRACE_KIND_IPM,
                                   MTRACE_IPM_FINI, 0, NULL, 0);
    }
    return status;
}

zx_status_t ipm_ioctl(cpu_trace_device_t* dev, uint32_t op,
                      const void* cmd, size_t cmdlen,
                      void* reply, size_t replymax,
                      size_t* out_actual) {
    assert(IOCTL_FAMILY(op) == IOCTL_FAMILY_CPUPERF);

    switch (op) {
    case IOCTL_CPUPERF_GET_PROPERTIES:
        if (cmdlen != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_get_properties(dev, reply, replymax, out_actual);

    case IOCTL_CPUPERF_ALLOC_TRACE:
        if (replymax != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_alloc_trace(dev, cmd, cmdlen);

    case IOCTL_CPUPERF_FREE_TRACE:
        if (cmdlen != 0 || replymax != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_free_trace(dev);

    case IOCTL_CPUPERF_GET_ALLOC:
        if (cmdlen != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_get_alloc(dev, reply, replymax, out_actual);

    case IOCTL_CPUPERF_GET_BUFFER_HANDLE:
        return ipm_get_buffer_handle(dev, cmd, cmdlen, reply, replymax, out_actual);

    case IOCTL_CPUPERF_STAGE_CONFIG:
        if (replymax != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_stage_config(dev, cmd, cmdlen);

    case IOCTL_CPUPERF_GET_CONFIG:
        return ipm_get_config(dev, reply, replymax, out_actual);

    case IOCTL_CPUPERF_START:
        if (cmdlen != 0 || replymax != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_start(dev);

    case IOCTL_CPUPERF_STOP:
        if (cmdlen != 0 || replymax != 0)
            return ZX_ERR_INVALID_ARGS;
        return ipm_stop(dev);

    default:
        return ZX_ERR_INVALID_ARGS;
    }
}

void ipm_release(cpu_trace_device_t* dev) {
    // TODO(dje): None of these should fail. What to do?
    // Suggest flagging things as busted and prevent further use.
    ipm_stop(dev);
    ipm_free_trace(dev);
}
