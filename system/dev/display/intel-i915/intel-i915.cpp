// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string.h>

#include <ddk/binding.h>
#include <ddk/debug.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <ddk/protocol/display.h>
#include <ddk/protocol/pci.h>
#include <hw/inout.h>
#include <hw/pci.h>

#include <assert.h>
#include <fbl/unique_ptr.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zircon/syscalls.h>
#include <zircon/types.h>
#include <zx/vmar.h>
#include <zx/vmo.h>

#include "bootloader-display.h"
#include "dp-display.h"
#include "hdmi-display.h"
#include "intel-i915.h"
#include "macros.h"
#include "registers.h"
#include "registers-ddi.h"
#include "registers-dpll.h"
#include "registers-pipe.h"
#include "registers-transcoder.h"

#define INTEL_I915_BROADWELL_DID (0x1616)

#define INTEL_I915_REG_WINDOW_SIZE (0x1000000u)
#define INTEL_I915_FB_WINDOW_SIZE (0x10000000u)

#define BACKLIGHT_CTRL_OFFSET (0xc8250)
#define BACKLIGHT_CTRL_BIT ((uint32_t)(1u << 31))

#define FLAGS_BACKLIGHT 1

#define ENABLE_MODESETTING 0

namespace {
    static bool is_gen9(uint16_t device_id) {
        // Skylake graphics all match 0x19XX and kaby lake graphics all match
        // 0x59XX. There are a few other devices which have matching device_ids,
        // but none of them are display-class devices.
        device_id &= 0xff00;
        return device_id == 0x1900 || device_id == 0x5900;
    }

    static int irq_handler(void* arg) {
        return static_cast<i915::Controller*>(arg)->IrqLoop();
    }
}

namespace i915 {

int Controller::IrqLoop() {
    for (;;) {
        if (zx_interrupt_wait(irq_, NULL) != ZX_OK) {
            zxlogf(TRACE, "i915: interrupt wait failed\n");
            break;
        }

        auto interrupt_ctrl = registers::MasterInterruptControl::Get().ReadFrom(mmio_space_.get());
        interrupt_ctrl.enable_mask().set(0);
        interrupt_ctrl.WriteTo(mmio_space_.get());

        if (interrupt_ctrl.sde_int_pending().get()) {
            auto sde_int_identity = registers::SdeInterruptBase
                    ::Get(registers::SdeInterruptBase::kSdeIntIdentity).ReadFrom(mmio_space_.get());
            for (uint32_t i = 0; i < registers::kDdiCount; i++) {
                registers::Ddi ddi = registers::kDdis[i];
                bool hp_detected = sde_int_identity.ddi_bit(ddi).get();
                bool long_pulse_detected = registers::HotplugCtrl
                        ::Get(ddi).ReadFrom(mmio_space_.get()).long_pulse_detected(ddi).get();
                if (hp_detected && long_pulse_detected) {
                    // TODO(ZX-1414): Actually handle these events
                    zxlogf(TRACE, "i915: hotplug detected %d\n", ddi);
                }
            }
            // Write back the register to clear the bits
            sde_int_identity.WriteTo(mmio_space_.get());
        }

        interrupt_ctrl.enable_mask().set(1);
        interrupt_ctrl.WriteTo(mmio_space_.get());
    }
    return 0;
}

void Controller::EnableBacklight(bool enable) {
    if (flags_ & FLAGS_BACKLIGHT) {
        uint32_t tmp = mmio_space_->Read32(BACKLIGHT_CTRL_OFFSET);

        if (enable) {
            tmp |= BACKLIGHT_CTRL_BIT;
        } else {
            tmp &= ~BACKLIGHT_CTRL_BIT;
        }

        mmio_space_->Write32(BACKLIGHT_CTRL_OFFSET, tmp);
    }
}

zx_status_t Controller::InitHotplug(pci_protocol_t* pci) {
    // Disable interrupts here, we'll re-enable them at the very end of ::Bind
    auto interrupt_ctrl = registers::MasterInterruptControl::Get().ReadFrom(mmio_space_.get());
    interrupt_ctrl.enable_mask().set(0);
    interrupt_ctrl.WriteTo(mmio_space_.get());

    uint32_t irq_cnt = 0;
    zx_status_t status = pci_query_irq_mode_caps(pci, ZX_PCIE_IRQ_MODE_LEGACY, &irq_cnt);
    if (status != ZX_OK || !irq_cnt) {
        zxlogf(ERROR, "i915: Failed to find interrupts %d %d\n", status, irq_cnt);
        return ZX_ERR_INTERNAL;
    }

    if ((status = pci_set_irq_mode(pci, ZX_PCIE_IRQ_MODE_LEGACY, 1)) != ZX_OK) {
        zxlogf(ERROR, "i915: Failed to set irq mode %d\n", status);
        return status;
    }

    if ((status = pci_map_interrupt(pci, 0, &irq_) != ZX_OK)) {
        zxlogf(ERROR, "i915: Failed to map interrupt %d\n", status);
        return status;
    }

    status = thrd_create_with_name(&irq_thread_, irq_handler, this, "i915-irq-thread");
    if (status != ZX_OK) {
        zxlogf(ERROR, "i915: Failed to create irq thread\n");
        return status;
    }

    auto sfuse_strap = registers::SouthFuseStrap::Get().ReadFrom(mmio_space_.get());
    for (uint32_t i = 0; i < registers::kDdiCount; i++) {
        registers::Ddi ddi = registers::kDdis[i];
        // TODO(stevensd): gen9 doesn't have any registers to detect if ddi A or E are present.
        // For now just assume that they are, but we should eventually read from the VBT.
        bool enabled = (ddi == registers::DDI_A) || (ddi == registers::DDI_E)
                || (ddi == registers::DDI_B && sfuse_strap.port_b_present().get())
                || (ddi == registers::DDI_C && sfuse_strap.port_c_present().get())
                || (ddi == registers::DDI_D && sfuse_strap.port_d_present().get());

        auto hp_ctrl = registers::HotplugCtrl::Get(ddi).ReadFrom(mmio_space_.get());
        hp_ctrl.hpd_enable(ddi).set(enabled);
        hp_ctrl.WriteTo(mmio_space_.get());

        auto mask = registers::SdeInterruptBase::Get(
                registers::SdeInterruptBase::kSdeIntMask).ReadFrom(mmio_space_.get());
        mask.ddi_bit(ddi).set(!enabled);
        mask.WriteTo(mmio_space_.get());

        auto enable = registers::SdeInterruptBase::Get(
                registers::SdeInterruptBase::kSdeIntEnable).ReadFrom(mmio_space_.get());
        enable.ddi_bit(ddi).set(enabled);
        enable.WriteTo(mmio_space_.get());
    }

    return ZX_OK;
}

bool Controller::BringUpDisplayEngine() {
    // Enable PCH Reset Handshake
    auto nde_rstwrn_opt = registers::NorthDERestetWarning::Get().ReadFrom(mmio_space_.get());
    nde_rstwrn_opt.rst_pch_handshake_enable().set(1);
    nde_rstwrn_opt.WriteTo(mmio_space_.get());

    // Wait for Power Well 0 distribution
    if (!WAIT_ON_US(registers::FuseStatus
            ::Get().ReadFrom(mmio_space_.get()).pg0_dist_status().get(), 5)) {
        zxlogf(ERROR, "Power Well 0 distribution failed\n");
        return false;
    }

    // Enable and wait for Power Well 1 and Misc IO power
    auto power_well = registers::PowerWellControl2::Get().ReadFrom(mmio_space_.get());
    power_well.power_well_1_request().set(1);
    power_well.misc_io_power_state().set(1);
    power_well.WriteTo(mmio_space_.get());
    if (!WAIT_ON_US(registers::PowerWellControl2
            ::Get().ReadFrom(mmio_space_.get()).power_well_1_state().get(), 10)) {
        zxlogf(ERROR, "Power Well 1 failed to enable\n");
        return false;
    }
    if (!WAIT_ON_US(registers::PowerWellControl2
            ::Get().ReadFrom(mmio_space_.get()).misc_io_power_state().get(), 10)) {
        zxlogf(ERROR, "Misc IO power failed to enable\n");
        return false;
    }
    if (!WAIT_ON_US(registers::FuseStatus
            ::Get().ReadFrom(mmio_space_.get()).pg1_dist_status().get(), 5)) {
        zxlogf(ERROR, "Power Well 1 distribution failed\n");
        return false;
    }

    // Enable CDCLK PLL to 337.5mhz if the BIOS didn't already enable it. If it needs to be
    // something special (i.e. for eDP), assume that the BIOS already enabled it.
    auto dpll_enable = registers::DpllEnable::Get(0).ReadFrom(mmio_space_.get());
    if (!dpll_enable.enable_dpll().get()) {
        // Set the cd_clk frequency to the minimum
        auto cd_clk = registers::CdClockCtl::Get().ReadFrom(mmio_space_.get());
        cd_clk.cd_freq_select().set(cd_clk.kFreqSelect3XX);
        cd_clk.cd_freq_decimal().set(cd_clk.kFreqDecimal3375);
        cd_clk.WriteTo(mmio_space_.get());

        // Configure DPLL0
        auto dpll_ctl1 = registers::DpllControl1::Get().ReadFrom(mmio_space_.get());
        dpll_ctl1.dpll_link_rate(0).set(dpll_ctl1.kLinkRate810Mhz);
        dpll_ctl1.dpll_override(0).set(1);
        dpll_ctl1.dpll_hdmi_mode(0).set(0);
        dpll_ctl1.dpll_ssc_enable(0).set(0);
        dpll_ctl1.WriteTo(mmio_space_.get());

        // Enable DPLL0 and wait for it
        dpll_enable.enable_dpll().set(1);
        dpll_enable.WriteTo(mmio_space_.get());
        if (!WAIT_ON_MS(registers::Lcpll1Control
                ::Get().ReadFrom(mmio_space_.get()).pll_lock().get(), 5)) {
            zxlogf(ERROR, "Failed to configure dpll0\n");
            return false;
        }

        // Do the magic sequence for Changing CD Clock Frequency specified on
        // intel-gfx-prm-osrc-skl-vol12-display.pdf p.135
        constexpr uint32_t kGtDriverMailboxInterface = 0x138124;
        constexpr uint32_t kGtDriverMailboxData0 = 0x138128;
        constexpr uint32_t kGtDriverMailboxData1 = 0x13812c;
        mmio_space_.get()->Write32(kGtDriverMailboxData0, 0x3);
        mmio_space_.get()->Write32(kGtDriverMailboxData1, 0x0);
        mmio_space_.get()->Write32(kGtDriverMailboxInterface, 0x80000007);

        int count = 0;
        for (;;) {
            if (!WAIT_ON_US(mmio_space_.get()
                    ->Read32(kGtDriverMailboxInterface) & 0x80000000, 150)) {
                zxlogf(ERROR, "GT Driver Mailbox driver busy\n");
                return false;
            }
            if (mmio_space_.get()->Read32(kGtDriverMailboxData0) & 0x1) {
                break;
            }
            if (count++ == 3) {
                zxlogf(ERROR, "Failed to set cd_clk\n");
                return false;
            }
            zx_nanosleep(zx_deadline_after(ZX_MSEC(1)));
        }

        cd_clk.WriteTo(mmio_space_.get());

        mmio_space_.get()->Write32(kGtDriverMailboxData0, 0x3);
        mmio_space_.get()->Write32(kGtDriverMailboxData1, 0x0);
        mmio_space_.get()->Write32(kGtDriverMailboxInterface, 0x80000007);
    }

    // Enable and wait for DBUF
    auto dbuf_ctl = registers::DbufCtl::Get().ReadFrom(mmio_space_.get());
    dbuf_ctl.power_request().set(1);
    dbuf_ctl.WriteTo(mmio_space_.get());

    if (!WAIT_ON_US(registers::DbufCtl
            ::Get().ReadFrom(mmio_space_.get()).power_state().get(), 10)) {
        zxlogf(ERROR, "Failed to enable DBUF\n");
        return false;
    }

    // We never use VGA, so just disable it at startup
    constexpr uint16_t kSequencerIdx = 0x3c4;
    constexpr uint16_t kSequencerData = 0x3c5;
    constexpr uint8_t kClockingModeIdx = 1;
    constexpr uint8_t kClockingModeScreenOff = (1 << 5);
    zx_status_t status = zx_mmap_device_io(get_root_resource(), kSequencerIdx, 2);
    if (status != ZX_OK) {
        zxlogf(ERROR, "Failed to map vga ports\n");
        return false;
    }
    outp(kSequencerIdx, kClockingModeIdx);
    uint8_t clocking_mode = inp(kSequencerData);
    if (!(clocking_mode & kClockingModeScreenOff)) {
        outp(kSequencerIdx, inp(kSequencerData) | kClockingModeScreenOff);
        zx_nanosleep(zx_deadline_after(ZX_MSEC(100)));

        auto vga_ctl = registers::VgaCtl::Get().ReadFrom(mmio_space());
        vga_ctl.vga_display_disable().set(1);
        vga_ctl.WriteTo(mmio_space());
    }

    return true;
}

bool Controller::ResetPipe(registers::Pipe pipe) {
    registers::PipeRegs pipe_regs(pipe);
    registers::TranscoderRegs trans_regs(pipe);

    // Disable planes
    pipe_regs.PlaneControl().FromValue(0).WriteTo(mmio_space());
    pipe_regs.PlaneSurface().FromValue(0).WriteTo(mmio_space());

    // Disable transcoder and wait it to stop
    auto trans_conf = trans_regs.Conf().ReadFrom(mmio_space());
    trans_conf.transcoder_enable().set(0);
    trans_conf.WriteTo(mmio_space());
    if (!WAIT_ON_MS(!trans_regs.Conf().ReadFrom(mmio_space()).transcoder_state().get(), 60)) {
        zxlogf(ERROR, "Failed to reset transcoder\n");
        return false;
    }

    // Disable transcoder ddi select and clock select
    auto trans_ddi_ctl = trans_regs.DdiFuncControl().ReadFrom(mmio_space());
    trans_ddi_ctl.trans_ddi_function_enable().set(0);
    trans_ddi_ctl.ddi_select().set(0);
    trans_ddi_ctl.WriteTo(mmio_space());

    auto trans_clk_sel = trans_regs.ClockSelect().ReadFrom(mmio_space());
    trans_clk_sel.trans_clock_select().set(0);
    trans_clk_sel.WriteTo(mmio_space());

    return true;
}

bool Controller::ResetDdi(registers::Ddi ddi) {
    registers::DdiRegs ddi_regs(ddi);

    // Disable the port
    auto ddi_buf_ctl = ddi_regs.DdiBufControl().ReadFrom(mmio_space());
    bool was_enabled = ddi_buf_ctl.ddi_buffer_enable().get();
    ddi_buf_ctl.ddi_buffer_enable().set(0);
    ddi_buf_ctl.WriteTo(mmio_space());

    auto ddi_dp_tp_ctl = ddi_regs.DdiDpTransportControl().ReadFrom(mmio_space());
    ddi_dp_tp_ctl.transport_enable().set(0);
    ddi_dp_tp_ctl.dp_link_training_pattern().set(ddi_dp_tp_ctl.kTrainingPattern1);
    ddi_dp_tp_ctl.WriteTo(mmio_space());

    if (was_enabled && !WAIT_ON_MS(
            ddi_regs.DdiBufControl().ReadFrom(mmio_space()).ddi_idle_status().get(), 8)) {
        zxlogf(ERROR, "Port failed to go idle\n");
        return false;
    }

    // Disable IO power
    auto pwc2 = registers::PowerWellControl2::Get().ReadFrom(mmio_space());
    pwc2.ddi_io_power_request(ddi).set(0);
    pwc2.WriteTo(mmio_space());

    // Remove the PLL mapping and disable the PLL (we don't share PLLs)
    auto dpll_ctrl2 = registers::DpllControl2::Get().ReadFrom(mmio_space());
    dpll_ctrl2.ddi_clock_off(ddi).set(1);
    dpll_ctrl2.WriteTo(mmio_space());

    uint8_t dpll_number = static_cast<uint8_t>(dpll_ctrl2.ddi_clock_select(ddi).get());
    auto dpll_enable = registers::DpllEnable::Get(dpll_number).ReadFrom(mmio_space());
    dpll_enable.enable_dpll().set(1);
    dpll_enable.WriteTo(mmio_space());

    return true;
}

void Controller::AllocDisplayBuffers() {
    // Do display buffer alloc and watermark programming with fixed allocation from
    // intel docs. This allows the display to work but prevents power management.
    // TODO(ZX-1413): Calculate these dynamically based on what's enabled.
    for (unsigned i = 0; i < registers::kPipeCount; i++) {
        registers::Pipe pipe = registers::kPipes[i];
        registers::PipeRegs pipe_regs(pipe);

        // Plane 1 gets everything
        constexpr uint32_t kPerDdi = 891 / 3;
        auto buf_cfg = pipe_regs.PlaneBufCfg(1).FromValue(0);
        buf_cfg.buffer_start().set(kPerDdi * pipe);
        buf_cfg.buffer_end().set(kPerDdi * (pipe + 1) - 1);
        buf_cfg.WriteTo(mmio_space());

        // Cursor and planes 2 and 3 get nothing
        pipe_regs.PlaneBufCfg(0).FromValue(0).WriteTo(mmio_space());
        pipe_regs.PlaneBufCfg(2).FromValue(0).WriteTo(mmio_space());
        pipe_regs.PlaneBufCfg(3).FromValue(0).WriteTo(mmio_space());

        auto wm0 = pipe_regs.PlaneWatermark(0).FromValue(0);
        wm0.enable().set(1);
        wm0.lines().set(2);
        wm0.blocks().set(kPerDdi);
        wm0.WriteTo(mmio_space());

        for (int i = 1; i < 8; i++) {
            auto wm = pipe_regs.PlaneWatermark(i).FromValue(0);
            wm.WriteTo(mmio_space());
        }

        // Write so double-buffered regs are updated
        auto base = pipe_regs.PlaneSurface().ReadFrom(mmio_space());
        base.WriteTo(mmio_space());
    }
    // TODO(ZX-1413): Wait for vblank instead of sleeping
    zx_nanosleep(zx_deadline_after(ZX_MSEC(33)));
}

zx_status_t Controller::InitDisplays(uint16_t device_id) {
    fbl::AllocChecker ac;
    fbl::unique_ptr<DisplayDevice> disp_device(nullptr);
    if (ENABLE_MODESETTING && is_gen9(device_id)) {
        BringUpDisplayEngine();

        for (unsigned i = 0; i < registers::kPipeCount; i++) {
            ResetPipe(registers::kPipes[i]);
        }

        for (unsigned i = 0; i < registers::kDdiCount; i++) {
            ResetDdi(registers::kDdis[i]);
        }

        AllocDisplayBuffers();

        for (uint32_t i = 0; i < registers::kDdiCount && !disp_device; i++) {
            zxlogf(TRACE, "Trying to init display %d\n", registers::kDdis[i]);
            zxlogf(SPEW, "Trying hdmi\n");
            fbl::unique_ptr<DisplayDevice> hdmi_disp(
                    new (&ac) HdmiDisplay(this, registers::kDdis[i], registers::PIPE_A));
            if (ac.check() && hdmi_disp->Init()) {
                disp_device = fbl::move(hdmi_disp);
            }

            if (!disp_device) {
                zxlogf(SPEW, "Trying dp\n");
                fbl::unique_ptr<DisplayDevice> dp_disp(
                        new (&ac) DpDisplay(this, registers::kDdis[i], registers::PIPE_A));
                if (ac.check() && dp_disp->Init()) {
                    disp_device = fbl::move(dp_disp);
                }
            }
        }

        if (!disp_device) {
            zxlogf(INFO, "Did not find any displays\n");
            return ZX_OK;
        }
    } else {
        // The DDI doesn't actually matter, so just say DDI A. The BIOS does use PIPE_A.
        disp_device.reset(new (&ac) BootloaderDisplay(this, registers::DDI_A, registers::PIPE_A));
        if (!ac.check()) {
            zxlogf(ERROR, "i915: failed to alloc disp_device\n");
            return ZX_ERR_NO_MEMORY;
        }

        if (!disp_device->Init()) {
            zxlogf(ERROR, "i915: failed to init display\n");
            return ZX_ERR_INTERNAL;
        }
    }

    zx_status_t status = disp_device->DdkAdd("intel_i915_disp");
    if (status != ZX_OK) {
        zxlogf(ERROR, "i915: failed to add display device\n");
        return status;
    }

    display_device_ = disp_device.release();
    return ZX_OK;
}

void Controller::DdkUnbind() {
    if (display_device_) {
        device_remove(display_device_->zxdev());
        display_device_ = nullptr;
    }
    device_remove(zxdev());
}

void Controller::DdkRelease() {
    delete this;
}

zx_status_t Controller::Bind(fbl::unique_ptr<i915::Controller>* controller_ptr) {
    zxlogf(TRACE, "i915: binding to display controller\n");

    pci_protocol_t pci;
    if (device_get_protocol(parent_, ZX_PROTOCOL_PCI, &pci)) {
        return ZX_ERR_NOT_SUPPORTED;
    }

    void* cfg_space;
    size_t config_size;
    zx_handle_t cfg_handle = ZX_HANDLE_INVALID;
    zx_status_t status = pci_map_resource(&pci, PCI_RESOURCE_CONFIG,
                                          ZX_CACHE_POLICY_UNCACHED_DEVICE,
                                          &cfg_space, &config_size, &cfg_handle);
    if (status != ZX_OK) {
        zxlogf(ERROR, "i915: Failed to map PCI resource config\n");
        return status;
    }
    const pci_config_t* pci_config = reinterpret_cast<const pci_config_t*>(cfg_space);
    if (pci_config->device_id == INTEL_I915_BROADWELL_DID) {
        // TODO: this should be based on the specific target
        flags_ |= FLAGS_BACKLIGHT;
    }

    uintptr_t gmchGfxControl =
            reinterpret_cast<uintptr_t>(cfg_space) + registers::GmchGfxControl::kAddr;
    uint16_t gmch_ctrl = *reinterpret_cast<volatile uint16_t*>(gmchGfxControl);
    uint32_t gtt_size = registers::GmchGfxControl::mem_size_to_mb(gmch_ctrl);

    zx_handle_close(cfg_handle);

    zxlogf(TRACE, "i915: mapping registers\n");
    // map register window
    uintptr_t regs;
    uint64_t regs_size;
    status = pci_map_resource(&pci, PCI_RESOURCE_BAR_0, ZX_CACHE_POLICY_UNCACHED_DEVICE,
                              reinterpret_cast<void**>(&regs), &regs_size, &regs_handle_);
    if (status != ZX_OK) {
        zxlogf(ERROR, "i915: failed to map bar 0: %d\n", status);
        return status;
    }

    fbl::AllocChecker ac;
    fbl::unique_ptr<MmioSpace> mmio_space(new (&ac) MmioSpace(regs));
    if (!ac.check()) {
        zxlogf(ERROR, "i915: failed to alloc MmioSpace\n");
        return ZX_ERR_NO_MEMORY;
    }
    mmio_space_ = fbl::move(mmio_space);

    if (is_gen9(pci_config->device_id)) {
        zxlogf(TRACE, "i915: initialzing hotplug\n");
        status = InitHotplug(&pci);
        if (status != ZX_OK) {
            zxlogf(ERROR, "i915: failed to init hotplugging\n");
            return status;
        }
    }

    zxlogf(TRACE, "i915: mapping gtt\n");
    gtt_.Init(mmio_space_.get(), gtt_size);

    status = DdkAdd("intel_i915");
    if (status != ZX_OK) {
        zxlogf(ERROR, "i915: failed to add controller device\n");
        return status;
    }
    controller_ptr->release();

    zxlogf(TRACE, "i915: initializing displays\n");
    status = InitDisplays(pci_config->device_id);
    if (status != ZX_OK) {
        device_remove(zxdev());
        return status;
    }

    if (is_gen9(pci_config->device_id)) {
        auto interrupt_ctrl = registers::MasterInterruptControl::Get().ReadFrom(mmio_space_.get());
        interrupt_ctrl.enable_mask().set(1);
        interrupt_ctrl.WriteTo(mmio_space_.get());
    }

    // TODO remove when the gfxconsole moves to user space
    EnableBacklight(true);
    if (display_device_) {
        zx_set_framebuffer_vmo(get_root_resource(), display_device_->framebuffer_vmo().get(),
                               static_cast<uint32_t>(display_device_->framebuffer_size()),
                               display_device_->info().format, display_device_->info().width,
                               display_device_->info().height, display_device_->info().stride);
    }

    zxlogf(TRACE, "i915: initialization done\n");

    return ZX_OK;
}

Controller::Controller(zx_device_t* parent) : DeviceType(parent), irq_(ZX_HANDLE_INVALID) { }

Controller::~Controller() {
    if (irq_ != ZX_HANDLE_INVALID) {
        zx_interrupt_cancel(irq_);

        thrd_join(irq_thread_, nullptr);

        zx_handle_close(irq_);
    }

    if (mmio_space_) {
        EnableBacklight(false);

        zx_handle_close(regs_handle_);
        regs_handle_ = ZX_HANDLE_INVALID;
    }
}

} // namespace i915

zx_status_t intel_i915_bind(void* ctx, zx_device_t* parent) {
    fbl::AllocChecker ac;
    fbl::unique_ptr<i915::Controller> controller(new (&ac) i915::Controller(parent));
    if (!ac.check()) {
        return ZX_ERR_NO_MEMORY;
    }

    return controller->Bind(&controller);
}
