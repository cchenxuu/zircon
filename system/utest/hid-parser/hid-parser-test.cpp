// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <stdio.h>

#include <hid-parser/item.h>
#include <hid-parser/parser.h>

#include <unistd.h>
#include <unittest/unittest.h>

namespace {

// A mouse as defined in the HID documentation (appendix B.2)
// Note that it does not have a report id.
const uint8_t boot_mouse_r_desc[] = {
    0x05, 0x01,       // Usage Page (generic Desktop)
    0x09, 0x02,       // Usage (mouse)
    0xa1, 0x01,       // Collection (application)
    0x09, 0x01,       //   Usage (pointer)
    0xa1, 0x00,       //   Collection (physical)
    0x05, 0x09,       //     Usage Page (button)
    0x19, 0x01,       //     Usage_minimum (button 1)
    0x29, 0x03,       //     Usage_maximum (button 3)
    0x15, 0x00,       //     Logical Minimum (0)
    0x25, 0x01,       //     Logical Maximum (1)
    0x95, 0x03,       //     Report Count (3)
    0x75, 0x01,       //     Report_size (1)
    0x81, 0x02,       //     Input (data,var,abs)
    0x95, 0x01,       //     Report Count (1)
    0x75, 0x05,       //     Report_size (5)
    0x81, 0x03,       //     Input (cnst,var,abs)
    0x05, 0x01,       //     Usage Page (generic Desktop)
    0x09, 0x30,       //     Usage (x)
    0x09, 0x31,       //     Usage (y)
    0x15, 0x81,       //     Logical Minimum (-127)
    0x25, 0x7f,       //     Logical Minimum (127)
    0x75, 0x08,       //     Report_size (8)
    0x95, 0x02,       //     Report Count (2)
    0x81, 0x06,       //     Input (data,var,rel)
    0xc0,             //   End Collection
    0xc0              // End Collection
};

// Composite device by Adafruit.
const uint8_t trinket_r_desc[] = {
    0x05, 0x01,        // Usage_page (generic Desktop)
    0x09, 0x02,        // Usage (mouse)
    0xa1, 0x01,        // Collection (application)
    0x09, 0x01,        //   Usage (pointer)
    0xa1, 0x00,        //   Collection (physical)
    0x85, 0x01,        //     Report_id (1)
    0x05, 0x09,        //     Usage_page (button)
    0x19, 0x01,        //     Usage_minimum (1)
    0x29, 0x03,        //     Usage_maximum (3)
    0x15, 0x00,        //     Logical_minimum (0)
    0x25, 0x01,        //     Logical_maximum (1)
    0x95, 0x03,        //     Report_count (3)
    0x75, 0x01,        //     Report_size (1)
    0x81, 0x02,        //     Input (data,var,abs)
    0x95, 0x01,        //     Report_count (1)
    0x75, 0x05,        //     Report_size (5)
    0x81, 0x03,        //     Input (const,var,abs)
    0x05, 0x01,        //     Usage_page (generic Desktop)
    0x09, 0x30,        //     Usage (x)
    0x09, 0x31,        //     Usage (y)
    0x15, 0x81,        //     Logical_minimum (-127)
    0x25, 0x7f,        //     Logical_maximum (127)
    0x75, 0x08,        //     Report_size (8)
    0x95, 0x02,        //     Report_count (2)
    0x81, 0x06,        //     Input (data,var,rel)
    0xc0,              //   End_collection
    0xc0,              // End Collection
// ========================================================================================
    0x05, 0x01,        // Usage_page (generic Desktop)
    0x09, 0x06,        // Usage (keyboard)
    0xa1, 0x01,        // Collection (application)
    0x85, 0x02,        //   Report_id (2)
    0x75, 0x01,        //   Report_size (1)
    0x95, 0x08,        //   Report_count (8)
    0x05, 0x07,        //   Usage_page (keyboard)(key Codes)
    0x19, 0xe0,        //   Usage_minimum (keyboard Leftcontrol)(224)
    0x29, 0xe7,        //   Usage_maximum (keyboard Right Gui)(231)
    0x15, 0x00,        //   Logical_minimum (0)
    0x25, 0x01,        //   Logical_maximum (1)
    0x81, 0x02,        //   Input (data,var,abs) ; Modifier Byte
    0x95, 0x01,        //   Report_count (1)
    0x75, 0x08,        //   Report_size (8)
    0x81, 0x03,        //   Input (cnst,var,abs) ; Reserved Byte
    0x95, 0x05,        //   Report_count (5)
    0x75, 0x01,        //   Report_size (1)
    0x05, 0x08,        //   Usage_page (leds)
    0x19, 0x01,        //   Usage_minimum (num Lock)
    0x29, 0x05,        //   Usage_maximum (kana)
    0x91, 0x02,        //   Output (data,var,abs) ; Led Report
    0x95, 0x01,        //   Report_count (1)
    0x75, 0x03,        //   Report_size (3)
    0x91, 0x03,        //   Output (cnst,var,abs) ; Led Report Padding
    0x95, 0x05,        //   Report_count (5)
    0x75, 0x08,        //   Report_size (8)
    0x15, 0x00,        //   Logical_minimum (0)
    0x26, 0xa4, 0x00,  //   Logical_maximum (164)
    0x05, 0x07,        //   Usage_page (keyboard)(key Codes)
    0x19, 0x00,        //   Usage_minimum (reserved (no Event Indicated))(0)
    0x2a, 0xa4, 0x00,  //   Usage_maximum (keyboard Application)(164)
    0x81, 0x00,        //   Input (data,ary,abs)
    0xc0,              // End_collection
// ==== Multimedia Keys ======================================================================
    0x05, 0x0c,        // Usage_page (consumer Devices)
    0x09, 0x01,        // Usage (consumer Control)
    0xa1, 0x01,        // Collection (application)
    0x85, 0x03,        //   Report_id (3)
    0x19, 0x00,        //   Usage_minimum (unassigned)
    0x2a, 0x3c, 0x02,  //   Usage_maximum
    0x15, 0x00,        //   Logical_minimum (0)
    0x26, 0x3c, 0x02,  //   Logical_maximum
    0x95, 0x01,        //   Report_count (1)
    0x75, 0x10,        //   Report_size (16)
    0x81, 0x00,        //   Input (data,ary,abs)
    0xc0,              // End_collection
// ======== Power Controls ==================================================================
    0x05, 0x01,        // Usage_page (generic Desktop)
    0x09, 0x80,        // Usage (system Control)
    0xa1, 0x01,        // Collection (application)
    0x85, 0x04,        //   Report_id (4)
    0x95, 0x01,        //   Report_count (1)
    0x75, 0x02,        //   Report_size (2)
    0x15, 0x01,        //   Logical_minimum (1)
    0x25, 0x03,        //   Logical_maximum (3)
    0x09, 0x82,        //   Usage (system Sleep)
    0x09, 0x81,        //   Usage (system Power)
    0x09, 0x83,        //   Usage (system Wakeup)
    0x81, 0x60,        //   Input
    0x75, 0x06,        //   Report_size (6)
    0x81, 0x03,        //   Input (cnst,var,abs)
    0xc0,              // End_collection
};

const uint8_t acer12_touch_r_desc[] = {
    0x05, 0x0D,        // Usage Page (Digitizer)
    0x09, 0x04,        // Usage (Touch Screen)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x01,        //   Report ID (1)
    0x09, 0x22,        //   Usage (Finger)
    0xA1, 0x02,        //   Collection (Logical)
    0x09, 0x42,        //     Usage (Tip Switch)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x75, 0x01,        //     Report Size (1)
    0x95, 0x01,        //     Report Count (1)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x01,        //     Report Size (1)
    0x81, 0x03,        //     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x06,        //     Report Size (6)
    0x09, 0x51,        //     Usage (0x51)
    0x25, 0x3F,        //     Logical Maximum (63)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0xFF, 0x00,  //     Logical Maximum (255)
    0x75, 0x08,        //     Report Size (8)
    0x09, 0x48,        //     Usage (0x48)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x49,        //     Usage (0x49)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //     Report Count (1)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0xA4,              //     Push
    0x26, 0xD0, 0x0B,  //       Logical Maximum (3024)
    0x75, 0x10,        //       Report Size (16)
    0x55, 0x0F,        //       Unit Exponent (-1)
    0x65, 0x11,        //       Unit (System: SI Linear, Length: Centimeter)
    0x09, 0x30,        //       Usage (X)
    0x35, 0x00,        //       Physical Minimum (0)
    0x46, 0xFE, 0x00,  //       Physical Maximum (254)
    0x95, 0x02,        //       Report Count (2)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0x10, 0x08,  //       Logical Maximum (2064)
    0x46, 0xA9, 0x00,  //       Physical Maximum (169)
    0x09, 0x31,        //       Usage (Y)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xB4,              //     Pop
    0xC0,              //   End Collection
    0x05, 0x0D,        //   Usage Page (Digitizer)
    0x09, 0x22,        //   Usage (Finger)
    0xA1, 0x02,        //   Collection (Logical)
    0x05, 0x0D,        //     Usage Page (Digitizer)
    0x09, 0x42,        //     Usage (Tip Switch)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x75, 0x01,        //     Report Size (1)
    0x95, 0x01,        //     Report Count (1)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x01,        //     Report Size (1)
    0x81, 0x03,        //     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x06,        //     Report Size (6)
    0x09, 0x51,        //     Usage (0x51)
    0x25, 0x3F,        //     Logical Maximum (63)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0xFF, 0x00,  //     Logical Maximum (255)
    0x75, 0x08,        //     Report Size (8)
    0x09, 0x48,        //     Usage (0x48)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x49,        //     Usage (0x49)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //     Report Count (1)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0xA4,              //     Push
    0x26, 0xD0, 0x0B,  //       Logical Maximum (3024)
    0x75, 0x10,        //       Report Size (16)
    0x55, 0x0F,        //       Unit Exponent (-1)
    0x65, 0x11,        //       Unit (System: SI Linear, Length: Centimeter)
    0x09, 0x30,        //       Usage (X)
    0x35, 0x00,        //       Physical Minimum (0)
    0x46, 0xFE, 0x00,  //       Physical Maximum (254)
    0x95, 0x02,        //       Report Count (2)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0x10, 0x08,  //       Logical Maximum (2064)
    0x46, 0xA9, 0x00,  //       Physical Maximum (169)
    0x09, 0x31,        //       Usage (Y)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xB4,              //     Pop
    0xC0,              //   End Collection
    0x05, 0x0D,        //   Usage Page (Digitizer)
    0x09, 0x22,        //   Usage (Finger)
    0xA1, 0x02,        //   Collection (Logical)
    0x05, 0x0D,        //     Usage Page (Digitizer)
    0x09, 0x42,        //     Usage (Tip Switch)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x75, 0x01,        //     Report Size (1)
    0x95, 0x01,        //     Report Count (1)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x01,        //     Report Size (1)
    0x81, 0x03,        //     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x06,        //     Report Size (6)
    0x09, 0x51,        //     Usage (0x51)
    0x25, 0x3F,        //     Logical Maximum (63)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0xFF, 0x00,  //     Logical Maximum (255)
    0x75, 0x08,        //     Report Size (8)
    0x09, 0x48,        //     Usage (0x48)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x49,        //     Usage (0x49)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //     Report Count (1)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0xA4,              //     Push
    0x26, 0xD0, 0x0B,  //       Logical Maximum (3024)
    0x75, 0x10,        //       Report Size (16)
    0x55, 0x0F,        //       Unit Exponent (-1)
    0x65, 0x11,        //       Unit (System: SI Linear, Length: Centimeter)
    0x09, 0x30,        //       Usage (X)
    0x35, 0x00,        //       Physical Minimum (0)
    0x46, 0xFE, 0x00,  //       Physical Maximum (254)
    0x95, 0x02,        //       Report Count (2)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0x10, 0x08,  //       Logical Maximum (2064)
    0x46, 0xA9, 0x00,  //       Physical Maximum (169)
    0x09, 0x31,        //       Usage (Y)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xB4,              //     Pop
    0xC0,              //   End Collection
    0x05, 0x0D,        //   Usage Page (Digitizer)
    0x09, 0x22,        //   Usage (Finger)
    0xA1, 0x02,        //   Collection (Logical)
    0x05, 0x0D,        //     Usage Page (Digitizer)
    0x09, 0x42,        //     Usage (Tip Switch)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x75, 0x01,        //     Report Size (1)
    0x95, 0x01,        //     Report Count (1)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x01,        //     Report Size (1)
    0x81, 0x03,        //     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x06,        //     Report Size (6)
    0x09, 0x51,        //     Usage (0x51)
    0x25, 0x3F,        //     Logical Maximum (63)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0xFF, 0x00,  //     Logical Maximum (255)
    0x75, 0x08,        //     Report Size (8)
    0x09, 0x48,        //     Usage (0x48)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x49,        //     Usage (0x49)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //     Report Count (1)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0xA4,              //     Push
    0x26, 0xD0, 0x0B,  //       Logical Maximum (3024)
    0x75, 0x10,        //       Report Size (16)
    0x55, 0x0F,        //       Unit Exponent (-1)
    0x65, 0x11,        //       Unit (System: SI Linear, Length: Centimeter)
    0x09, 0x30,        //       Usage (X)
    0x35, 0x00,        //       Physical Minimum (0)
    0x46, 0xFE, 0x00,  //       Physical Maximum (254)
    0x95, 0x02,        //       Report Count (2)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0x10, 0x08,  //       Logical Maximum (2064)
    0x46, 0xA9, 0x00,  //       Physical Maximum (169)
    0x09, 0x31,        //       Usage (Y)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xB4,              //     Pop
    0xC0,              //   End Collection
    0x05, 0x0D,        //   Usage Page (Digitizer)
    0x09, 0x22,        //   Usage (Finger)
    0xA1, 0x02,        //   Collection (Logical)
    0x05, 0x0D,        //     Usage Page (Digitizer)
    0x09, 0x42,        //     Usage (Tip Switch)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x75, 0x01,        //     Report Size (1)
    0x95, 0x01,        //     Report Count (1)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x01,        //     Report Size (1)
    0x81, 0x03,        //     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x75, 0x06,        //     Report Size (6)
    0x09, 0x51,        //     Usage (0x51)
    0x25, 0x3F,        //     Logical Maximum (63)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0xFF, 0x00,  //     Logical Maximum (255)
    0x75, 0x08,        //     Report Size (8)
    0x09, 0x48,        //     Usage (0x48)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x49,        //     Usage (0x49)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //     Report Count (1)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0xA4,              //     Push
    0x26, 0xD0, 0x0B,  //       Logical Maximum (3024)
    0x75, 0x10,        //       Report Size (16)
    0x55, 0x0F,        //       Unit Exponent (-1)
    0x65, 0x11,        //       Unit (System: SI Linear, Length: Centimeter)
    0x09, 0x30,        //       Usage (X)
    0x35, 0x00,        //       Physical Minimum (0)
    0x46, 0xFE, 0x00,  //       Physical Maximum (254)
    0x95, 0x02,        //       Report Count (2)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x26, 0x10, 0x08,  //       Logical Maximum (2064)
    0x46, 0xA9, 0x00,  //       Physical Maximum (169)
    0x09, 0x31,        //       Usage (Y)
    0x81, 0x02,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xB4,              //     Pop
    0xC0,              //   End Collection
    0x05, 0x0D,        //   Usage Page (Digitizer)
    0x09, 0x56,        //   Usage (0x56)
    0x55, 0x00,        //   Unit Exponent (0)
    0x65, 0x00,        //   Unit (None)
    0x27, 0xFF, 0xFF, 0xFF, 0x7F,  //   Logical Maximum (2147483647)
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x20,        //   Report Size (32)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x54,        //   Usage (0x54)
    0x25, 0x7F,        //   Logical Maximum (127)
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x08,        //   Report Size (8)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x85, 0x0A,        //   Report ID (10)
    0x09, 0x55,        //   Usage (0x55)
    0x25, 0x0A,        //   Logical Maximum (10)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0x0E,        //   Report ID (14)
    0x06, 0x00, 0xFF,  //   Usage Page (Vendor Defined 0xFF00)
    0x09, 0xC5,        //   Usage (0xC5)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x96, 0x00, 0x01,  //   Report Count (256)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              // End Collection
// ===========================================================================================
    0x06, 0xFF, 0x01,  // Usage Page (Reserved 0x01FF)
    0x09, 0x01,        // Usage (0x01)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x02,        //   Report ID (2)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x09, 0x00,        //   Usage (0x00)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
// ===========================================================================================
    0x06, 0x00, 0xFF,  // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        // Usage (0x01)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x03,        //   Report ID (3)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x20,        //   Report Count (32)
    0x09, 0x01,        //   Usage (0x01)
    0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              // End Collection
// ===========================================================================================
    0x06, 0x00, 0xFF,  // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        // Usage (0x01)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x06,        //   Report ID (6)
    0x09, 0x03,        //   Usage (0x03)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x12,        //   Report Count (18)
    0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x09, 0x04,        //   Usage (0x04)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x03,        //   Report Count (3)
    0xB1, 0x02,        //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              // End Collection
// ===========================================================================================
    0x06, 0x01, 0xFF,  // Usage Page (Vendor Defined 0xFF01)
    0x09, 0x01,        // Usage (0x01)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x04,        //   Report ID (4)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x13,        //   Report Count (19)
    0x09, 0x00,        //   Usage (0x00)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
// ===========================================================================================
    0x05, 0x0D,        // Usage Page (Digitizer)
    0x09, 0x02,        // Usage (Pen)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x07,        //   Report ID (7)
    0x35, 0x00,        //   Physical Minimum (0)
    0x09, 0x20,        //   Usage (Stylus)
    0xA1, 0x00,        //   Collection (Physical)
    0x09, 0x32,        //     Usage (In Range)
    0x09, 0x42,        //     Usage (Tip Switch)
    0x09, 0x44,        //     Usage (Barrel Switch)
    0x09, 0x3C,        //     Usage (Invert)
    0x09, 0x45,        //     Usage (Eraser)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x75, 0x01,        //     Report Size (1)
    0x95, 0x05,        //     Report Count (5)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x03,        //     Report Count (3)
    0x81, 0x03,        //     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0x09, 0x30,        //     Usage (X)
    0x75, 0x10,        //     Report Size (16)
    0x95, 0x01,        //     Report Count (1)
    0xA4,              //     Push
    0x55, 0x0F,        //       Unit Exponent (-1)
    0x65, 0x11,        //       Unit (System: SI Linear, Length: Centimeter)
    0x46, 0xFE, 0x00,  //       Physical Maximum (254)
    0x26, 0xC0, 0x0F,  //       Logical Maximum (4032)
    0x81, 0x42,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,Null State)
    0x09, 0x31,        //       Usage (Y)
    0x46, 0xA9, 0x00,  //       Physical Maximum (169)
    0x26, 0xC0, 0x0A,  //       Logical Maximum (2752)
    0x81, 0x42,        //       Input (Data,Var,Abs,No Wrap,Linear,Preferred State,Null State)
    0xB4,              //     Pop
    0x05, 0x0D,        //     Usage Page (Digitizer)
    0x09, 0x30,        //     Usage (Tip Pressure)
    0x26, 0x00, 0x01,  //     Logical Maximum (256)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              //   End Collection
    0xC0,              // End Collection
// ===========================================================================================
    0x06, 0x00, 0xFF,  // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01,        // Usage (0x01)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x17,        //   Report ID (23)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x1F,        //   Report Count (31)
    0x09, 0x05,        //   Usage (0x05)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
    // 660 bytes
};

struct Stats {
    int input_count;
    int collection[2];
};

size_t ItemizeHIDReportDesc(const uint8_t* rpt_desc, size_t desc_len, Stats* stats) {
    const uint8_t* buf = rpt_desc;
    size_t len = desc_len;
    while (len > 0) {
        size_t actual = 0;
        auto item = hid::Item::ReadNext(buf, len, &actual);
        if ((actual > len) || (actual == 0))
            break;

        if (item.tag() == hid::Item::Tag::kEndCollection)
            stats->collection[1]++;
        else if (item.tag() == hid::Item::Tag::kCollection)
            stats->collection[0]++;

        if (item.type() == hid::Item::Type::kMain && item.tag() == hid::Item::Tag::kInput)
            stats->input_count++;

        len -= actual;
        buf += actual;
    }

    return (desc_len - len);
}

}  // namespace.

static bool itemize_acer12_rpt1() {
    BEGIN_TEST;

    Stats stats = {};
    auto len = sizeof(acer12_touch_r_desc);
    auto consumed = ItemizeHIDReportDesc(acer12_touch_r_desc, len, &stats);

    ASSERT_EQ(consumed, len);
    ASSERT_EQ(stats.input_count, 45);
    ASSERT_EQ(stats.collection[0], 13);
    ASSERT_EQ(stats.collection[1], 13);

    END_TEST;
}

static bool parse_boot_mouse() {
    BEGIN_TEST;

    hid::DeviceDescriptor* dd = nullptr;
    auto res = hid::ParseReportDescriptor(
        boot_mouse_r_desc, sizeof(boot_mouse_r_desc), &dd);

    EXPECT_EQ(res, hid::ParseResult::kParseOk);
    END_TEST;
}

static bool parse_adaf_trinket() {
    BEGIN_TEST;

    hid::DeviceDescriptor* dd = nullptr;
    auto res = hid::ParseReportDescriptor(
        trinket_r_desc, sizeof(trinket_r_desc), &dd);

    EXPECT_EQ(res, hid::ParseResult::kParseOk);
    END_TEST;
}

static bool parse_acer12_touch() {
    BEGIN_TEST;

    hid::DeviceDescriptor* dd = nullptr;
    auto res = hid::ParseReportDescriptor(
        acer12_touch_r_desc, sizeof(acer12_touch_r_desc), &dd);

    EXPECT_EQ(res, hid::ParseResult::kParseOk);
    END_TEST;
}

BEGIN_TEST_CASE(hidparser_tests)
RUN_TEST(itemize_acer12_rpt1)
RUN_TEST(parse_boot_mouse)
RUN_TEST(parse_adaf_trinket)
RUN_TEST(parse_acer12_touch)
END_TEST_CASE(hidparser_tests)

int main(int argc, char** argv) {
    bool success = unittest_run_all_tests(argc, argv);
    return success ? 0 : -1;
}
