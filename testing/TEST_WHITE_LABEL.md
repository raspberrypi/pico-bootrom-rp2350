# USB boot white label

This is hopefully a reasonably quickly tractable one!

People want to "white label" their RP2350 for inclusion in other products, which means that every lavel/identification exposed via our USB boot should be replaceable via OTP.

The OTP rows detailed below are pertinent; a few notes first:

* OTP rows can be ECC, in which case they are 16 bits, or raw in which case they are 24
* We must always support partially written OTP rows (or combination of rows), so any optional ECC row is guarded
  by an enable bit.
* ECC rows cannot be changed to different values later, so are used for "values"
* Bit fields are kept in raw rows; geneerally as"RBIT-3"; "RBIT-3" is just 3 sequential raw rows of 24 bits each intended to hold identical copies of the data. When read we do an "out-of-3" vote for each bit position based on the 3 copies, to allow for possible bit errors.

```c
// =============================================================================
// Register    : OTP_DATA_USB_WHITE_LABEL_ADDR
// Description : Row index of the USB_WHITE_LABEL structure within OTP (ECC) The
//               table has 16 rows, each of which are also ECC and marked valid
//               by the corresponding valid bit in USB_BOOT_FLAGS (ECC).
//
//               The entries are either _VALUEs where the 16 bit value is used
//               as is, or _STRDEFs which acts as a pointers to a string value.
//
//               The value stored in a _STRDEF is two separate bytes: The low
//               seven bits of the first (LSB) byte indicates the number of
//               characters in the string, and the top bit of the first (LSB)
//               byte if set to indicate that each character in the string is
//               two bytes (Unicode) versus one byte if unset. The second (MSB)
//               byte represents the location of the string data, and is encoded
//               as the number of rows from this USB_WHITE_LABEL_ADDR; i.e. the
//               row of the start of the string is USB_WHITE_LABEL_ADDR value +
//               msb_byte.
//
//               In each case, the corresponding valid bit enables replacing the
//               default value for the corresponding item provided by the boot
//               rom.
//
//               Note that Unicode _STRDEFs are only supported for
//               USB_DEVICE_PRODUCT_STRDEF, USB_DEVICE_SERIAL_NUMBER_STRDEF and
//               USB_CONFIG_ATTRIBUTES_MAX_POWER_VALUES. Unicode values will be
//               ignored if specified for other fields, and non unicode values
//               for these three items will be converted to Unicode characters
//               by setting the upper 8 bits to zero.
//
//               Note that if the USB_WHITE_LABEL structure or the corresponding
//               strings are not readable by BOOTSEL mode based on OTP
//               permissions, or if alignment requirements are not met, then the
//               corresponding default values are used.
//
//               The index values indicate where each field is located (row
//               USB_WHITE_LABEL_ADDR value + index):
//               0x0000 -> INDEX_USB_DEVICE_VID_VALUE
//               0x0001 -> INDEX_USB_DEVICE_PID_VALUE
//               0x0002 -> INDEX_USB_DEVICE_BCD_DEVICE_VALUE
//               0x0003 -> INDEX_USB_DEVICE_LANG_ID_VALUE
//               0x0004 -> INDEX_USB_DEVICE_MANUFACTURER_STRDEF
//               0x0005 -> INDEX_USB_DEVICE_PRODUCT_STRDEF
//               0x0006 -> INDEX_USB_DEVICE_SERIAL_NUMBER_STRDEF
//               0x0007 -> INDEX_USB_CONFIG_ATTRIBUTES_MAX_POWER_VALUES
//               0x0008 -> INDEX_VOLUME_LABEL_STRDEF
//               0x0009 -> INDEX_SCSI_INQUIRY_VENDOR_STRDEF
//               0x000a -> INDEX_SCSI_INQUIRY_PRODUCT_STRDEF
//               0x000b -> INDEX_SCSI_INQUIRY_VERSION_STRDEF
//               0x000c -> INDEX_INDEX_HTM_REDIRECT_URL_STRDEF
//               0x000d -> INDEX_INDEX_HTM_REDIRECT_NAME_STRDEF
//               0x000e -> INDEX_INFO_UF2_TXT_MODEL_STRDEF
//               0x000f -> INDEX_INFO_UF2_TXT_BOARD_ID_STRDEF
#define OTP_DATA_USB_WHITE_LABEL_ADDR_ROW _u(0x6e)

// Register    : OTP_DATA_USB_BOOT_FLAGS
// Description : USB boot specific feature flags (RBIT-3)
#define OTP_DATA_USB_BOOT_FLAGS_ROW _u(0x6b)
// -----------------------------------------------------------------------------
// Field       : OTP_DATA_USB_BOOT_FLAGS_WHITE_LABEL_ADDR_VALID
// Description : valid flag for INFO_UF2_TXT_BOARD_ID_STRDEF entry of the
//               USB_WHITE_LABEL struct (index 15)
#define OTP_DATA_USB_BOOT_FLAGS_WHITE_LABEL_ADDR_VALID_RESET  "-"
#define OTP_DATA_USB_BOOT_FLAGS_WHITE_LABEL_ADDR_VALID_BITS   _u(0x00400000)
// -----------------------------------------------------------------------------
// Description : valid bits foe each of the 16 white label struct entries
#define OTP_DATA_USB_BOOT_FLAGS_WL_INFO_UF2_TXT_BOARD_ID_STRDEF_VALID_BITS   _u(0x00008000)
#define OTP_DATA_USB_BOOT_FLAGS_WL_INFO_UF2_TXT_MODEL_STRDEF_VALID_BITS   _u(0x00004000)
#define OTP_DATA_USB_BOOT_FLAGS_WL_INDEX_HTM_REDIRECT_NAME_STRDEF_VALID_BITS   _u(0x00002000)
#define OTP_DATA_USB_BOOT_FLAGS_WL_INDEX_HTM_REDIRECT_URL_STRDEF_VALID_BITS   _u(0x00001000)
#define OTP_DATA_USB_BOOT_FLAGS_WL_SCSI_INQUIRY_VERSION_STRDEF_VALID_BITS   _u(0x00000800)
#define OTP_DATA_USB_BOOT_FLAGS_WL_SCSI_INQUIRY_PRODUCT_STRDEF_VALID_BITS   _u(0x00000400)
#define OTP_DATA_USB_BOOT_FLAGS_WL_SCSI_INQUIRY_VENDOR_STRDEF_VALID_BITS   _u(0x00000200)
#define OTP_DATA_USB_BOOT_FLAGS_WL_VOLUME_LABEL_STRDEF_VALID_BITS   _u(0x00000100)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_CONFIG_ATTRIBUTES_MAX_POWER_VALUES_VALID_BITS   _u(0x00000080)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_SERIAL_NUMBER_STRDEF_VALID_BITS   _u(0x00000040)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_PRODUCT_STRDEF_VALID_BITS   _u(0x00000020)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_MANUFACTURER_STRDEF_VALID_BITS   _u(0x00000010)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_LANG_ID_VALUE_VALID_BITS   _u(0x00000008)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_SERIAL_NUMBER_VALUE_VALID_BITS   _u(0x00000004)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_PID_VALUE_VALID_BITS   _u(0x00000002)
#define OTP_DATA_USB_BOOT_FLAGS_WL_USB_DEVICE_VID_VALUE_VALID_BITS   _u(0x00000001)
// =============================================================================
// Register    : OTP_DATA_USB_BOOT_FLAGS_R1
// Description : Redundant copy of USB_BOOT_FLAGS
#define OTP_DATA_USB_BOOT_FLAGS_R1_ROW _u(0x6c)
// =============================================================================
// Register    : OTP_DATA_USB_BOOT_FLAGS_R2
// Description : Redundant copy of USB_BOOT_FLAGS
#define OTP_DATA_USB_BOOT_FLAGS_R2_ROW _u(0x6d)

```

## What to test

we want to test:

1. that all the values can be overriden individually and show up correctly
2. that too long values are truncated correctly
3. that values or the white label struct spanning non-readable (to nsboot) OTP pages should take their default values
4. that invalid values dont crash things (at least like to see that this is roughly the case) .. note we may send unreadable characters to the host, but hey, write the correct thing to OTP.

## What/where are these fields

### USB device descriptor
These 16 bit values are copied as is into the USB device descriptor (little endian)
* INDEX_USB_DEVICE_VID_VALUE (0x2e8a)
* INDEX_USB_DEVICE_PID_VALUE (0x000f)
* INDEX_USB_DEVICE_BCD_DEVICE_VALUE (0x0100)
* INDEX_USB_DEVICE_LANG_ID_VALUE (0x0409)
### USB device strings
Note these 3 can be UTF-16 or ascii (max 30 chars in either)
* INDEX_USB_DEVICE_MANUFACTURER_STRDEF ("Raspberry Pi")
* INDEX_USB_DEVICE_PRODUCT_STRDEF ("RP2350 Boot")
* INDEX_USB_DEVICE_SERIAL_NUMBER_STRDEF (hex string of device_id_lo, device_id_hi, wafer_id_lo, wafer_id_hi - i.e. first 4 rows of OTP)
### USB configuration descriptor
Note these are not white-label per se, but users want to be able to change them based on the device they are building
* INDEX_USB_CONFIG_ATTRIBUTES_MAX_POWER_VALUES ('0xfa80' i.e. bMaxPower of 0xfa, bmAttributes=0x80)
### UF2 volume related
* INDEX_VOLUME_LABEL_STRDEF ("RP2350") - max 11 bytes
### UF2 INDEX.HTM file
This is of the form:

`<html><head><meta http-equiv="refresh" content="0;URL='`
_REDIRECT_URL_
`'"/></head><body>Redirecting to <a href='`
_REDIRECT_URL_
`'>`
_REDIRECT_NAME_
`</a></body></html>`

* INDEX_INDEX_HTM_REDIRECT_URL_STRDEF ("https://raspberrypi.com/device/RP2?version=5A09D5466F90", note the 12 hex digits are the first 6 of the SYSINFO_GITREF_RP2350 and the first 6 of the bootrom gitref, max 127)
* INDEX_INDEX_HTM_REDIRECT_NAME_STRDEF ("raspberrypi.com", max 127)
### UF2 INFO_UF2.TXT file
Tnhis is of the form:

`UF2 Bootloader v1.0`

`Model: ` _MODEL_

`Board-ID: ` _BOARD_ID_
* INDEX_INFO_UF2_TXT_MODEL_STRDEF ("Raspberry Pi RP2350", max 128)
* INDEX_INFO_UF2_TXT_BOARD_ID_STRDEF ("RP2350", max 128)

### scsi inquiry
* INDEX_SCSI_INQUIRY_VENDOR_STRDEF ("RPI", max 8)
* INDEX_SCSI_INQUIRY_PRODUCT_STRDEF ("RP2350", max 16)
* INDEX_SCSI_INQUIRY_VERSION_STRDEF ("1", max 4)

Examples from my device:

```bash
lsusb -v -s 1:31

Bus 001 Device 031: ID 2e8a:000f Raspberry Pi RP2350 Boot
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               2.10
  bDeviceClass            0 
  bDeviceSubClass         0 
  bDeviceProtocol         0 
  bMaxPacketSize0        64
  idVendor           0x2e8a <--
  idProduct          0x000f <--
  bcdDevice            1.00 <--
  iManufacturer           1 Raspberry Pi <--
  iProduct                2 RP2350 Boot <--
  iSerial                 3 0000000000000000 <--
  bNumConfigurations      1
  Configuration Descriptor:
    bLength                 9
    bDescriptorType         2
    wTotalLength       0x0037
    bNumInterfaces          2
    bConfigurationValue     1
    iConfiguration          0 
    bmAttributes         0x80 <--
      (Bus Powered)
    MaxPower              500mA <--

```

```
sudo sg_inq /dev/sde1
invalid VPD response; probably a STANDARD INQUIRY response
standard INQUIRY:
  PQual=0  Device_type=0  RMB=1  LU_CONG=0  version=0x02  [SCSI-2]
  [AERC=0]  [TrmTsk=0]  NormACA=0  HiSUP=0  Resp_data_format=2
  SCCS=0  ACC=0  TPGS=0  3PC=0  Protect=0  [BQue=0]
  EncServ=0  MultiP=0  [MChngr=0]  [ACKREQQ=0]  Addr16=0
  [RelAdr=0]  WBus16=0  Sync=0  [Linked=0]  [TranDis=0]  CmdQue=0
    length=36 (0x24)   Peripheral device type: disk
 Vendor identification: RPI <--   
 Product identification: RP2350 <--         
 Product revision level: 1 <--  
```

This is a bit weird; I swear in the past this used to include the information (and now doesn't for RP2040 either),
so seems like a Ubuntu change perhaps.
```bash
lsblk -JO /dev/sde1 | json_pp
```

### UF2 drive serial number

The UF2 drive serial number is supposed to be based on the unique id for the chip in OTP...

```bash
lsblk -oNAME,LABEL,UUID /dev/sde1
NAME LABEL  UUID
sde1 RP2350 000B-5BF4
```

Currently, (wrongly thought perhaps it doesn't much matter) it is hardware timer based as on RP2040.

