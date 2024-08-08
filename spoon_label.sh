# row of white label struct
picotool otp set -e OTP_DATA_USB_WHITE_LABEL_ADDR 0x400
# white label VOLUME_LABEL entry is 05 ASCII characters at 0x400 + 0x30 = 0x430
picotool otp set -e 0x408 0x3005
# 'S', 'P'
picotool otp set -e 0x430 0x5053
# 'O', 'O'
picotool otp set -e 0x431 0x4f4f
# 'N'
picotool otp set -e 0x432 0x4e
# Enable (bit 8 == VOLUME_LABEL override valid, bit 22 = OTP_DATA_USB_WHITE_LABEL_ADDR valid
picotool otp set -r OTP_DATA_USB_BOOT_FLAGS 0x400100
# OTP_DATA_USB_BOOT_FLAGS + 1 for RBIT3
picotool otp set -r 0x5a 0x400100

picotool reboot -u