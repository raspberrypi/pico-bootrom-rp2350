# USB Command Verifier

I had been running USB2CV (which is no longer available online, and I can't find the installer), however the latest copy USB3CV is available here.

Note I just tried USB3CV and it doesn't find the device on my crappy $150 old test machine, so someone should run the USB30CV version to check everything passes

https://www.usb.org/compliancetools

We need to run (in both ARM and RISC-V)

* (USB2) Chapter 9 Tests
* (USB2) MSC Tests

There should be no failures (there are a couple of warnings for things which are optional that we don't implement)

Note: that now we correctly expose the chip ID as the MSD serial number; it seems we do get a warning about it being all zeros (which is what the chip ID stuff is in OTP by default - would be programmed by ATE)