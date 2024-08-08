# App update POC

Proof of concept app which installed in PT with A/B, and updates itself over wifi (with hash or sig)

basically, that need to find the flash partition where the data goes, and install it, then reboot with "try-before-you-buy"

This ensures we have sufficient bootrom APIs to do this kind of stuff, and also does some testing of rolling-windows, absolute/rel flash etc.

_extra points if we support separate downloadable say WiFi firmware in a separate (set of A/B) partition(s)_ 

NOTE: this should work for both ARM/RISC-V (can't be signed on RISC-V but could be hashed; but then again with try before you buy, it doesn't really matter)
