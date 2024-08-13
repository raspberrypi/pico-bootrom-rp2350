## Bootrom OTP spec

### OTP rbit read hardening

TODO: something about how to read rbits etc. in a hardened way

### OTP access under "USB boot"

#### Usually NS application code runs with **NS** permission which are normally the least permissive,

Rationale: application code cannot accidentally write to OTP

#### Secure code runs with **S** permission which are normally the most permissive.

Note that we have multiple levels of secure code; i.e. a secure bootloader may lock down
pages before the main secure application runs.

Secure code must be able to protect reading/writing from parts of OTP. This is handled
by advancing the secure page locks at runtime (which then requires a reset to unlock)

#### "USB boot" adds flexibility and complexity

1. "USB boot" happens before any secure code (even bootloader runs)
2. We want to allow users to use `picotool` to configure OTP.
3. We want `picotool` to be able to do more than regular `NS` code (note "USB boot" itself is a non-secure app, so 
   when we refer to it's access we generally mean what secure code does on its behalf - note that "USB boot" code 
   itself will never deliberately access OTP except via the secure gateway provided for its benefit)

   Rationale: it is quite likely that users will want to be able to configure things by picotool that they don't 
   exposed to a random NS app.

First it is worth mentioning that we have course OTP flags based controls that can be applied which affect the 
launching of the non-secure "USB boot" code

* *Disable picoboot* - this should be "disable USB PICOBOOT"
* *Disable UART boot* - this should be "disable UART PICOBOOT" 
* *Disable I2C boot* - this should be "disable I2C PICOBOOT"
* *Disable USB MSD* - this is not a PICOBOOT interface

**FACT**: if none of the PICOBOOT interfaces are enabled (note at most one can be), then the secure gateway for OTP 
will not be available.

##### So what happens with OTP if PICOBOOT is enabled

The "USB boot" app itself runs as NS code, and will have NS OTP permissions.

We have two scenarios based on (**TODO**) new "OTP accesses via picotool must be signed"

1. The default mode i.e. no need for signing to access OTP:
   
   The secure bootrom code will provide an API for "USB boot" code to perform access at "USB boot" permission level.

    Rationale: the user will have been able to lock down bits of OTP it doesn't want accessible to the end user, but 
   the end user can still read/write other stuff.

2. When signed picotool packets are required to access OTP:

   **FACT**: signed packets are handled in the secure state.
   
   We still want to be able to use a different set of OTP permissions (other than "S")

   Rationale: it is still likely that we don't want to give access to certain OTP pages belonging to say a 
   bootloader. Normally, the bootloader would runtime advance the locks to prevent access to later secure code, but 
   in this case we want to just use the "USB boot" permissisons to deny access as no bootloader code is run before 
   "USB boot"

**FACT**: It turns out (*and Luke said this!*), that we can handle both use cases by advancing the secure locks to the 
"USB 
boot" settings before launching USB boot ;-) 
i.e. once we enter USB boot, the hardware will prevent any access to anything not available with "USB boot" permissions.

##### But what if you wanted to set some of the "S" accessible stuff via signed PICOBOOT

You just have to give "USB boot" access the same permissions as "S" access for that page. Given that we have decided 
now that you have to choose via (OTP flag) between whether OTP access can be done with or without signing, there 
isn't a case where we might run NS code with these permissive "USB boot" permissions.

##### Final notes / Questions

* I don't think there is any need to disallow (nor can we) OTP access via signed code if signing is enabled, but 
  we've allowed non-signed PICOBOOT access to OTP too. The secure code will just have "USB boot" permissions as allways
* **FACT** we should rename these permissions PICOBOOT if they aren't already!
* It can be a bit confusing when thinking about signed PICOBOOT, because it really gives you the ability to do 
  things in secure mode. However, what we've decided is that EVEN in this case you cannot access OTP with any 
  permissions above "USB boot" permissions. You could however boot into signed code.
* We actually lock down runtime NS OTP permissions entirely when entering USB boot. this only really affects PICOBOOT 
  EXEC code... which we should probably let call our API.

### bootrom related contents

#### USB nsboot

# boot override

2 - offset ->

1 - bmAttributes
1 - bmMaxPower
1 - Drive name (11)
1 - "Raspberry Pi",
// todo amy
"RP2350 Boot",
