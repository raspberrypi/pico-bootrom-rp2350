# Permissions

* flash permissions should be by partition table
  * QUESTION: what about override? at runtime; we've said you can install a partition table.
* Individual APIs
  * we should have redundant bits and indexes (permission for NS, and possibly boot?) - actually thing 16 bit half of rcp_ bool
  * API permissions with S/NS, P/NP ... hard to do S (P vs NP)
    * hopefully most of these (e.g. flash) actually have lower level test, but doh...
    * argh... BOOTRAM is SP only .. this means we can't check permissions in SP - ugh.
    * sadly we can't do equiv of SG into Priv, usually you'd do a SVC or whatever, but we don't own the vector. Equally, sadly, the doorbell etc. are logically owned by secure code.. 
    * seems like we have to restrict APIs to P (and user code will have to expose from P to NP) which aren't:
      * exempt, and able to reflect h/w state (otp APIS I think can do this for example), ah but we want spin lock - but that is fine for writes (that can be P) 
      * just able to reflect h/w state.
    * still a bit silly for things like boot_random which are in BOOTRAM
    * Question: how would we fix this if we wanted to in a later version

## Claiming

Can we avoid shared claiming by just assuming that we don't mix permissions S & NS, and that we don't change them once we're running (at least after they've been assigned)

Note: SDK does at least need to respect permissions when picking

**NOTE** Ah ha perhaps the thing i missed is claiming of things by the bootrom.

### DMA channels
* I believe we can assign these to NS, so that should just claim amongst those
### INTERP lane
* Um, i think the interp block is assigned now?
  * yes each interp - again we should 
### User IRQ
* These have to be granted, so good 
### PIO sm, PIO program space
* Again I think whole PIO is probably the way to go here
### Timer

### UART?
We talked about sharing a UART from server side

### Others

if there is a singleton instance, we should have a secure API covering it