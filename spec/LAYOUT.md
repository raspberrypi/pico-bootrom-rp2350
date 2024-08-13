# LAYOUT

```
------ 
           EX : exempt_start:
0x0000     EX : ARM vector table (PC, SP, NMI, Hardfault, as IRQs are not used)
  +010     EX : ARM well known stuff
           EX : {
           EX :    main bootrom code that is in the exempt region on ARM, and may also be called by RISC-V
           EX :    note that because the code is exempt, these functions may be called from SECURE, and must
           EX :         be hardened.
           EX :    functions of the form:
           EX :   
           EX :    s_arm8_foo: ARM8 code
           EX :    s_arm6_foo: ARM6 code (can have RCP)
           EX :    s_native_foo: ARM8 code (but named native because the same code is compiled natively for RISC-V)
           EX :    s_from_arm_foo: ARM8 code (can have RCP) NSC wrappers 
           EX :       // todo currently this is ARM8 because RISC-V does not need the checking
           EX :       // provided by the NSC wrappers, and just calls the secure version directly.
           EX :    sb_foo: Sweet-b stuff
           EX : }
           EX : exempt_end:
           NS : ns_start:
           NS : {
           NS :     non secure functions that CANNOT be called in secure mode, so don't need to be hardened
           NS : }
------
           NS : nsboot_start:
0xxxx0     NS : NSBOOT NS VECTOR TABLE (must be 0x80 aligned) - full of code ecept for USBCTRL IRQ VECTOR
 +0x78     NS : USBCTRL IRQ VECTOR   
           NS : nsboot_end:
------
           NS : riscv_start:
           NS : riscv_end:
------      
0x7ddc     NS : RISC-V well known stuff
0x7dec     NS : RISC-V initial PC
0x7e00     NS : ns_end:
------
0x7e00 S(NSC) : secure gateways
       S(NSC) : currently misc RISC-V code because we needed the space for A0 - ideally this wont be there for A17
------
```