Security Notes
==============

- Both cores start out of reset without valid stacks
  - core 0 will set a preboot secure stack and enter C code
  - core 1 will wait and do handshake wiht no stack until it is given a secure stack to use
- **Question**: do we now need to pause core1? I guess not, because if it is running it can itself reset ACCESSCTRL
- ~~**Question**: Clang?~~ No - it crashes in link with our mixed arm6/arm8


------
# OLD

## ~~Multiple function tables~~
  
For speed we don't want to have to NS wrap functions. However for something like memcpy (anything which accesses 
memory), we must do so potentially duplicate: If we just use the NS version then it would not be able to access 
secure memory.

- Common ARM Secure
- Common ARM NS
- Common RISCV
  
## Flash writing

Current thought is to use security attributes

# SECURITY REMINDERS 

- don't forget that non secure IRQ can preempt secure code and change NS data.
