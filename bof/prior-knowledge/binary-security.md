# Binary Security

Binaries, like .exe or .elf files, have security implementations that we need to know how to enumerate and understand. While there are some security mechanisms present, this does not mean its unexploitable, just a lot harder.

## ASLR

Address Space Layout Randomization (ASLR) is a measure that is meant to introduce randomness of executables, the libraries it uses and the stack in memory address space.

For example, take a look at this snippet:

```c
#include <stdlib.h>
int main(){
    system("echo 'hello world!'");
    return 0;
}
```

This is a program that basically executes a `system` function, which allows us to execute any command we want as if we were in a command terminal. Each time a program uses a library, it would call that library to find the pre-defined functions that it needs, in this case `system` from `stdlib.h`.  This `system` function lives within the `stdlib.h`, and has a specific address of which it exists. This address is specified as an offset.&#x20;

For example if the base address is loaded at `0x12345678`, and the offset is `0x00000001`, then the `system` function would be at `0x12345677` within the library on our machine.&#x20;

Without ASLR, the address of which this function exists in is **always the same**. The memory address is static, and this can be rather dangerous as predictability can allow for buffer overflows (which rely on memory addresses) to be rather easy.

With ASLR, the OS loads the same executable at **different locations in memory each time**. This means that everytime we run this program, the memory addresses are completely different. This would mean that the function effectively 'lives' at a different area as well.&#x20;

## DEP

Data Execution Prevention (DEP) is a defensive hardware and software measure that **prevents the exeuction of code within memory**. This would mean that when we do an exploit on this, we cannot **inject malicious shellcode into memory** because it would not run.

## Canary / Stack Cookie

This measure would place a value next to the return address on the stack. This prefix would prevent for the attackers from controlling the EIP and returning to wherever they want.&#x20;

The function prologue would load this value into its location, and everytime there is a return statement, the program checks to see if this value has been edited in any way. If it has, the program does not continue with execution. If nothing is detected, then it will continue as per normal.

## RELRO

To understand what Relocation Read-Only (RELRO) means, we need to understand a bit more about how binaries **find the right functions within the libraries they load**.

### GOT / PLT

When .elf binaries are compiled, they contain a look-up table called the **Global Offset Table (GOT)**, which **dynamically** resolve functions that are located in shared libraries. These calls point towards the **Procedure Linkage Table (PLT)** which is present in the .plt section of the binary.

For example, let's say we call the `puts()` function within our program. Our program does not actually have the `puts()` function within it, but it is compiled as `puts@plt`. This is because the program **does not actually know where it is yet**. So, the function jumps to the PLT entry of `puts()` and there are two things that can happen:

* If there is a GOT entry for `puts()`, then it jumps to the address stored there and executes.&#x20;
* If there isn't a GOT entry for it, it will resolve it and jump there afterwards. This address is stored and **does not usually change**. This is also known as 'lazy binding'.

This raises a few vulnerabilities:

* The PLT is at a **fixed location from the .text section,** else the program would not know where to go to find functions.
* GOT contains data used by different parts of the program directly, and **is also located at a known static address**.&#x20;
* **Once a function is called, its address is saved and does not change within the GOT**.
* The GOT contains the **actual addresses in memory** of `libc` functions within it. When the PLT gets called, it reads the GOT address and redirects execution there. Else, it coordinates with the `ld.so` file, known as a **dynamic linker**, to get the function address and store it in the GOT.

Because of how it is structured, **calling the PLT address of a function is the same as calling the function itself**. The GOT address contains addresses of functions in `libc`, and this table is part of the binary at a **static location with a constant offset away from the base address**.&#x20;

As such, attackers can do the following if they are able to write bytes in a specific location in memory:

* Redirect execution of a function to its PLT entry. We can call `system()` through the table without jumping to `libc`.&#x20;
* If RELRO is partial or disabled, **attackers can overwrite the GOT entries** and execute code on the vulnerable machine.&#x20;
* If ASLR is disabled, we can find the addresses of the `libc` functions.&#x20;
* If ASLR is enabled, we can **can leak the base address** of the binary to find the functions through calculating the offsets. This can be easily done **if we have LFI on the machine,** as we can read the `/proc/<pid>/maps` directory to find the exact address that each library is loaded at, thus finding the base address.&#x20;

### Security Measures

RELRO would **harden** the binary by making sure that we **do not have any ability to overwrite the GOT table**. There is **partial RELRO** and **full RELRO**.&#x20;

With partial RELRO, it is possible to do a 'GOT Overwrite' attack, where the GOT address is overwritten with the location of another function or with a ROP gadget that an attacker can run. In essence, we can force the GOT to point towards an address we can control, which can lead to RCE.

With Full RELRO, we cannot do anything with it. The GOT and PLT are all read-only, and **any attempts to overwrite them would crash the program**. This prevents any tampering with addresses within the binary.

Most binaries are compiled with partial RELRO by default, as Full RELRO has a significant effect on program startup time since all symbols must be resolved before a program is started. In large programs, the effect is quite visible.&#x20;

Here's a writeup to a GOT Overwrite exploit:

{% embed url="https://infosecwriteups.com/got-overwrite-bb9ff5414628" %}

## Compiler Flags

To compile binaries with these security measures, we have to include **specific flags** when compiling. Below is a list of flags for the `gcc` compiler.&#x20;

```
GCC Security related flags and options:

CFLAGS="-fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2" 
LDFLAGS="-Wl,-z,now -Wl,-z,relro"
  Hardened gentoo default flags.
  
-Wall -Wextra
  Turn on all warnings.

-Wconversion -Wsign-conversion
  Warn on unsign/sign conversions.

-Wformat­security
  Warn about uses of format functions that represent possible security problems

-Werror
  Turns all warnings into errors.

-arch x86_64
  Compile for 64-bit to take max advantage of address space (important for ASLR; more virtual address space to chose from when randomising layout).

-fstack-protector-all -Wstack-protector --param ssp-buffer-size=4
  Your choice of "-fstack-protector" does not protect all functions (see comments). You need -fstack-protector-all to guarantee guards are applied to all functions, although this will likely incur a performance penalty. Consider -fstack-protector-strong as a middle ground.
  The -Wstack-protector flag here gives warnings for any functions that aren't going to get protected.

-pie -fPIE
  For ASLR

-ftrapv
  Generates traps for signed overflow (currently bugged in gcc)

-­D_FORTIFY_SOURCE=2 ­O2
  Buffer overflow checks. See also difference between =2 and =1

­-Wl,-z,relro,-z,now
  RELRO (read-only relocation). The options relro & now specified together are known as "Full RELRO". You can specify "Partial RELRO" by omitting the now flag. RELRO marks various ELF memory sections read­only (E.g. the GOT)

If compiling on Windows, please Visual Studio instead of GCC, as some protections for Windows (ex. SEHOP) are not part of GCC, but if you must use GCC:

-Wl,dynamicbase
  Tell linker to use ASLR protection

-Wl,nxcompat
  Tell linker to use DEP protection
  
```

## Enumeration

When we first get a binary, we can use `checksec` from gdb to see the security measures that have been enabled for .elf files.

For Windows files, we can use this tool:

{% embed url="https://github.com/trailofbits/winchecksec" %}

When we get the output from the command, it would look something like this:

<figure><img src="../../.gitbook/assets/image (2971).png" alt=""><figcaption><p><em>Taken from HTB Retired</em></p></figcaption></figure>

We can breakdown the output from this:

* CANARY has been **disabled**, meaning there are no stack cookies present
* FORTIFY has been **disabled**, meaning there are no checks for buffer overflows within the binary (indicating this binary is vulnerable!)
* NX has been **enabled**, meaning that **no execute is enabled**. This means the memory within the stack is non-executable and DEP has been enabled. **Thus, no shellcode injection here.**
* PIE has been **enabled**, meaning ASLR is enabled. This makes all attacks significantly more difficult as addresses change each time it is run.
* RELRO is on **FULL,** meaning that the binary is **fully read-only** and its contents cannot be edited throughout the execution of it. So the GOT and PLT tables cannot be edited in any way.&#x20;

With this knowledge, we would need to use a debugger to see the application better. For this machine in HTB, it was vulnerable to ROP chaning leading to RCE, as that was the only option.

## Summary

If NX is enabled, there's no execution from the stack, but this does not rule shellcode out entirely! It is still possible to execute shellcode through calling `mprotect`, which is a function that makes the stack executable.

If CANARY is enabled, we would need to either:

* Leak the stack cookie
* Brute Force the cookie if predictable enough

If PIE is enabled, it means ASLR is on. We would need to either:

* Leak the base address of the library `libc` calls. This would allow us to find the addresses of the rest of the functions within the binary.
* Brute force the address we want if the ASLR range is not large enough and it's predictable.

If RELRO is **not set to full**:

* GOT Overwrite attack for RELRO disabled and partial.

If FORTIFY is disabled:

* Binaries are possibly vulnerable to BOF as the compiler does not intelligently check for any vulnerabilities within it. This means that the variables that are user-controlled can be manipulated to exceed their maximum limit.
