# Algernon

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.219.65 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 10:33 +08
Nmap scan report for 192.168.219.65
Host is up (0.17s latency).
Not shown: 65520 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
7680/tcp  open  pando-pub
9998/tcp  open  distinct32
17001/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

Lots of ports open.&#x20;

### Rabbit Holes

Port 80 just shows an IIS server default page, with no further directories. FTP does allow for anonymous access, but there aren't any files within it.&#x20;

### SmarterMail RCE

Port 9998 shows a login page for SmarterMail:

<figure><img src="../../../.gitbook/assets/image (3605).png" alt=""><figcaption></figcaption></figure>

If we view the page source, we can sort of find the version that is running:

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

This software has quite a few exploits:

```
$ searchsploit smartermail   
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
SmarterMail 16 - Arbitrary File Upload                     | multiple/webapps/48580.py
SmarterMail 7.1.3876 - Directory Traversal                 | windows/remote/15048.txt
SmarterMail 7.3/7.4 - Multiple Vulnerabilities             | asp/webapps/16955.txt
SmarterMail 8.0 - Multiple Cross-Site Scripting Vulnerabil | asp/webapps/16975.txt
SmarterMail < 7.2.3925 - LDAP Injection                    | asp/webapps/15189.txt
SmarterMail < 7.2.3925 - Persistent Cross-Site Scripting   | asp/webapps/15185.txt
SmarterMail Build 6985 - Remote Code Execution             | windows/remote/49216.py
SmarterMail Enterprise and Standard 11.x - Persistent Cros | asp/webapps/31017.php
smartermail free 9.2 - Persistent Cross-Site Scripting     | windows/webapps/20362.py
SmarterTools SmarterMail 4.3 - 'Subject' HTML Injection    | php/webapps/31240.txt
SmarterTools SmarterMail 5.0 - HTTP Request Handling Denia | windows/dos/31607.py
----------------------------------------------------------- ---------------------------------
```

The product build listed above is 6919, which is older than the RCE exploit for Build 6985. As such, we can use that exploit. Just change the IP addresses and leave the ports.

Running that gives us a reverse shell as the SYSTEM user:

<figure><img src="../../../.gitbook/assets/image (3108).png" alt=""><figcaption></figcaption></figure>

Rooted!
