# Nibbles

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.219.47
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 10:40 +08
Nmap scan report for 192.168.219.47
Host is up (0.17s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
80/tcp   open   http
5437/tcp open   pmip6-data
```

Did a detailed scan as well.&#x20;

```
$ sudo nmap -p 21,22,80,5437 -sC -sV --min-rate 5000 192.168.219.47                
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 10:42 +08
Nmap scan report for 192.168.219.47
Host is up (0.17s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 10621ff522de29d42496a766c364b710 (RSA)
|   256 c915ffcdf397ec3913164838c558d75f (ECDSA)
|_  256 907ca34473b4b44ce39c71d187baca7b (ED25519)
80/tcp   open  http       Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Enter a title, displayed at the top of the window.
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.9
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-27T15:41:47
|_Not valid after:  2030-04-25T15:41:47
|_ssl-date: TLS randomness does not represent time
```

### SQL Creds -> RCE

I enumerated the PostGreSQL instance, and found that the default credentials of `postgres:postgres` worked.&#x20;

<figure><img src="../../../.gitbook/assets/image (1942).png" alt=""><figcaption></figcaption></figure>

I tested the RCE PoC on Hacktricks, and it worked:

<figure><img src="../../../.gitbook/assets/image (3397).png" alt=""><figcaption></figcaption></figure>

We can then use a Metasploit module to get a reverse shell as this user.&#x20;

<figure><img src="../../../.gitbook/assets/image (2134).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SUID Binaries -> Root

Ran a search on what SUID binaries there were, and found that `find` was one of them:

```
$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mount
/usr/bin/find
/usr/bin/sudo
/usr/bin/umount
```

Use the command from GTFOBins to get a shell as `root`:

<figure><img src="../../../.gitbook/assets/image (4058).png" alt=""><figcaption></figcaption></figure>
