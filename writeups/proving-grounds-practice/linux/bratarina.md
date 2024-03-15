# Bratarina

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.197.71
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 15:27 +08
Nmap scan report for 192.168.197.71
Host is up (0.18s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
80/tcp  open   http
445/tcp open   microsoft-ds
```

Interesting ports are open. I did a detailed `nmap` scan too just in case:

```
$ sudo nmap -p 25,80,445 -sC -sV --min-rate 4000 -Pn 192.168.197.71
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 15:28 +08
Nmap scan report for 192.168.197.71
Host is up (0.19s latency).

PORT    STATE SERVICE     VERSION
25/tcp  open  smtp        OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.216], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
80/tcp  open  http        nginx 1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB        
|_http-server-header: nginx/1.14.0 (Ubuntu)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
```

### SMTPD RCE -> Root

The first thing I noticed was OpenSMTPD 2.0.0, which just looks outdated. There are a handful of exploits available:

```
$ searchsploit OpenSMTPD     
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)   | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploi | linux/local/48185.rb
OpenSMTPD 6.4.0 < 6.6.1 - Local Privilege Escalation + Rem | openbsd/remote/48051.pl
OpenSMTPD 6.6.1 - Remote Code Execution                    | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                      | linux/remote/48139.c
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote  | openbsd/remote/48140.c
----------------------------------------------------------- --------------------------------
```

The RCE exploit looks the most promising. We can verify it works using `ping`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1061).png" alt=""><figcaption></figcaption></figure>

I was facing similar difficulties in getting a reverse shell back, and found that we had to use port 25 as the listener port:

<figure><img src="../../../.gitbook/assets/image (2103).png" alt=""><figcaption></figcaption></figure>

Rooted!
