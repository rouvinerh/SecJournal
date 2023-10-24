# Nappa

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.201.114
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 12:08 +08
Warning: 192.168.201.114 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.201.114
Host is up (0.17s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
21/tcp    open     ftp
3306/tcp  open     mysql
8080/tcp  open     http-proxy
28080/tcp open     thor-engine
60022/tcp open     unknown
```

### FTP Anonymous Creds

FTP accepts anonymous logins:

```
$ ftp 192.168.201.114                       
Connected to 192.168.201.114.
220 (vsFTPd 3.0.3)
Name (192.168.201.114:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||59327|)
150 Here comes the directory listing.
drwxr-xr-x   14 14       11           4096 Nov 06  2020 forum
226 Directory send OK.
ftp> cd forum
l250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||33106|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1965 Nov 06  2020 Gemfile
-rw-r--r--    1 0        0            5512 Nov 06  2020 Gemfile.lock
-rw-r--r--    1 0        0             374 Nov 06  2020 README.md
-rw-r--r--    1 0        0             227 Nov 06  2020 Rakefile
drwxr-xr-x   11 0        0            4096 Nov 06  2020 app
drwxr-xr-x    2 0        0            4096 Nov 06  2020 bin
drwxr-xr-x    5 0        0            4096 Nov 06  2020 config
-rw-r--r--    1 0        0             130 Nov 06  2020 config.ru
drwxr-xr-x    2 0        0            4096 Nov 06  2020 db
drwxr-xr-x    4 0        0            4096 Nov 06  2020 lib
drwxr-xr-x    2 0        0            4096 Nov 06  2020 log
-rw-r--r--    1 0        0             217 Nov 06  2020 package.json
drwxr-xr-x    2 0        0            4096 Nov 06  2020 public
drwxr-xr-x    2 0        0            4096 Nov 06  2020 storage
drwxr-xr-x   10 0        0            4096 Nov 06  2020 test
drwxr-xr-x    5 0        0            4096 Nov 06  2020 tmp
drwxr-xr-x    2 0        0            4096 Nov 06  2020 vendor
226 Directory send OK.
```

There was some config files and what not, but there's nothing in it at all. Moving on!

### Web Enumeration --> Password

Port 80 was a ForumOnRails instance:

<figure><img src="../../../.gitbook/assets/image (3088).png" alt=""><figcaption></figcaption></figure>

I registered a user and looked through the posts made by the admin, and found his email.

<figure><img src="../../../.gitbook/assets/image (3085).png" alt=""><figcaption></figcaption></figure>

I decided to look into the page source for the Login, Register and Forgot Password pages. Within the Register page, there's a password within the page source:

<figure><img src="../../../.gitbook/assets/image (1523).png" alt=""><figcaption></figcaption></figure>

We can then login as the admin email and password of `it0jNc6L/r090Q==`.&#x20;

### More Page Source Reading --> RCE

The administrator had access to the `/serverinfo` page:

<figure><img src="../../../.gitbook/assets/image (1535).png" alt=""><figcaption></figcaption></figure>

Again, there were some interesting comments in the page source:

<figure><img src="../../../.gitbook/assets/image (2561).png" alt=""><figcaption></figcaption></figure>

We can edit the HTML such that the `cmd` box appears:

<figure><img src="../../../.gitbook/assets/image (1271).png" alt=""><figcaption></figcaption></figure>

Then, we can send stuff to this to get a request within Burp, which can give us a reverse shell:

<figure><img src="../../../.gitbook/assets/image (2568).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3744).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Base32Key --> Root

The user's file had a few files:

```
[kathleen@nappa ~]$ ls -la
total 40
drwx------  5 kathleen kathleen 4096 Nov 16  2020 .
drwxr-xr-x  3 root     root     4096 Nov  4  2020 ..
-rw-------  1 kathleen kathleen    0 Nov  6  2020 .bash_history
-rw-r--r--  1 kathleen kathleen   21 Aug  9  2020 .bash_logout
-rw-r--r--  1 kathleen kathleen   57 Aug  9  2020 .bash_profile
-rw-r--r--  1 kathleen kathleen 4302 Nov  6  2020 .bashrc
drwxr-xr-x  3 kathleen kathleen 4096 Nov  4  2020 .bundle
drwxr-xr-x  4 kathleen kathleen 4096 Nov  4  2020 .gem
drwxr-xr-x 15 kathleen kathleen 4096 Nov  4  2020 forum
-rw-------  1 kathleen kathleen   33 Jul 15 04:08 local.txt
```

I read the `.bashrc` file which had a large string within it.&#x20;

```
[kathleen@nappa ~]$ cat .bashrc
#
# ~/.bashrc
#

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

alias ls='ls --color=auto'
PS1='[\u@\h \W]\$ '

# alias FUWS2LJNIJCUOSKOEBHV <TRUNCATED>
```

This string was only alphanumeric characters, so it wasn't `base64`. Similar to another machine, I checked what binaries starting with `base` were available:

```
[kathleen@nappa ~]$ base
base32    base64    basename  basenc
```

When decoded with `base32`, it revealed a private SSH key:

```
$ echo 'huge string here' | base32 -d
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<TRUNCATED>
```

We can then use this to `ssh` in as `root`:

<figure><img src="../../../.gitbook/assets/image (3169).png" alt=""><figcaption></figcaption></figure>
