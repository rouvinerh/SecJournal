# Kotarak

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1669).png" alt=""><figcaption></figcaption></figure>

Doing a detailed Nmap scan reveals a bit more about the services running on the machine.

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Port 8080 was running a Tomcat instance, and this might be the method used for a reverse shell via a malicious .war file. Port 60000 was also running some form of custom application.&#x20;

Credentials were required for port 8080:

<figure><img src="../../../.gitbook/assets/image (3278).png" alt=""><figcaption></figcaption></figure>

### Private Browser

This port was hosting a private browser that takes a URL as a parameter.

<figure><img src="../../../.gitbook/assets/image (2764).png" alt=""><figcaption></figcaption></figure>

We can use this to get hits on our own HTTP server, but it does not seem to download files or anything. As such, there isn't much point on trying to host something on our machine. Instead, we can do SSRF and let this application **send requests to itself**. This would allow us to enumerate all ports that were open within the machine but not reachable from my Kali machine.

Using `curl` and a quick bash script, we can enumerate the ports that are open:

```bash
for i in {0..65535}; do
    cmd = $(curl -s http://10.10.10.55:60000/url.php?path=http://127.0.0.1:"${i}");
    echo -n "${i}: "; echo "$res"
    fi;
```

Eventually, we would start getting hits on the ports that are open.

### File Manager + Shell

Using this bash loop, we can find that there's a Simple File Viewer application open on port 888, that was unaccessible to us earlier.

<figure><img src="../../../.gitbook/assets/image (1116).png" alt=""><figcaption></figcaption></figure>

When viewing this page, we can see a few folders, but the most interesting would be the `backup` folder.

<figure><img src="../../../.gitbook/assets/image (197).png" alt=""><figcaption></figcaption></figure>

Clicking on the links does not work at all as we don't actually have access to this service from our machine. However, we can attempt to read the files using SSRF through the private browser.

The links were structured like this:

```markup
<a href="?doc=on"  class="tableElement">
```

We can see that the `?doc` parameter was being used to access these links. We can then read the files by accessing `http://10.10.10.15:60000/url.php?path=127.0.0.1:888?doc=backup`.

This reveals to us a folder with the Tomcat credentials.

<figure><img src="../../../.gitbook/assets/image (2091).png" alt=""><figcaption></figcaption></figure>

With this, we can acess port 8080 and login. Then, using `msfvenom`, we can generate a quick reverse shell to upload to gain a reverse shell easily.

<figure><img src="../../../.gitbook/assets/image (1047).png" alt=""><figcaption></figcaption></figure>

We would be the `tomcat` user on the machine.

## Privilege Escalation

### Windows Memory Dump

When viewing the `/home` directory, we can find another user present.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

The `tomcat` user also had some interesting files within their directory.

<figure><img src="../../../.gitbook/assets/image (3063).png" alt=""><figcaption></figcaption></figure>

The name of the file was a giveaway that this contained NTLM hashes from a memory dump of a Windows machine. As such, we can transfer this back to our machine and dump the credentials using `secretsdump.py`.

<figure><img src="../../../.gitbook/assets/image (2821).png" alt=""><figcaption></figcaption></figure>

Then we can crack the Administrator's hash to get `f16tomcat!`. Afterwards, we can `su` to the `atanas` user with these credentials.

<figure><img src="../../../.gitbook/assets/image (893).png" alt=""><figcaption></figcaption></figure>

### wget RCE

Interestingly, the `atanas` user can access the root directory and find a hint as to where the root flag is.

<figure><img src="../../../.gitbook/assets/image (1069).png" alt=""><figcaption></figcaption></figure>

Reading the `app.log` file reveals some interesting stuff.

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

First thing to note was that there was another IP address at 10.0.3.133. Next, this was using `wget` 1.16, which was a vulnerable version of the binary. Lastly, take a look at the timestamps. Notice how they occur exactly after every 2 minutes? Perhaps this was a cronjob running in the background that we needed to exploit.&#x20;

There were scripts for the exploit available on Github:

{% embed url="https://github.com/xl7dev/Exploit/blob/master/Wget/wget-exploit.py" %}

How this script works is through exploiting the method of which `wget` interacts with an FTP server to download files. When `wget` sends a request to a website like `http://test.com/file.txt`, and the server responds with a **redirect** to `ftp://anothertest.com/anotherfile.txt`, `wget` will go get `anotherfile.txt` and save it as `anotherfile.txt`. This exploit can be used to tamper with the cronjobs that are running on the server, and we can use this to gain a reverse shell as the root user.

First, we would need to create a `.wgetrc` file:

```
post_file = /etc/shadow
output_document = /etc/cron.d/malicious-cron
```

Then, we can replace the command used in the script to a cronjob reverse shell by root.

<figure><img src="../../../.gitbook/assets/image (1283).png" alt=""><figcaption></figcaption></figure>

Then, we would need to set up a FTP server on our machine with these files using `python3`.

<figure><img src="../../../.gitbook/assets/image (1825).png" alt=""><figcaption></figcaption></figure>

Then, we can attempt to test run the exploit and see that it returns a `socket.error`.

<figure><img src="../../../.gitbook/assets/image (3616).png" alt=""><figcaption></figcaption></figure>

Permission denied was an interesting error to get, as the script doesn't do anything out of the ordinary. Perhaps I was being blocked as I needed to access port 21, which typically requires superuser permissions.

We can use `authbind` to bypass this.

<figure><img src="../../../.gitbook/assets/image (3695).png" alt=""><figcaption></figcaption></figure>

Afterwards, the exploit should work by first extracting the `/etc/shadow` file (as specified in the `.wgetrc` file we made earlier, although this can be any file).

<figure><img src="../../../.gitbook/assets/image (2689).png" alt=""><figcaption></figcaption></figure>

Afterwards, we would get a reverse shell on a listener port.

<figure><img src="../../../.gitbook/assets/image (3341).png" alt=""><figcaption></figcaption></figure>
