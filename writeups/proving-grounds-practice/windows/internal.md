# Internal

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.233.40 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 17:39 +08
Warning: 192.168.233.40 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.233.40
Host is up (0.17s latency).
Not shown: 65465 closed tcp ports (conn-refused), 57 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
```

Lots of ports open. The version scan (which I normally leave out because it contains a lot of irrelevant information) actually had something useful this time:

```
$ nmap -p 53,135,139,445,3389,5357 -sV 192.168.233.40
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 17:40 +08
Nmap scan report for 192.168.233.40
Host is up (0.17s latency).

PORT     STATE SERVICE            VERSION
53/tcp   open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ssl/ms-wbt-server?
5357/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2
```

The first thing we notice is how old the OS of this machine is.

### SMB RCE

The SMB services might be vulnerable to stuff like MS17-010 or other exploits because of how old it is, so I ran an `nmap` scan to enumerate that:

```
$ nmap --script smb-vuln* -p 139,445 192.168.233.40    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 17:43 +08
Nmap scan report for 192.168.233.40
Host is up (0.17s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
```

This is vulnerable to CVE-2009-3103. I ran the Metasploit module to exploit this (because I was honestly lazy since I'm re-doing the machines for the writeups) after resetting the machine since the `nmap` scan apparently crashed it.&#x20;

This worked in giving us a SYSTEM shell:

<figure><img src="../../../.gitbook/assets/image (3940).png" alt=""><figcaption></figcaption></figure>

Rooted!
