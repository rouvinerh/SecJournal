---
description: >-
  Active Directory Machine that requires good enumeration techniques to find the
  vulnerabilities.
---

# Flight

## Gaining Access

As usual, we begin with our enumeration process.

<figure><img src="../../../.gitbook/assets/image (3905).png" alt=""><figcaption></figcaption></figure>

Loads of ports open as per a normal AD machine. Nothing about the SMB shares was found.

### Finding Hidden Domain

When viewing the website, we can see the bottom of the page to get a possible domain.

<figure><img src="../../../.gitbook/assets/image (2623).png" alt=""><figcaption></figcaption></figure>

With this, we could fuzz out some hidden vhosts on the machine with gobuster. Turns out there is a `school.flight.htb` present. We can add both of these into our hosts file and proceed to enumerate the school website.

<figure><img src="../../../.gitbook/assets/image (1486).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2895).png" alt=""><figcaption></figcaption></figure>

### Responder Hash

When clicking the about us page, we can see the URL and find that it might contain a LFI or RFI. This is because a .php page that has a ?view parameter has generally always been suspicious in HTB.



<figure><img src="../../../.gitbook/assets/image (961).png" alt=""><figcaption></figcaption></figure>

We can set up a quick Python server and check this URL to find that we can receive a hit from the server.

<figure><img src="../../../.gitbook/assets/image (433).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3673).png" alt=""><figcaption></figcaption></figure>

Since this is a AD machine, perhaps we can get some shares and intercept the response using Responder.

<figure><img src="../../../.gitbook/assets/image (1562).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2003).png" alt=""><figcaption></figcaption></figure>

We can crack this easily using John.

<figure><img src="../../../.gitbook/assets/image (3414).png" alt=""><figcaption></figcaption></figure>

### SMB Shares

With these credentials, we can view the shares that are present on this machine.

<figure><img src="../../../.gitbook/assets/image (1909).png" alt=""><figcaption></figcaption></figure>

The ones to investigate are Users, Web and Shared.&#x20;

#### Users

In users, we can find that there is C.Bum user.

<figure><img src="../../../.gitbook/assets/image (2589).png" alt=""><figcaption></figcaption></figure>

### Desktop.ini

We can't do anything with that directory, though. The rest of the directories contain nothing of interest at all. Web only contains source code for the websites that also have nothing, while Shared was empty.

At this point, I was stuck for quite a while. Went back to enumeration of possible SMB server version vulnerablities. The credentials cannot be used to login as well, so there has to be anotehr set of credentials elsewhere.

I was thinking if it was possible to intercept some kind of reponse to retrieve more credentials, when I remembered about cetain expliots using the Desktop.ini file. What this file does is essentially contain the information regarding the icons used on the desktop, and we seem to be able to download and replace this for this machine.

As such, the next step was to replace this file with our own malicious file to make it query our responder share to intercept another hash.

{% embed url="https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini" %}

Based on that, we can create our own malicious .ini file and replace the one that is in the Shared share.

<figure><img src="../../../.gitbook/assets/image (3910).png" alt=""><figcaption></figcaption></figure>

However, I cannot put this file on the directory using svc\_apache, so we would need to enumerate some other users first.

### Finding Users

Crackmapexec can enumerate users using the credentials we found.

<figure><img src="../../../.gitbook/assets/image (1545).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2459).png" alt=""><figcaption></figcaption></figure>

Then we can gather these users into a file and brute force, checking for any password re-use. We can find that the S.Moon user seems to work.

<figure><img src="../../../.gitbook/assets/image (872).png" alt=""><figcaption></figcaption></figure>

### Retrieving Hash

Now, we can upload our file as S.Moon and proceed to retrieve the hash.

<figure><img src="../../../.gitbook/assets/image (2168).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3653).png" alt=""><figcaption></figcaption></figure>

Cracking, the hash, we get C.Bum's password.

<figure><img src="../../../.gitbook/assets/image (3289).png" alt=""><figcaption></figcaption></figure>

We still cannot evil-winrm in, so we need to find another way. In the meantime, one can capture the flag using the c.bum credentials to access his desktop.

<figure><img src="../../../.gitbook/assets/image (2058).png" alt=""><figcaption></figcaption></figure>

### Gaining Shell

Since we do have another share called Web, perhaps we can upload a simple web shell as C.bum onto it to achieve some form of RCE.

I tried this method using a cmd.php basic web shell.

<figure><img src="../../../.gitbook/assets/image (2199).png" alt=""><figcaption></figcaption></figure>

This works in getting me a shell as svc\_apache.

<figure><img src="../../../.gitbook/assets/image (1958).png" alt=""><figcaption></figcaption></figure>

I guess we can just get a reverse shell as svc\_apache. Use whatever method you'd like, I decided for the lazy nc.exe method.

<figure><img src="../../../.gitbook/assets/image (1141).png" alt=""><figcaption></figcaption></figure>

As this user, because we have credentials for another user, we can use the runas.exe binary to gain RCE as C.Bum and proceed from there.

<figure><img src="../../../.gitbook/assets/image (1674).png" alt=""><figcaption></figcaption></figure>

We would receive a shell as c.bum on whatever port we are on.

<figure><img src="../../../.gitbook/assets/image (1369).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/antonioCoco/RunasCs" %}

## Privilege Escalation

Now that we are c.bum, we can look around this machine.

Within the C:\inetpub directory, there's an interesting folder called development.

<figure><img src="../../../.gitbook/assets/image (2350).png" alt=""><figcaption></figcaption></figure>

This was interesting as it suggested that perhaps there was another port listening on the localhost.  Sure enough, there was a service listening on port 8000 that was not detected by nmap earlier.

<figure><img src="../../../.gitbook/assets/image (2111).png" alt=""><figcaption></figcaption></figure>

When curled, it reveals a webpage tha matches the index.html file in the development server. For now, we can do some port forwarding to access it.

### Port Forwarding

For this machine, I used chisel to tunnel and we can access the website on 127.0.0.1:8000.

<figure><img src="../../../.gitbook/assets/image (1229).png" alt=""><figcaption></figcaption></figure>

When viewing the web service, we can see that there are errors because there is no default configuration for this IIS server.

<figure><img src="../../../.gitbook/assets/image (1287).png" alt=""><figcaption></figcaption></figure>

Since this is an IIS server, we can actually generate a aspx reverse shell using MSFVenom and upload it to that directory to gain another reverse shell.

### ASP Shell

<figure><img src="../../../.gitbook/assets/image (356).png" alt=""><figcaption></figcaption></figure>

Then, upload this to the website through wget and put it within the C:\inetpub\development directory which can be accessed through the chisel server.

<figure><img src="../../../.gitbook/assets/image (956).png" alt=""><figcaption></figcaption></figure>

Afterwards, we would receive a shell as another service account.

<figure><img src="../../../.gitbook/assets/image (881).png" alt=""><figcaption></figcaption></figure>

### JuicyPotato

A quick check on the privileges of this user reveals we have the SeImpersonatePrivilege.

<figure><img src="../../../.gitbook/assets/image (2977).png" alt=""><figcaption></figcaption></figure>

There are no printers on this machine, so we have to go with JuicyPotato to impersonate the administrator and finish this machine. The usage of PrintSpoofer does not work on this machine.

For this machine, I used JuicyPotatoNG, which is sort of a faster version of the default JuicyPotato exploit.

{% embed url="https://github.com/antonioCoco/JuicyPotatoNG" %}

Then, we can easily become the administrator!

<figure><img src="../../../.gitbook/assets/image (2439).png" alt=""><figcaption></figcaption></figure>

This machine was really long, but really interesting as well. Simple exploits that required a bit more enumeration and time then the average.
