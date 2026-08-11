# Bastion

## Gaining Access

Nmap scan revealed a lot of ports:

![](../../../.gitbook/assets/bastion-1.png)

### Windows Backup

When checking the SMB shares, we fnd that the Backups share does not require credentials to access.

![](../../../.gitbook/assets/bastion-3.png)

When checking the files, we can see that there's a WindowsImageBackup directory within it.

![](../../../.gitbook/assets/bastion-8.png)

Within it, there was a few .vhd files.

![](../../../.gitbook/assets/bastion-4.png)

These file can actually be mounted and they do not requrie credentials at all!

![](../../../.gitbook/assets/bastion-9.png)

From here, because this is a Windows backup, we can directly go to the `C:\Windows\System32\config` file to use the SYSTEM and SAM registry folders and dump the credentials via `samdump2`.

![](../../../.gitbook/assets/bastion-5.png)

Then, this hash is easily cracked using hashcat.

![](../../../.gitbook/assets/bastion-6.png)

Afterwards, we can SSH in as the L4mpje user.

## Privilege Escalation

### mRemoteNG

In the user's directory, I enumerated all the directories that I could using `dir /all`.

![](../../../.gitbook/assets/bastion-11.png)

Within the `AppData\Roaming` folder, we can find some files related to mRemoteNG.

![](../../../.gitbook/assets/bastion-10.png)

Checking the confCons.xml file, we can find an encrypted password for the Administrator.

![](../../../.gitbook/assets/bastion-2.png)

mRemoteNG passwords can be decrypted using this repository:

{% embed url="https://github.com/haseebT/mRemoteNG-Decrypt" %}

![](../../../.gitbook/assets/bastion-7.png)

Then, we can SSH in as the administrator using this password.
