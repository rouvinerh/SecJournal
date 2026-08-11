# Bastion

## Gaining Access

Nmap scan revealed a lot of ports:

![](<../../../.gitbook/assets/image%20(1344).png>)

### Windows Backup

When checking the SMB shares, we fnd that the Backups share does not require credentials to access.

![](<../../../.gitbook/assets/image%20(2119).png>)

When checking the files, we can see that there's a WindowsImageBackup directory within it.

![](<../../../.gitbook/assets/image%20(3576).png>)

Within it, there was a few .vhd files.

![](<../../../.gitbook/assets/image%20(2201).png>)

These file can actually be mounted and they do not requrie credentials at all!

![](<../../../.gitbook/assets/image%20(3737).png>)

From here, because this is a Windows backup, we can directly go to the `C:\Windows\System32\config` file to use the SYSTEM and SAM registry folders and dump the credentials via `samdump2`.

![](<../../../.gitbook/assets/image%20(2345).png>)

Then, this hash is easily cracked using hashcat.

![](<../../../.gitbook/assets/image%20(320).png>)

Afterwards, we can SSH in as the L4mpje user.

## Privilege Escalation

### mRemoteNG

In the user's directory, I enumerated all the directories that I could using `dir /all`.

![](<../../../.gitbook/assets/image%20(553).png>)

Within the `AppData\Roaming` folder, we can find some files related to mRemoteNG.

![](<../../../.gitbook/assets/image%20(3960).png>)

Checking the confCons.xml file, we can find an encrypted password for the Administrator.

![](<../../../.gitbook/assets/image%20(1490).png>)

mRemoteNG passwords can be decrypted using this repository:

{% embed url="https://github.com/haseebT/mRemoteNG-Decrypt" %}

![](<../../../.gitbook/assets/image%20(342).png>)

Then, we can SSH in as the administrator using this password.
