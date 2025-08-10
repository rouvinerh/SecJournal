# ACLs and GPOs

Access Control Lists (ACL) are basically a list of permissions that one object has over other objects within the domain.

Every single object in an AD network has a set of permissions and control over objects. For instance, some users are part of the IT Operators group, and hence can add new users to the domain or access the IT Database for the network.&#x20;

These are designed to supprot more than one client system within the workgroup.

Some of the AD object permissions that we as attackers are interested in are:

* GenericAll
  * Full rights to an object
  * Can add users, or reset users' password within that object
* GenericWrite
  * Able to update the object's attributes
  * E.g. change the login script for members in the group
* WriteOwner
  * Change the object's owner&#x20;
  * Attackers can use this to change the ownership of the object to a compromised user to take full control of that object.
* WriteDACL
  * Modify the object's ACLs and accessibility for that one object
* AllExtendedRights
  * Ability to add user to the object and reset password of whoever is in the object
* ForceChangePassword
  * Can force a change of password for a user through RPC
* Self
  * Ability to add oneself to a group
* DCSync
  * This implies that we have further permissions **under the DC category.**
  * A compromised user with DCSync permission enabled allows attackers to do DCSync attacks, and basically be able to leak credentials for the entire domain.

Apart from ACLs, there are objects within AD networks called **Group Policy Objects.**&#x20;

What GPOs are is a feature of Windows that controls the working environment of user accounts and computer accounts. They provide centralized management and configuration of OS, applications and user settings in the AD environment.&#x20;

## Enumeration

### Powershell Scripts

Generally, we can view these ACLs either using Powershell manually, or using a tool like Bloodhound that would map it out for us.

Here are some PowerView commands that do this for us:

{% code overflow="wrap" %}
```powershell
Get-ObjectAcl -SamAccountName <USERNAME> -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "<persmission>"} 
# view user ACLs and filter results to show certain permissions

Get-NetGroup "domain admins" -FullData
# view groups to see if there are weak permissions
```
{% endcode %}

This above above would basically show us all the permissions that the current user has. However, it does not list out the permissions of whatever group a user is in.

<figure><img src="../../.gitbook/assets/image (466).png" alt=""><figcaption><p><em>PowerView ACL Enumeration</em></p></figcaption></figure>

There are many other commands and tools that can be used for enumeration of ACLs, most of which are accessed through PowerView.

### Bloodhound

As mentioned earlier, Bloodhound can be used to easily view all of these. However, it must be noted that Bloodhound would generate **significantly more logs and hence is louder.** Furthermore, the collectors of Bloodhound may not be useful because domains are able to block the execution of certain .exe or .ps1 files.

<figure><img src="../../.gitbook/assets/image (3953).png" alt=""><figcaption></figcaption></figure>

Above is an example of how Bloodhound can map out and show the ACLs for each of the objects. For this case, we can see how the **support** user (which has been compromised) is part of the Shared Support Accounts group, which has GenericAll privileges over the Domain Controller.

### GPOs

As mentioned above, some users may be authorized to manage GPOs and change their permissions. Bloodhound sometimes does not cover these, and we would need to manually enumerate them using PowerView.

{% code overflow="wrap" %}
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
# find GPOs that user can control

Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
# find permissions of speicifc GPO name

Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
# find policies applied to a computer

Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
# find OUs with domain policy added
```
{% endcode %}

### DCSync

The DCSync permission would imply we have these permissions:

* DS-Replication-Get-Changes
* Replicating Directory Changes All
* Replicating Directory Changes in Filtered set

Having these 3 enabled on a user would allow for us to leak credentials basically.

To check, PowerView:

{% code overflow="wrap" %}
```powershell
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```
{% endcode %}

## Sources

{% embed url="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#abusing-the-gpo-permissions" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces" %}
