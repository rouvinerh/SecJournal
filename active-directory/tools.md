# Tools

Here are a list of tools that we need to know and use when attacking an AD network. There are loads of alternatives and other tools out there, but normally these few here get the job done:

* Powershell scripts
* Impacket suite of tools
* Evil-winrm
* Rubeus
* Mimikatz
* Bloodhound

Others, such as gMSAdumper.py and their use cases is on you to learn!

## Powershell

Powershell scripts are used to make enumeration and exploitation easy. Powershell commands to add users, and enumerate the domain are long, complicated and hard to use.

### PowerView

By far my favourite, because it makes enumeration easy. In essence, this circumvents the need for hard enumeration and allows us to view the domain objects clearly, and also exploit where needed.&#x20;

### Powermad

Sort of like PowerView, but easier in some aspects to use. Some of the commands used here, such as adding users, is more simple than that of PowerView.&#x20;

### Sharphound

Just a powershell implementation of a bloodhound collector in case the .exe cannot run.

### Mimikatz.exe

Just a powershell implementation of mimikatz in case the .exe cannot run.

### Importing Modules

Generally, the modules can be imported like so.

```powershell
. .\Powerview.ps1

. .\Sharphound.ps1
Invoke-Sharphound <flags>
```

{% embed url="https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview" %}
_Basic Commands for PowerView_
{% endembed %}

{% embed url="https://github.com/PowerShellMafia/PowerSploit" %}
Repo with everything PowerShell you need
{% endembed %}

## Impacket

A collection of Python classes for working with certain network protocols. The suite of tools from impacket cover a huge range of uses, from Kerberoasting to dumping all credentials.

In my experience, if you're trying to find a script for an AD attack, impacket probably has it somewhere.

<figure><img src="../.gitbook/assets/image (2578).png" alt=""><figcaption><p><em>Kerberoasting using Impacket-GetUserSPN</em></p></figcaption></figure>

{% embed url="https://github.com/SecureAuthCorp/impacket" %}

## Evil-Winrm

Basically, the SSH thing of Windows with loads of easy to use additional commands. Supports file transfer to and fro, as well as passing the hash for authentication. This tool abuses the service typically listening on port 5985.

<figure><img src="../.gitbook/assets/image (2507).png" alt=""><figcaption><p><em>Evil-winrm with Password</em></p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1252).png" alt=""><figcaption><p><em>Evil-winrm with LM Hash</em></p></figcaption></figure>

{% embed url="https://github.com/Hackplayers/evil-winrm" %}

## Rubeus

A C# toolset for raw Kerberos interaction and abuses. Has a wide range of tools and use cases, from impersonating users, forging tickets, extracting tickets, extracting credentials and many, many more. Most abuses from Kerberos can be done via this tool.

{% embed url="https://github.com/GhostPack/Rubeus" %}

## Mimikatz

Mimikatz is an open-source application used to retrieve Windows credentials from the registry, interact with authentication tokens, impersonating users using existing tokens, storing and forging tickets, get password data and so on.

There are loads of implementations of Mimikatz and the use cases for this application are wide. However, **it should be noted that most of the applications do not work unless we have some sort of superuser**. Trying to dump out credentials from the Windows registry as a non-admin would not work out well.

This tool is mainly useful for when we are trying to pillage the domain for more information, or perhaps move laterally to another computer within the domain through passing the hash or password re-use.

There is also a Powershell implementation of this as well witin Powersploit.

<figure><img src="../.gitbook/assets/image (1801).png" alt=""><figcaption><p><em>Taken from</em> <a href="https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/"><em>https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/</em></a></p></figcaption></figure>

## Bloodhound

This is an amazing tool that does enumeration of the domain **automatically.** This would basically map out all the possible objects and ACLs, then draw links between each object and present this information using graphs

There are 2 parts to Bloodhound, one is the **collector** and another is the **graphing application.**

The collectors are used to extract the information about the domain in .json format, and the graphing application is where we can upload the data and map out the objects.

In order to use this, we would need to have a **neo4j database on our linux device.**

### Setting up

```bash
sudo apt install bloodhound

sudo apt install neo4j

sudo neo4j start
#starts neo4j, and we can access http://localhost:7474/browser/. 
#then, we need to change the default password of neo4j to something else.

./Bloodhound
```

### Collectors

These require access to a domain account, and are performed on that system itself.

```powershell
./SharpHound.exe --CollectionMethod All

. .\Sharphound.ps1
Invoke-Bloodhound -CollectionMethod All
```

Alternatively, if we have valid credentials but don't have a shell, we can use **bloodhound-python**.

{% code overflow="wrap" %}
```bash
bloodhound-python -u user -p password -ns 10.10.10.10. -d domain.local -c all

proxychains bloodhound-python -u user -p password -ns 10.10.10.10. -d domain.local -c all
#if we are doing pivoting
```
{% endcode %}

Once we have run the ingestor, we would just need to upload the data onto the graphing application.

Here's a use case of the Sharphound.ps1, and the zip file it generates containing all the .json data of the domain.

<figure><img src="../.gitbook/assets/image (1913).png" alt=""><figcaption><p>Using SharpHound.ps1</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (425).png" alt=""><figcaption><p><em>Viewing Files Generated</em></p></figcaption></figure>

### Bloodhound in Action

<figure><img src="../.gitbook/assets/image (1008).png" alt=""><figcaption></figcaption></figure>

Ths is an example of what the graphing application would look like, and we can see how each node (object) is mapped and linked to other objects.&#x20;

For this example, we can see how a group has **WriteDacl** privileges over another part of the domain, and that the user **svc-alfresco** is part of the group, and hence has the same privileges by transitivity.&#x20;

We can find out more information from each line and whether it can be abused by right-clicking on it and using more info.

<figure><img src="../.gitbook/assets/image (2740).png" alt=""><figcaption><p><em>Abuse Info on GenericAll Privilege</em></p></figcaption></figure>

Bloodhound is insanely useful and fast for mapping a domain out, and it even gives clear instructions and information about each abusable privilege.&#x20;
