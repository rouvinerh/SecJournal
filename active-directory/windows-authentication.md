---
description: >-
  Credits to ATTL4S for helping me understand this, and I also used some of his
  images.
---

# Windows Authentication

Windows authentication is not as straightforward, and it's made a little more complex thanks to Active Directory and having multiple machines use the same set of credentials. Understanding how Windows authenticates users is critical to allowing us to move laterally in a domain.&#x20;

## Types of Authentication

There are different methods of which a user can authenticate to a Windows machine that may or may not be connected to a domain.

### Local&#x20;

Local users are only present in one **specific standalone system**. Obviously, my user isn't present in my friend's laptop, and it is only present in my laptop. Likewise, `laptop1\user` and `laptop2\user` are totally different users.&#x20;

The local users have their records and passwords stored in the **Security Account Manager (SAM) database**. Windows would use these records to verify passwords when trying to authenticate to a system. This is similar to how `/etc/passwd` works in checking users:

1. User attempts to login with `user:Password@123`.
2. Laptop checks SAM for whether `user` exists and if `Password@123` is valid.
3. If yes, grant access. If no, deny.&#x20;

### Domain&#x20;

Domain users are only present in **one specific domain**. For example, `acme\user123` is not present in `acme2\user123`. However, **all domain-joined devices** know how to handle authentication. This means that, by default, **any domain user can login to any domain computer** provided they have physical access to it.&#x20;

Domain joined devices delegate the authentication to the DC, and all of these records are stored within the NT Directory Service (NTDS) database. The DC uses the NTDS records to authenticate users.&#x20;

1. User attempts to login with `acme\user:Password@123` on `WKSTN`.&#x20;
2. `WKSTN` delegates the authentication to the `DC`.
3. `DC` checks NTDS to verify that the user exists and password is correct,
4. `DC` verifies user and sends a thumbs up to `WKSTN`.&#x20;
5. `WKSTN` grants access.

### Remote&#x20;

Remote authentications require privileges to do (for example, being part of the Remote Management Group allows users to have remote Powershell sessions). When moving laterally, **this is the main thing we care about**.&#x20;

## Windows Authentication

### Terms

Some terms we need to know before discussing how the authentication works:

#### Auth Packages

Authentication Packages (APs) authenticate users by analysing their **logon data via Security Support Providers (SSP)**. Different APs provide support for different logon processes, and they are typically `.dll` files that are loaded and used by **Local Security Authority (LSA)**.&#x20;

Some examples of APs are:

* Kerberos
* NTLM Hashes

When we try to login to a website, the website is probably using some kind of backend database that is verifying our credentials. APs provide the logic needed for Windows to act as **both of these** using the same machine.&#x20;

#### LSA

As mentioned earlier, LSA allows Windows to act as both the client and authentication server at the same time.

How it works is illustrated in this diagram here (taken from ATTL4S):

<figure><img src="../.gitbook/assets/image (3929).png" alt=""><figcaption></figcaption></figure>

#### SSP

Microsoft provides an Interface for the SSPs (SSPI) to integrate applications with this authentication system.&#x20;

<figure><img src="../.gitbook/assets/image (2131).png" alt=""><figcaption></figcaption></figure>

There are 4 major categories for the functions provided:

1. Package Management --> Handles packages
2. Credential Management --> Handles credentials of principals
3. Context Management --> Creates security context
4. Message Support --> Ensures message **integrity and privacy** during message exchanges.

### Authentication

When someone successfully authenticates to the WIndows message, the AP does 2 things:

1. Create a new logon session
2. Provides security information about the authenticated user to the LSA

The LSA then creates an access token **representing the user's local security context** on the system. This security context would contain information like:

* User SID
* Logon session SID
* Integrity
* Groups
* Other user information

This security context is used to create an access token, which is the thing required to create the new logon session.&#x20;

### Sessions

There are 2 main types of sessions that are created:

1. Interactive --> Credentials given
2. Non-interactive --> Credentials not given

#### Interactive

Interactive sessions are what happens when we login normally through our login page. The user credentials are cached within the memory of the LSA process, called the Local Security Authority Subsystem Service (LSASS). In specific, it is cached in `lsass.exe`. Cached credentials allow for Windows to provide for a Single Sign-On (SSO) service to users.&#x20;

<figure><img src="../.gitbook/assets/image (3972).png" alt=""><figcaption></figcaption></figure>

#### Non-Interactive

These are sessions that leverage the cached credentials on behalf of a user. When we use the SSO service to logon to the same or another device, this is actually a non-interactive session. **Interactive sessions need to happen first for credentials to be cached**.&#x20;

This leverages the use of the SSPI to work.

<figure><img src="../.gitbook/assets/image (2769).png" alt=""><figcaption></figcaption></figure>

For example, a non-interactive session can grant us access to the file system of another device and do `ls \\dc\c$` using cached credentials.&#x20;

After a user successfully authenticates, a new **logon session** is created regardless of what type of authentication is used. The cached credentials in the AP are tied to logon sessions. Logon sessions are not limited to the 2 types listed above:

<figure><img src="../.gitbook/assets/image (3075).png" alt=""><figcaption></figcaption></figure>

We can verify a logon session with `Get-LogonSession` from Powerview.

### Access Tokens

The information that is returned to LSA after creating the logon session is used to create an access token. An access token is a protected object that contains the **local security context** of an authenticated user. The security context is defined as the **privileges and permissions a user has on a specific workstation and across the network.**&#x20;

<figure><img src="../.gitbook/assets/image (1085).png" alt=""><figcaption></figcaption></figure>

Every single logon session is identifiable by a 64-bit locally unique identifier (LUID), otherwise known as the logon ID. This access token contains an Authentication ID (AuthID) that identifies the logon session via the LUID.

<figure><img src="../.gitbook/assets/image (299).png" alt=""><figcaption></figcaption></figure>

The access token caches a number of attributes that determine its security context such as the user SID, group memberships, privileges and logon ID that references the origin logon session. In the above image, we can see that the Integrity is set to Medium. But what if we use the 'Run as Administrator' option and run `cmd.exe`?&#x20;

This is where multiple security contexts come in. A user can have more than 1 context, and using the 'Run as Administrator' option simply spawns a **high integrity** process via the User Account Control (UAC). As such, Windows allows users to have different access tokens and logon sessions **in the same system**.&#x20;

These access tokens serve as an access check for Windows. For instance, when a thread or process attempts to read a high security object (like `root.txt`), it needs 3 pieces of information:

1. Who is requesting access?
2. What do they want to do (read, write or execute)?
3. Who can access this object?

Windows will first check the token associated with the calling thread and look at the authorization attributes cached. Then, it looks at the access requested by the thread. Lastly, Windows retrieves the security descriptor for the target object in the form of a DACL specifying what users have access to the object and what type of access is granted.&#x20;

If the access token matches what is required, then access is granted, else it is not.&#x20;

There are 2 types of tokens:

1. Primary (process tokens) --> Every process has aprimary token, and when a new process is created, the default action is to inherit the primary token of the parent process.
2. Impersonation (thread tokens) --> Enable a thread to run with a different security context (and hence token).

### Impersonation + Abuse

The point of impersonation is to allow for one process to spawn different threads that have different security contexts.&#x20;

One use case is the listing of shares via remote authentication. If a user `user1` has access to the web shares of `DB`, then credentials for `user1` is first retrieved and verified. Then, an access token with the security context of `user1` is created. The `chrome.exe` instance can spawn a thread and place a copy of the access token into that new thread. This thread can now act on behalf of `user1` and any subsequent access to files or resources are determined by pre-set ACLs.

There are different types of impersonation levels:

<figure><img src="../.gitbook/assets/image (3241).png" alt=""><figcaption></figcaption></figure>

Creating a security context requires credentials, while hijacking a security context (via stealing tokens) requires privileges.&#x20;

User impersonation is the thing that let's us move laterally!

## Lateral Movement

### Token-Based

Windows API allows us to manipulate access tokens, such as duplicating it, or spawning a new process. The level of manipulation depends on our privileges on the system:

* As a local admin or SYSTEM user, we can manipulate all tokens in the system
* As a service account, we can make use of Hot Potato or PrintSpoofer.&#x20;
* As a normal user, we can only manipulate our own token.

There are 2 common ways of which token exploits happen:

1. Token Impersonation --> Duplicate target token and use it to spawn a new process (such as Cobalt Strike's / Meterpreter's `steal_token` command).&#x20;
2. Process Injection --> Inject payload (reverse shell shel code) into the process where the token we want is at (Meterpreter's `migrate` function allows us to run our shell in the `mmc.exe` of another user).&#x20;

### RunAs.exe

`runas.exe` is a binary that allows us to create processes using alternate credentials. When running `runas.exe`, it would ask for credentials, which are verified by the LSA in a similar process to how Interactive Sessions are created.&#x20;

<figure><img src="../.gitbook/assets/image (865).png" alt=""><figcaption></figcaption></figure>

If we attempt to use credentials from a user that is not known by the system, then it would just fail. This is because starting a process on the local system as an unknown user obviously doesn't work. When we run `runas.exe` and give the correct credentials, then it spawns a **local level process.**&#x20;

This is where the `/netonly` flag comes in. This flag indicates that the credentials given are for **remote access only**. Thus, they are not verified by the LSA, and spawn a **network level process** with the identity of the user given.&#x20;

Here's how it works:

<figure><img src="../.gitbook/assets/image (4063).png" alt=""><figcaption></figcaption></figure>

This reason is what leads to tickets and NTLM hashes being cached on the system. How `runas.exe` works is actually using the Win32 API **CreateProcessWithLogon** function, which is in charge of the creation of new processes with the new security context.&#x20;

The `/netonly` flag uses the **LOGON\_NETCREDENTIALS\_ONLY** logon option, which creates and uses a new logon session, but using the original token.&#x20;

<figure><img src="../.gitbook/assets/image (1346).png" alt=""><figcaption></figcaption></figure>

In most tools like Metasploit and Cobalt Strike, they have their own version of `runas`. This provides some additional functionality:

1. Execute payload directly with wanted security context.
2. Create an arbitrary process and steal its token.
3. Create an arbitary process and inject payloads.&#x20;

The **CreateProcessWithLogon** function uses another function called **LogonUser**, and this fnction allows us to create new logon sessions and tokens **without creating a new process**. We can choose between different logon approaches. This is what Cobalt Strike's `make_token` function uses to create a new token using passwords.&#x20;

As mentioned earlier, it is trivial to use a high integrity administrative context to manipulate tokens since we can basically do everything with it. However, the same cannot be done using a medium integrity user context:

* Only can play with own processes (steal tokens and process injection)
* Impersonating tokens in current process if we can access those
* Cannot create new token since that requires credentials as well.&#x20;

In short, we cannot do much without an administrator shell!&#x20;

### Pass The Hash

If we somehow retrieve a hash of a user, we cannot use Win32 APIs to do anything with them. Windows does not provide functionality to authenticate with users via NT hashes. As such, there are 2 broad categories of what we can do:

1. Use LSA
2. Don't use LSA

#### LSA Way

This method would involve injection into `lsass.exe`, which can be quite risky.&#x20;

This is done using the `mimikatz.exe sekurlsa::pth` function. This allows us to create a new process using an NT hash rather than a password, which basically requires administrative privileges in the form of `SeDebugPrivilege`. This is how it works:

1. Create new process with CreateProcessWithLogon via net credentials only.
2. Identify the new session created by extracting from the access token belonging to the new process.
3. Write credential material into the target logon session, which requires debugging privileges.&#x20;

Basically, injecting credentials into the logon session.&#x20;

<figure><img src="../.gitbook/assets/image (2935).png" alt=""><figcaption></figcaption></figure>

A similar thing happens when we use the Overpass The Hash exploit to request for tickets:

<figure><img src="../.gitbook/assets/image (286).png" alt=""><figcaption></figcaption></figure>

#### Non-LSA Way

This approach involves specifying credentials to external tools without playing around with Windows components. For example, `Invoke-the-hash` is a cmdlet that can be used to do this. The Impacket suite of tools can be used for this via `wmiexec.py`.&#x20;

Kerberos can also be used, and this involves tools being used to generate Kerberos traffic to obtain TGTs or STs. Tools like `Rubeus.exe` or scripts from Impacket can be used for this.&#x20;

```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
Rubeus.exe asktgt /user:user123 /domain:acme.local /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /nowrap /ptt
```

These tickets retrieved can also be passed along to generate new processes.&#x20;

### Pass The Ticket

Windows provides functionality for Kerberos tickets, and we can import TGTs or STs into existing logon sessions. Importing a ticket into our current session does not require privileges, but doing so for another session does.

#### LSA Way

If we have the ticket from another user, we can importing the ticket into an attacker-controlled logon session and act on behalf of another user in the network.&#x20;

<figure><img src="../.gitbook/assets/image (3023).png" alt=""><figcaption></figcaption></figure>

The cool thing about this is the the Kerberos LSA API **does not require administrative privileges to interact with**. How `mimikatz.exe` and `Rubeus.exe` do this is via the **LsaCallAuthenticationPackage** function. This function enables apps to talk to Windows APs, and is done through messages which have a specific structure.&#x20;

In the case of Pass The Ticket, this is done using **KerbSubmitTicketMessage**. There are 2 methods of passing tickets via LSA:

1. Import ticket into another session, then steal tokens or do process injection via `Rubeus.exe ptt` function.&#x20;
2. Import ticket into current session. (prevents overwriting the original TGT, for eg. `make_token`).&#x20;

#### Non-LSA Way

We can do the same thing with MSF and Impacket tools. Impacket tools generally support the `-k` option, which would use the tickets exported in Kali (`export KRB5CCNAME`) to make requests on behalf of the user. Alternatively, MSF's `run` option still works.&#x20;

### SSPI Moving

We can also move laterally to **other machines using a user's security context**. Windows provides loads of protocols to allow remote execution. The simplest example is using `psexec`. With the appropriate security context and network visibility, we can create a remote service using the SCM remote procotol.

Using the `sc.exe` native tool, we can use our new security context to create services on the remote device to execute payloads like beacons. The `sc_start.x64.o` file can be used to start a service remotely.&#x20;

<figure><img src="../.gitbook/assets/image (670).png" alt=""><figcaption></figcaption></figure>

This is the basics of how Windows authenticates users!&#x20;
