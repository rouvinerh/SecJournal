# Lightweight

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2813).png" alt=""><figcaption></figcaption></figure>

### Website Hints

On port 80, we can find some interesting information.

<figure><img src="../../../.gitbook/assets/image (1806).png" alt=""><figcaption></figcaption></figure>

The user page tells us how to use SSH to get into the machine.

<figure><img src="../../../.gitbook/assets/image (4038).png" alt=""><figcaption></figcaption></figure>

So our IP address is our username and password for this machine. Interesting.

### LDAP Scan

I found it rather interesting that there was a LDAP service running on this Linux machine, and wanted to enumerate this within the machine as other scans weren't giving me much to work with.

First, we can SSH using our IP address as the username and password. We can view other users on the machine.

<figure><img src="../../../.gitbook/assets/image (3680).png" alt=""><figcaption></figcaption></figure>

The most interesting part was the within the `/etc/passwd` file, a completely new user was being created for each IP address.&#x20;

### Sniffing

I was stuck here for a long time because I could not find anything of interest on the machine that we could access.&#x20;

I found it really odd that LDAP was listening on the machine and I did not know what it was doing. As a last resort, I sniffed the traffic of LDAP using `tcpdump` on port 389. Surprisingly, I found some credentials in plaintext.

<figure><img src="../../../.gitbook/assets/image (3403).png" alt=""><figcaption></figcaption></figure>

We can `su` as `ldapuser2` using this plaintext credential (it's the hash).

<figure><img src="../../../.gitbook/assets/image (652).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### backup.7z

Within the new user's directory, we can find a backup file.

<figure><img src="../../../.gitbook/assets/image (790).png" alt=""><figcaption></figcaption></figure>

It was password encrypted, but that's no issue for `john`.

<figure><img src="../../../.gitbook/assets/image (1845).png" alt=""><figcaption></figcaption></figure>

Then, we can extract the files using `7z e`. Within the `status.php` file, we find another set of credentials.

<figure><img src="../../../.gitbook/assets/image (560).png" alt=""><figcaption></figcaption></figure>

We can now access `ldapuser1`.

### OpenSSL Cap

Within the user directory, we can find that there some binaries present.

<figure><img src="../../../.gitbook/assets/image (935).png" alt=""><figcaption></figcaption></figure>

The `openssl` and `tcpdump` binaries are identical to the normal ones, but checking the permissions reveals something different.

```
[ldapuser1@lightweight ~]$ getcap tcpdump /usr/sbin/tcpdump
tcpdump = cap_net_admin,cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
[ldapuser1@lightweight ~]$ getcap openssl /usr/bin/openssl 
openssl =ep
```

`openssl` in this folder has the `=ep` capability, which means it has **all the capabilities present**. This essentially means we can read and edit files the same as the `root` user would.

We can use this to capture the root flag:

<figure><img src="../../../.gitbook/assets/image (2819).png" alt=""><figcaption></figcaption></figure>

But that's not good enough for OSCP. So, I decided to overwrite the `root` user's hash in `/etc/shadow`. This allows me to `su` as `root` using a password of my choosing.

First, we need to generate a new hash.

<figure><img src="../../../.gitbook/assets/image (3143).png" alt=""><figcaption></figcaption></figure>

Then, we can get a copy the `/etc/shadow` file into the `ldapuser1` user directory.

<figure><img src="../../../.gitbook/assets/image (1499).png" alt=""><figcaption></figcaption></figure>

Then we can replace the root hash with our own.

<figure><img src="../../../.gitbook/assets/image (1058).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can overwrite the `/etc/shadow` file with the edited version, then `su` to get a root shell.

<figure><img src="../../../.gitbook/assets/image (2881).png" alt=""><figcaption></figcaption></figure>
