# Lightweight

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(2813).png>)

### Website Hints

On port 80, we can find some interesting information.

![](<../../../.gitbook/assets/image%20(1806).png>)

The user page tells us how to use SSH to get into the machine.

![](<../../../.gitbook/assets/image%20(4038).png>)

So our IP address is our username and password for this machine. Interesting.

### LDAP Scan

I found it rather interesting that there was a LDAP service running on this Linux machine, and wanted to enumerate this within the machine as other scans weren't giving me much to work with.

First, we can SSH using our IP address as the username and password. We can view other users on the machine.

![](<../../../.gitbook/assets/image%20(3680).png>)

The most interesting part was the within the `/etc/passwd` file, a completely new user was being created for each IP address.

### Sniffing

I was stuck here for a long time because I could not find anything of interest on the machine that we could access.

I found it really odd that LDAP was listening on the machine and I did not know what it was doing. As a last resort, I sniffed the traffic of LDAP using `tcpdump` on port 389. Surprisingly, I found some credentials in plaintext.

![](<../../../.gitbook/assets/image%20(3403).png>)

We can `su` as `ldapuser2` using this plaintext credential (it's the hash).

![](<../../../.gitbook/assets/image%20(652).png>)

## Privilege Escalation

### backup.7z

Within the new user's directory, we can find a backup file.

![](<../../../.gitbook/assets/image%20(790).png>)

It was password encrypted, but that's no issue for `john`.

![](<../../../.gitbook/assets/image%20(1845).png>)

Then, we can extract the files using `7z e`. Within the `status.php` file, we find another set of credentials.

![](<../../../.gitbook/assets/image%20(560).png>)

We can now access `ldapuser1`.

### OpenSSL Cap

Within the user directory, we can find that there some binaries present.

![](<../../../.gitbook/assets/image%20(935).png>)

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

![](<../../../.gitbook/assets/image%20(2819).png>)

But that's not good enough for OSCP. So, I decided to overwrite the `root` user's hash in `/etc/shadow`. This allows me to `su` as `root` using a password of my choosing.

First, we need to generate a new hash.

![](<../../../.gitbook/assets/image%20(3143).png>)

Then, we can get a copy the `/etc/shadow` file into the `ldapuser1` user directory.

![](<../../../.gitbook/assets/image%20(1499).png>)

Then we can replace the root hash with our own.

![](<../../../.gitbook/assets/image%20(1058).png>)

Afterwards, we can overwrite the `/etc/shadow` file with the edited version, then `su` to get a root shell.

![](<../../../.gitbook/assets/image%20(2881).png>)
