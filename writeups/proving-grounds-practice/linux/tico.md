# Tico

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.240.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 12:25 +08
Nmap scan report for 192.168.240.143
Host is up (0.17s latency).
Not shown: 65428 filtered tcp ports (no-response), 101 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
8080/tcp  open  http-proxy
11211/tcp open  memcache
27017/tcp open  mongod
```

### FTP Rabbit Hole

FTP allowed for anonymous access:

```
ftp> ls
229 Entering Extended Passive Mode (|||40076|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 01  2021 pub

ftp> ls
229 Entering Extended Passive Mode (|||40044|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4603 Feb 01  2021 debug.pcap
```

We can view the traffic within this file using `wireshark`. There was only 1 TCP stream to follow, and I didn't quite understand it.

![](<../../../.gitbook/assets/image%20(276).png>)

There was some mention of the MongoDB instance and a few GCC compiler flags, but it doesn't seem to be useful now.

### Markdown Rabbit Hole

Port 80 had a Markdown Editor:

![](<../../../.gitbook/assets/image%20(365).png>)

Again, there was nothing interesting with this. We could try XSS injection or something, but there's no hint that a user is viewing this.

### NodeBB -> Admin Takeover

Port 8080 had a NodeBB instance:

![](<../../../.gitbook/assets/image%20(720).png>)

There are some exploits that are available for NodeBB:

```
$ searchsploit nodebb    
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
NodeBB Forum 1.12.2-1.14.2 - Account Takeover              | multiple/webapps/48875.txt
NodeBB Plugin Emoji 3.2.1 - Arbitrary File Write           | multiple/webapps/49813.py
----------------------------------------------------------- ---------------------------------
```

The first one looks applicable, and it involves an administrator account takeover that we can try. First, we need to register a user. Afterwards, we can head to the password reset page:

![](<../../../.gitbook/assets/image%20(3363).png>)

Intercept this response to see a JSON request being sent:

![](<../../../.gitbook/assets/image%20(3022).png>)

Replace the `uid` value with '1', and then let the requests pass through. We can then login as `admin` with the new password I set.

![](<../../../.gitbook/assets/image%20(3365).png>)

### Arbitrary File Write -> Root

We can access the admin dashboard to see the plugins:

![](<../../../.gitbook/assets/image%20(1897).png>)

This confirms that the Emoji plugin is installed, and we can try the other exploit. The public expoit attempts to write our SSH public key into the `authorized_keys` folder of `root`.

```
$ python3 49813.py
[+] Login successful
[+] Emoji plugin is installed
[+] Successfully uploaded file
```

Afterwards, we can just `ssh` into `root`:

![](<../../../.gitbook/assets/image%20(3360).png>)

Rooted!
