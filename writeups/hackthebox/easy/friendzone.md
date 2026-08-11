---
description: Full of rabbit holes and garbage enumeration. I'll be skipping them.
---

# FriendZone

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/friendzone-2.png)

Lots of ports open.

### SMB + Web RCE

We can enumerate the SMB shares to find that we have write permissions over one of them.

![](../../../.gitbook/assets/friendzone-3.png)

This folder contains nothing, but the fact that we have write access indicates that we should probably be adding something to it. We can also find some credentials in the other share.

![](../../../.gitbook/assets/friendzone-11.png)

Now, DNS is open, so we can expect to have loads of sub-domains. This machine has so many and it's rather painful to exploit. So I'll cut to the chase, we have to visit `administrator1.friendzone.red` that has a login page for us:

![](../../../.gitbook/assets/friendzone-9.png)

We can login using the credentials we found earlier in the SMB share. The page then tells us to visit `dashboard.php`, which is a Smart Photo Script.

![](../../../.gitbook/assets/friendzone-8.png)

The `pagename` parameter is vulnerable to LFI, and since this is a PHP application, we can place a PHP reverse shell file somewhere and execute it using this page. That's where the share that we can write to comes in.

![](../../../.gitbook/assets/friendzone-13.png)

Then we can just simply access it by visiting this:

```
http://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/rev,
```

This works because the `pagename` paramter automatically truncates the `.php` extension. The original page included a timestamp at the bottom that is being dynamically generated.

![](../../../.gitbook/assets/friendzone-10.png)

This points towards to some script being used in the backend, and thus we can replace that with our own malicious PHP script to gain a shell.

![](../../../.gitbook/assets/friendzone-12.png)

## Privilege Escalation

### SQL Credentials

As `www-data`, we have limited access over everything. The first place to look is within the `/var/www` file which can contain some credentials.

![](../../../.gitbook/assets/friendzone-1.png)

We can use this to `su friend`.

![](../../../.gitbook/assets/friendzone-4.png)

### Python OS Tampering

When we run `pspy64`, we can see that `root` is runnin some scripts in the background:

![](../../../.gitbook/assets/friendzone-5.png)

When we read this script, we can see that it contains some random code that we can't really exploit because we cannot edit it:

![](../../../.gitbook/assets/friendzone-7.png)

We can see that `import os` is used, and any external modules could be exploitable. Conveniently, the machine let's us have write permission to `os.py`.

![](../../../.gitbook/assets/friendzone-6.png)

Then, we just need to append a Python reverse shell to this:

![](../../../.gitbook/assets/friendzone-14.png)

After opening a listener port and waiting, we would catch a root shell.

![](../../../.gitbook/assets/friendzone-15.png)
