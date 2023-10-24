---
description: Full of rabbit holes and garbage enumeration. I'll be skipping them.
---

# FriendZone

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

Lots of ports open.

### SMB + Web RCE

We can enumerate the SMB shares to find that we have write permissions over one of them.

<figure><img src="../../../.gitbook/assets/image (2012).png" alt=""><figcaption></figcaption></figure>

This folder contains nothing, but the fact that we have write access indicates that we should probably be adding something to it. We can also find some credentials in the other share.&#x20;

<figure><img src="../../../.gitbook/assets/image (676).png" alt=""><figcaption></figcaption></figure>

&#x20;Now, DNS is open, so we can expect to have loads of sub-domains. This machine has so many and it's rather painful to exploit. So I'll cut to the chase, we have to visit `administrator1.friendzone.red` that has a login page for us:

<figure><img src="../../../.gitbook/assets/image (3660).png" alt=""><figcaption></figcaption></figure>

We can login using the credentials we found earlier in the SMB share. The page then tells us to visit `dashboard.php`, which is a Smart Photo Script.

<figure><img src="../../../.gitbook/assets/image (3510).png" alt=""><figcaption></figcaption></figure>

The `pagename` parameter is vulnerable to LFI, and since this is a PHP application, we can place a PHP reverse shell file somewhere and execute it using this page. That's where the share that we can write to comes in.

<figure><img src="../../../.gitbook/assets/image (799).png" alt=""><figcaption></figcaption></figure>

Then we can just simply access it by visiting this:

```
http://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/rev,
```

This works because the `pagename` paramter automatically truncates the `.php` extension. The original page included a timestamp at the bottom that is being dynamically generated.

<figure><img src="../../../.gitbook/assets/image (4011).png" alt=""><figcaption></figcaption></figure>

This points towards to some script being used in the backend, and thus we can replace that with our own malicious PHP script to gain a shell.

<figure><img src="../../../.gitbook/assets/image (736).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SQL Credentials

As `www-data`, we have limited access over everything. The first place to look is within the `/var/www` file which can contain some credentials.

<figure><img src="../../../.gitbook/assets/image (1113).png" alt=""><figcaption></figcaption></figure>

We can use this to `su friend`.

<figure><img src="../../../.gitbook/assets/image (2387).png" alt=""><figcaption></figcaption></figure>

### Python OS Tampering

When we run `pspy64`, we can see that `root` is runnin some scripts in the background:

<figure><img src="../../../.gitbook/assets/image (2427).png" alt=""><figcaption></figcaption></figure>

When we read this script, we can see that it contains some random code that we can't really exploit because we cannot edit it:

<figure><img src="../../../.gitbook/assets/image (3319).png" alt=""><figcaption></figcaption></figure>

We can see that `import os` is used, and any external modules could be exploitable. Conveniently, the machine let's us have write permission to `os.py`.

<figure><img src="../../../.gitbook/assets/image (2490).png" alt=""><figcaption></figcaption></figure>

Then, we just need to append a Python reverse shell to this:

<figure><img src="../../../.gitbook/assets/image (868).png" alt=""><figcaption></figcaption></figure>

After opening a listener port and waiting, we would catch a root shell.

<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>
