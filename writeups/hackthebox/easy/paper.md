# Paper

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1371).png" alt=""><figcaption></figcaption></figure>

We can append `paper.htb` to our `/etc/hosts` file, as per standard HTB stuff. The web pages don't reveal much and have the default pages loaded.

When proxying requests through Burp, we can see this custom `X-Backend-Server` header.

<figure><img src="../../../.gitbook/assets/image (4061).png" alt=""><figcaption></figcaption></figure>

We can add the `office.paper` header to our hosts file and enumerate that.

### Office Paper

The new domain was some kind of company website.

<figure><img src="../../../.gitbook/assets/image (3189).png" alt=""><figcaption></figcaption></figure>

At the very bottom, it says this was **Powered By Wordpress**. When looking at some of the recent posts, we can see this one that highlights there are secret posts.

<figure><img src="../../../.gitbook/assets/image (373).png" alt=""><figcaption></figcaption></figure>

Because there were hints to view a private post of some sort, we can try appending `?static=1` to the URL and see what we get.

{% embed url="https://www.exploit-db.com/exploits/47690" %}

<figure><img src="../../../.gitbook/assets/image (3818).png" alt=""><figcaption></figcaption></figure>

We now have a new URL to head to.

### Recyclops

Within this new URL, we can register as a new user and login to find a Rocket.Chat instance.

<figure><img src="../../../.gitbook/assets/image (184).png" alt=""><figcaption></figcaption></figure>

Within the chats tab, we can see that there is a `recyclops` bot that has some documentation.

<figure><img src="../../../.gitbook/assets/image (1408).png" alt=""><figcaption></figcaption></figure>

I tested it out and it seems to execute code on the machine remotely.

<figure><img src="../../../.gitbook/assets/image (3770).png" alt=""><figcaption></figcaption></figure>

Basic directory traversal works on this machine due to a lack of input validation for the directory entered.

<figure><img src="../../../.gitbook/assets/image (856).png" alt=""><figcaption></figcaption></figure>

The user is `dwight`, and we can see that within this directory, there is a `hubot` directory. Hubot is an open source chat robot that could be the one used for this user. I could not read the `.ssh` files, so this was the next best thing.

<figure><img src="../../../.gitbook/assets/image (2625).png" alt=""><figcaption></figcaption></figure>

We can see that within the `hubot/` directory, there's a `.env` file. This could contain some interesting content.

<figure><img src="../../../.gitbook/assets/image (436).png" alt=""><figcaption></figcaption></figure>

We can test this password with the user `dwight` and attempt to SSH in, which works!

<figure><img src="../../../.gitbook/assets/image (2009).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Running a LinPEAS, we find that CVE-2021-3560 works on this machine because of an outdated `sudo` version.

<figure><img src="../../../.gitbook/assets/image (274).png" alt=""><figcaption></figcaption></figure>

CVE-2021-3560 is an authentication bypass on polkit, which allows for users to carry out privileged actions using DBus. This repo here works on this machine to get root:

{% embed url="https://github.com/Almorabea/Polkit-exploit" %}

<figure><img src="../../../.gitbook/assets/image (2746).png" alt=""><figcaption></figcaption></figure>
