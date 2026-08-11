# Paper

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(1371).png>)

We can append `paper.htb` to our `/etc/hosts` file, as per standard HTB stuff. The web pages don't reveal much and have the default pages loaded.

When proxying requests through Burp, we can see this custom `X-Backend-Server` header.

![](<../../../.gitbook/assets/image%20(4061).png>)

We can add the `office.paper` header to our hosts file and enumerate that.

### Office Paper

The new domain was some kind of company website.

![](<../../../.gitbook/assets/image%20(3189).png>)

At the very bottom, it says this was **Powered By Wordpress**. When looking at some of the recent posts, we can see this one that highlights there are secret posts.

![](<../../../.gitbook/assets/image%20(373).png>)

Because there were hints to view a private post of some sort, we can try appending `?static=1` to the URL and see what we get.

{% embed url="https://www.exploit-db.com/exploits/47690" %}

![](<../../../.gitbook/assets/image%20(3818).png>)

We now have a new URL to head to.

### Recyclops

Within this new URL, we can register as a new user and login to find a Rocket.Chat instance.

![](<../../../.gitbook/assets/image%20(184).png>)

Within the chats tab, we can see that there is a `recyclops` bot that has some documentation.

![](<../../../.gitbook/assets/image%20(1408).png>)

I tested it out and it seems to execute code on the machine remotely.

![](<../../../.gitbook/assets/image%20(3770).png>)

Basic directory traversal works on this machine due to a lack of input validation for the directory entered.

![](<../../../.gitbook/assets/image%20(856).png>)

The user is `dwight`, and we can see that within this directory, there is a `hubot` directory. Hubot is an open source chat robot that could be the one used for this user. I could not read the `.ssh` files, so this was the next best thing.

![](<../../../.gitbook/assets/image%20(2625).png>)

We can see that within the `hubot/` directory, there's a `.env` file. This could contain some interesting content.

![](<../../../.gitbook/assets/image%20(436).png>)

We can test this password with the user `dwight` and attempt to SSH in, which works!

![](<../../../.gitbook/assets/image%20(2009).png>)

## Privilege Escalation

Running a LinPEAS, we find that CVE-2021-3560 works on this machine because of an outdated `sudo` version.

![](<../../../.gitbook/assets/image%20(274).png>)

CVE-2021-3560 is an authentication bypass on polkit, which allows for users to carry out privileged actions using DBus. This repo here works on this machine to get root:

{% embed url="https://github.com/Almorabea/Polkit-exploit" %}

![](<../../../.gitbook/assets/image%20(2746).png>)
