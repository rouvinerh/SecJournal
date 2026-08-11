# Shared

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(1110).png>)

I took note of the HTTPS site, and wanted to check it out. Also, added `shared.htb` to the `/etc/hosts` file as required.

### HTTPS Port

The website was a standard shopping page.

![](<../../../.gitbook/assets/image%20(4074).png>)

I wanted to view the certificate that was used to view any names or information that I could use.

![](<../../../.gitbook/assets/image%20(209).png>)

There were wildcards present in the domain, so I knew that we had to check for subdomains that were present.

![](<../../../.gitbook/assets/image%20(3654).png>)

### Custom\_cart SQLI

The checkout page looked vulnerable to me.

![](<../../../.gitbook/assets/image%20(753).png>)

All the parameters passed in via POST request were fine, but when proxying traffic, I noticed the weird `custom_cart` cookie that was used when we were adding products and viewing stuff. I tested some SQL injection payloads and found it to be vulnerable.

![](<../../../.gitbook/assets/image%20(3177).png>)

For instance, I was able to enumerate the datbase that was used.

![](<../../../.gitbook/assets/image%20(2611).png>)

![](<../../../.gitbook/assets/image%20(1080).png>)

The output of the injection was printed on screen for us. We can now enumerate the database, which has a **user** table within it. This payload can be used to enumerate whatever we need:

```
custom_cart = {"breached' and 0=1 union select 1, username, 3 from heckout.user -- -": "10"}
```

From there, we can find out the username of the user, which is **james\_mason**.

![](<../../../.gitbook/assets/image%20(199).png>)

We can also find his hash.

![](<../../../.gitbook/assets/image%20(2673).png>)

This password can be cracked using crackstation.

![](<../../../.gitbook/assets/image%20(1687).png>)

Then, we can ssh in as `james_mason`.

![](<../../../.gitbook/assets/image%20(334).png>)

## Privilege Escalation

We find that there's another user called `dan_smith`, and we cannot access the user flag he has:

![](<../../../.gitbook/assets/image%20(2629).png>)

### Pspy64

I ran `pspy` to see what processes were running on the server. Found a few interesting ones, the first being that the root user was running `redis-server`.

![](<../../../.gitbook/assets/image%20(3671).png>)

The second was that `dan_smith` was running `ipython` consistently.

![](<../../../.gitbook/assets/image%20(2834).png>)

### IPython

We can enumerate the version of `ipython` that was running.

![](<../../../.gitbook/assets/image%20(3375).png>)

This version was vulnerable to an RCE exploit.

{% embed url="https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x" %}

Following the PoC, we can grab dan's private key:

![](<../../../.gitbook/assets/image%20(3153).png>)

Then, we can SSH in as dan.

### Redis-Server

We saw earlier that root was running `redis-server`. We first need to search for the password for this server. Firstly, we can check the version and find that it's outdated and vulnerable to the Redis ExecuteCommand Module exploit.

![](<../../../.gitbook/assets/image%20(563).png>)

{% embed url="https://github.com/n0b0dyCN/RedisModules-ExecuteCommand" %}

I ran LinPEAS, and found one within the `/usr/local/bin/redis_connector_dev` file.

![](<../../../.gitbook/assets/image%20(3033).png>)

We can then sign in using `redis-cli` on the machine and load the exploit.

![](<../../../.gitbook/assets/image%20(1173).png>)

![](<../../../.gitbook/assets/image%20(3713).png>)

