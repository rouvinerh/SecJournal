# Shared

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/shared-2.png)

I took note of the HTTPS site, and wanted to check it out. Also, added `shared.htb` to the `/etc/hosts` file as required.

### HTTPS Port

The website was a standard shopping page.

![](../../../.gitbook/assets/shared-19.png)

I wanted to view the certificate that was used to view any names or information that I could use.

![](../../../.gitbook/assets/shared-6.png)

There were wildcards present in the domain, so I knew that we had to check for subdomains that were present.

![](../../../.gitbook/assets/shared-16.png)

### Custom\_cart SQLI

The checkout page looked vulnerable to me.

![](../../../.gitbook/assets/shared-21.png)

All the parameters passed in via POST request were fine, but when proxying traffic, I noticed the weird `custom_cart` cookie that was used when we were adding products and viewing stuff. I tested some SQL injection payloads and found it to be vulnerable.

![](../../../.gitbook/assets/shared-13.png)

For instance, I was able to enumerate the datbase that was used.

![](../../../.gitbook/assets/shared-7.png)

![](../../../.gitbook/assets/shared-1.png)

The output of the injection was printed on screen for us. We can now enumerate the database, which has a **user** table within it. This payload can be used to enumerate whatever we need:

```
custom_cart = {"breached' and 0=1 union select 1, username, 3 from heckout.user -- -": "10"}
```

From there, we can find out the username of the user, which is **james\_mason**.

![](../../../.gitbook/assets/shared-5.png)

We can also find his hash.

![](../../../.gitbook/assets/shared-9.png)

This password can be cracked using crackstation.

![](../../../.gitbook/assets/shared-4.png)

Then, we can ssh in as `james_mason`.

![](../../../.gitbook/assets/shared-14.png)

## Privilege Escalation

We find that there's another user called `dan_smith`, and we cannot access the user flag he has:

![](../../../.gitbook/assets/shared-8.png)

### Pspy64

I ran `pspy` to see what processes were running on the server. Found a few interesting ones, the first being that the root user was running `redis-server`.

![](../../../.gitbook/assets/shared-17.png)

The second was that `dan_smith` was running `ipython` consistently.

![](../../../.gitbook/assets/shared-10.png)

### IPython

We can enumerate the version of `ipython` that was running.

![](../../../.gitbook/assets/shared-15.png)

This version was vulnerable to an RCE exploit.

{% embed url="https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x" %}

Following the PoC, we can grab dan's private key:

![](../../../.gitbook/assets/shared-12.png)

Then, we can SSH in as dan.

### Redis-Server

We saw earlier that root was running `redis-server`. We first need to search for the password for this server. Firstly, we can check the version and find that it's outdated and vulnerable to the Redis ExecuteCommand Module exploit.

![](../../../.gitbook/assets/shared-20.png)

{% embed url="https://github.com/n0b0dyCN/RedisModules-ExecuteCommand" %}

I ran LinPEAS, and found one within the `/usr/local/bin/redis_connector_dev` file.

![](../../../.gitbook/assets/shared-11.png)

We can then sign in using `redis-cli` on the machine and load the exploit.

![](../../../.gitbook/assets/shared-3.png)

![](../../../.gitbook/assets/shared-18.png)

