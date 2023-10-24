# Shared

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1110).png" alt=""><figcaption></figcaption></figure>

I took note of the HTTPS site, and wanted to check it out. Also, added `shared.htb` to the `/etc/hosts` file as required.

### HTTPS Port

The website was a standard shopping page.

<figure><img src="../../../.gitbook/assets/image (4074).png" alt=""><figcaption></figcaption></figure>

I wanted to view the certificate that was used to view any names or information that I could use.

<figure><img src="../../../.gitbook/assets/image (209).png" alt=""><figcaption></figcaption></figure>

There were wildcards present in the domain, so I knew that we had to check for subdomains that were present.

<figure><img src="../../../.gitbook/assets/image (3654).png" alt=""><figcaption></figcaption></figure>

### Custom\_cart SQLI

The checkout page looked vulnerable to me.&#x20;

<figure><img src="../../../.gitbook/assets/image (753).png" alt=""><figcaption></figcaption></figure>

All the parameters passed in via POST request were fine, but when proxying traffic, I noticed the weird `custom_cart` cookie that was used when we were adding products and viewing stuff. I tested some SQL injection payloads and found it to be vulnerable.

<figure><img src="../../../.gitbook/assets/image (3177).png" alt=""><figcaption></figcaption></figure>

For instance, I was able to enumerate the datbase that was used.

<figure><img src="../../../.gitbook/assets/image (2611).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1080).png" alt=""><figcaption></figcaption></figure>

The output of the injection was printed on screen for us. We can now enumerate the database, which has a **user** table within it. This payload can be used to enumerate whatever we need:

```
custom_cart = {"breached' and 0=1 union select 1, username, 3 from heckout.user -- -": "10"}
```

From there, we can find out the username of the user, which is **james\_mason**.&#x20;

<figure><img src="../../../.gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

We can also find his hash.

<figure><img src="../../../.gitbook/assets/image (2673).png" alt=""><figcaption></figcaption></figure>

This password can be cracked using crackstation.

<figure><img src="../../../.gitbook/assets/image (1687).png" alt=""><figcaption></figcaption></figure>

Then, we can ssh in as `james_mason`.&#x20;

<figure><img src="../../../.gitbook/assets/image (334).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We find that there's another user called `dan_smith`, and we cannot access the user flag he has:

<figure><img src="../../../.gitbook/assets/image (2629).png" alt=""><figcaption></figcaption></figure>

### Pspy64

I ran `pspy` to see what processes were running on the server. Found a few interesting ones, the first being that the root user was running `redis-server`.

<figure><img src="../../../.gitbook/assets/image (3671).png" alt=""><figcaption></figcaption></figure>

The second was that `dan_smith` was running `ipython` consistently.

<figure><img src="../../../.gitbook/assets/image (2834).png" alt=""><figcaption></figcaption></figure>

### IPython

We can enumerate the version of `ipython` that was running.

<figure><img src="../../../.gitbook/assets/image (3375).png" alt=""><figcaption></figcaption></figure>

This version was vulnerable to an RCE exploit.

{% embed url="https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x" %}

Following the PoC, we can grab dan's private key:

<figure><img src="../../../.gitbook/assets/image (3153).png" alt=""><figcaption></figcaption></figure>

Then, we can SSH in as dan.&#x20;

### Redis-Server

We saw earlier that root was running `redis-server`. We first need to search for the password for this server. Firstly, we can check the version and find that it's outdated and vulnerable to the Redis ExecuteCommand Module exploit.

<figure><img src="../../../.gitbook/assets/image (563).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/n0b0dyCN/RedisModules-ExecuteCommand" %}

&#x20;I ran LinPEAS, and found one within the `/usr/local/bin/redis_connector_dev` file.

<figure><img src="../../../.gitbook/assets/image (3033).png" alt=""><figcaption></figcaption></figure>

We can then sign in using `redis-cli` on the machine and load the exploit.

<figure><img src="../../../.gitbook/assets/image (1173).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3713).png" alt=""><figcaption></figcaption></figure>

