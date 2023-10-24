# SwagShop

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (904).png" alt=""><figcaption></figcaption></figure>

We have to add `swagshop.htb` to our `/etc/hosts` file to access port 80.

### Magento Shop

This is whatwe see when we view port 80:

<figure><img src="../../../.gitbook/assets/image (2598).png" alt=""><figcaption></figcaption></figure>

This is running an outdated version of Magento shop, and we can easily find exploits for it. The exploit here would change admin password of the site via SQL Injection:

{% embed url="https://github.com/joren485/Magento-Shoplift-SQLI/blob/master/poc.py" %}

<figure><img src="../../../.gitbook/assets/image (4062).png" alt=""><figcaption></figcaption></figure>

Then we can grab a publicly available RCE exploit from ExploitDB:

{% embed url="https://www.exploit-db.com/exploits/37811" %}

This would require 3 fields, and we have 3 of them:

<figure><img src="../../../.gitbook/assets/image (1440).png" alt=""><figcaption></figcaption></figure>

We can visit `/app/etc/local.xml` to find the date required:

<figure><img src="../../../.gitbook/assets/image (1272).png" alt=""><figcaption></figcaption></figure>

Then, we can easily gain a reverse shell by using the PoC.

## Privilege Escalation

I don't have any screenshots of this in my archive for some reason...weird. Checking `sudo` privileges for this reveals we can use `vi` as root.

We can follow GTFOBins and run this to spawn a root shell:

```
sudo vi /var/www/html/a -c ':!/bin/sh'
```
