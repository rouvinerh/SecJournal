# OpenAdmin

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/openadmin-5.png)

### Port 80

We can run a `gobuster` scan on port 80:

![](../../../.gitbook/assets/openadmin-14.png)

I visited the `/music` directory first and it brought me to some corporate website:

![](../../../.gitbook/assets/openadmin-15.png)

When I clicked `login`, it brought me to `/ona`, which was a dashboard for OpenNetAdmin:

![](../../../.gitbook/assets/openadmin-4.png)

This version of OpenNetAdmin was vulnerable to RCE:

![](../../../.gitbook/assets/openadmin-3.png)

{% embed url="https://www.exploit-db.com/exploits/47691" %}

We can gain a shell by following the PoC:

![](../../../.gitbook/assets/openadmin-2.png)

![](../../../.gitbook/assets/openadmin-18.png)

## Privilege Escalation

### Jimmy Credentials

![](../../../.gitbook/assets/openadmin-12.png)

The users present on the machine are `joanna` and `jimmy`, and it seems that `ssh` with this password works on `jimmy`:

![](../../../.gitbook/assets/openadmin-6.png)

### Joanna SSH Key

When looking around the `/var/www/internal` directory, we can some code referencing the private SSH key of `joanna`:

![](../../../.gitbook/assets/openadmin-9.png)

When reading further, we can find the password and username hard-coded into the application:

![](../../../.gitbook/assets/openadmin-19.png)

The hash can be cracked to give `Revealed`. We can read `/etc/apache2/sites-available/internal.conf` to find the hidden sub-domain and port it is open on:

![](../../../.gitbook/assets/openadmin-17.png)

After port forwarding via `ssh -L 52846:127.0.0.1:52846 jimmy@10.10.10.71`, we can access the login page:

![](../../../.gitbook/assets/openadmin-16.png)

Logging in reveals a password protected RSA Private Key:

![](../../../.gitbook/assets/openadmin-7.png)

We can decrypt this via `ssh2john`:

![](../../../.gitbook/assets/openadmin-13.png)

Afterwards, we can use `openssl rsa -in key -out privatekey` to write the private RSA key, then `ssh` in as `joanna`:

![](../../../.gitbook/assets/openadmin-1.png)

### Nano GTFOBins

When checking `sudo` privileges, `joanna` can run `nano` as `root`:

![](../../../.gitbook/assets/openadmin-8.png)

Based on GTFOBins, we can simply run the following commands to gain a shell:

![](../../../.gitbook/assets/openadmin-11.png)

![](../../../.gitbook/assets/openadmin-10.png)

Rooted!
