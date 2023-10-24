# OpenAdmin

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1608).png" alt=""><figcaption></figcaption></figure>

### Port 80

We can run a `gobuster` scan on port 80:

<figure><img src="../../../.gitbook/assets/image (2882).png" alt=""><figcaption></figcaption></figure>

I visited the `/music` directory first and it brought me to some corporate website:

<figure><img src="../../../.gitbook/assets/image (3061).png" alt=""><figcaption></figcaption></figure>

When I clicked `login`, it brought me to `/ona`, which was a dashboard for OpenNetAdmin:

<figure><img src="../../../.gitbook/assets/image (1435).png" alt=""><figcaption></figcaption></figure>

This version of OpenNetAdmin was vulnerable to RCE:

<figure><img src="../../../.gitbook/assets/image (1311).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://www.exploit-db.com/exploits/47691" %}

We can gain a shell by following the PoC:

<figure><img src="../../../.gitbook/assets/image (123).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (601).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Jimmy Credentials

<figure><img src="../../../.gitbook/assets/image (2425).png" alt=""><figcaption></figcaption></figure>

The users present on the machine are `joanna` and `jimmy`, and it seems that `ssh` with this password works on `jimmy`:

<figure><img src="../../../.gitbook/assets/image (1617).png" alt=""><figcaption></figcaption></figure>

### Joanna SSH Key

When looking around the `/var/www/internal` directory, we can some code referencing the private SSH key of `joanna`:

<figure><img src="../../../.gitbook/assets/image (2282).png" alt=""><figcaption></figcaption></figure>

When reading further, we can find the password and username hard-coded into the application:

<figure><img src="../../../.gitbook/assets/image (836).png" alt=""><figcaption></figcaption></figure>

The hash can be cracked to give `Revealed`. We can read `/etc/apache2/sites-available/internal.conf` to find the hidden sub-domain and port it is open on:

<figure><img src="../../../.gitbook/assets/image (4017).png" alt=""><figcaption></figcaption></figure>

After port forwarding via `ssh -L 52846:127.0.0.1:52846 jimmy@10.10.10.71`, we can access the login page:

<figure><img src="../../../.gitbook/assets/image (3546).png" alt=""><figcaption></figcaption></figure>

Logging in reveals a password protected RSA Private Key:

<figure><img src="../../../.gitbook/assets/image (1988).png" alt=""><figcaption></figcaption></figure>

We can decrypt this via `ssh2john`:

<figure><img src="../../../.gitbook/assets/image (2631).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can use `openssl rsa -in key -out privatekey` to write the private RSA key, then `ssh` in as `joanna`:

<figure><img src="../../../.gitbook/assets/image (1098).png" alt=""><figcaption></figcaption></figure>

### Nano GTFOBins

When checking `sudo` privileges, `joanna` can run `nano` as `root`:

<figure><img src="../../../.gitbook/assets/image (2049).png" alt=""><figcaption></figcaption></figure>

Based on GTFOBins, we can simply run the following commands to gain a shell:

<figure><img src="../../../.gitbook/assets/image (2403).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2324).png" alt=""><figcaption></figcaption></figure>

Rooted!
