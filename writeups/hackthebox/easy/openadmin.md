# OpenAdmin

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(1608).png>)

### Port 80

We can run a `gobuster` scan on port 80:

![](<../../../.gitbook/assets/image%20(2882).png>)

I visited the `/music` directory first and it brought me to some corporate website:

![](<../../../.gitbook/assets/image%20(3061).png>)

When I clicked `login`, it brought me to `/ona`, which was a dashboard for OpenNetAdmin:

![](<../../../.gitbook/assets/image%20(1435).png>)

This version of OpenNetAdmin was vulnerable to RCE:

![](<../../../.gitbook/assets/image%20(1311).png>)

{% embed url="https://www.exploit-db.com/exploits/47691" %}

We can gain a shell by following the PoC:

![](<../../../.gitbook/assets/image%20(123).png>)

![](<../../../.gitbook/assets/image%20(601).png>)

## Privilege Escalation

### Jimmy Credentials

![](<../../../.gitbook/assets/image%20(2425).png>)

The users present on the machine are `joanna` and `jimmy`, and it seems that `ssh` with this password works on `jimmy`:

![](<../../../.gitbook/assets/image%20(1617).png>)

### Joanna SSH Key

When looking around the `/var/www/internal` directory, we can some code referencing the private SSH key of `joanna`:

![](<../../../.gitbook/assets/image%20(2282).png>)

When reading further, we can find the password and username hard-coded into the application:

![](<../../../.gitbook/assets/image%20(836).png>)

The hash can be cracked to give `Revealed`. We can read `/etc/apache2/sites-available/internal.conf` to find the hidden sub-domain and port it is open on:

![](<../../../.gitbook/assets/image%20(4017).png>)

After port forwarding via `ssh -L 52846:127.0.0.1:52846 jimmy@10.10.10.71`, we can access the login page:

![](<../../../.gitbook/assets/image%20(3546).png>)

Logging in reveals a password protected RSA Private Key:

![](<../../../.gitbook/assets/image%20(1988).png>)

We can decrypt this via `ssh2john`:

![](<../../../.gitbook/assets/image%20(2631).png>)

Afterwards, we can use `openssl rsa -in key -out privatekey` to write the private RSA key, then `ssh` in as `joanna`:

![](<../../../.gitbook/assets/image%20(1098).png>)

### Nano GTFOBins

When checking `sudo` privileges, `joanna` can run `nano` as `root`:

![](<../../../.gitbook/assets/image%20(2049).png>)

Based on GTFOBins, we can simply run the following commands to gain a shell:

![](<../../../.gitbook/assets/image%20(2403).png>)

![](<../../../.gitbook/assets/image%20(2324).png>)

Rooted!
