# Trick

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1832).png" alt=""><figcaption></figcaption></figure>

We can add the `trick.htb` domain as per usual HTB practice.

### DNS Fuzzing

All the ports yield nothing of interest and port 80 was just a corporate website with nothing to interact with. However, when attempting a zone transfer, we would get another domain here:

<figure><img src="../../../.gitbook/assets/image (3706).png" alt=""><figcaption></figcaption></figure>

The `preprod-payroll` subdomain was new, and I headed there.

### Payroll Rabbit Hole

The page revealed some kind of application used to manage employee salary tracking.

<figure><img src="../../../.gitbook/assets/image (2520).png" alt=""><figcaption></figcaption></figure>

Initially, I assumed that there would be some kind of public exploit for this Employee Record system, and found quite a few.

<figure><img src="../../../.gitbook/assets/image (2259).png" alt=""><figcaption></figcaption></figure>

However, none of the exploits worked here and I was stuck.

### Subdomain Fuzzing

The whole payroll bit was a rabbit hole, and I could not make anything work. As such, I started to fuzz subdomains again, but found nothing from it.&#x20;

I then tried to fuzz with the `preprod-` bit prefixed, and found a new domain:

<figure><img src="../../../.gitbook/assets/image (3857).png" alt=""><figcaption></figcaption></figure>

### LFI for SSH Keys

The new page contained a load of rubbish information, and when clicking on the different tabs, we can see this `page` parameter pop up.

<figure><img src="../../../.gitbook/assets/image (857).png" alt=""><figcaption></figcaption></figure>

We can test this for a simple directory traversal exploit. Using the standard `../../../` did not work, but `....//....//....//` worked instead.

<figure><img src="../../../.gitbook/assets/image (3273).png" alt=""><figcaption></figcaption></figure>

With this, I attempted to read the private SSH keys of the user `michael`.

<figure><img src="../../../.gitbook/assets/image (906).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can simply SSH in as michael using this key.

<figure><img src="../../../.gitbook/assets/image (452).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Fail2ban

When enumerating the user's permissions, we can see that he's part of the security group.

<figure><img src="../../../.gitbook/assets/image (1624).png" alt=""><figcaption></figcaption></figure>

Additionally, we are allowed to run `fail2ban restart` as root using `sudo`.

<figure><img src="../../../.gitbook/assets/image (2315).png" alt=""><figcaption></figcaption></figure>

Fail2ban is a service that would block an IP address after many failed attempts to connect. The conf file for this is within the `/etc/fail2ban/action.d/iptables-multiport.conf` file. Upon detecting a bannable action, a script would run to block the IP address.

We are given permissions to edit the configuration files for this service in this machine. As such, we can edit the script that is run to gain a reverse shell or create a SUID binary **after getting 'banned**'. We can force our malicious script to execute after using `hydra` to brute force SSH many times.

This repo made is easy to exploit:

{% embed url="https://github.com/rvizx/fail2ban/blob/main/fail2ban" %}

<figure><img src="../../../.gitbook/assets/image (598).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2247).png" alt=""><figcaption></figcaption></figure>

Rooted.
