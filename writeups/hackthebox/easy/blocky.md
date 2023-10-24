# Blocky

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (944).png" alt=""><figcaption></figcaption></figure>

### Plugins

Port 80 is a Wordpress Site that has a post referencing a plugin and a wiki system being in development.

<figure><img src="../../../.gitbook/assets/image (2844).png" alt=""><figcaption></figcaption></figure>

&#x20;We can use `gobuster` on the website to find some hidden content.

<figure><img src="../../../.gitbook/assets/image (1600).png" alt=""><figcaption></figcaption></figure>

Heading to the plugins directory, we find two .jar files.

<figure><img src="../../../.gitbook/assets/image (1816).png" alt=""><figcaption></figcaption></figure>

We can take a look at these jar files using `jd-gui`, and find some SQL credentials within the machine.

<figure><img src="../../../.gitbook/assets/image (2648).png" alt=""><figcaption></figcaption></figure>

So now we have a password but no user to use it with.

### Wordpress Scan

Earlier, we found some Wordpress-related directories, hence we can use `wpscan` to enumerate more about this machine. This would allow us to find this `notch` user.

<figure><img src="../../../.gitbook/assets/image (2138).png" alt=""><figcaption></figcaption></figure>

With the password and this username, we can SSH into the machine.

<figure><img src="../../../.gitbook/assets/image (2262).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Checking sudo privileges, we see this.

<figure><img src="../../../.gitbook/assets/image (3865).png" alt=""><figcaption></figcaption></figure>

Because we have the password from earlier, we can run `sudo su` to become root.
