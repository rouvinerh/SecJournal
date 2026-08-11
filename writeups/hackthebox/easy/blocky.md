# Blocky

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/blocky-8.png)

### Plugins

Port 80 is a Wordpress Site that has a post referencing a plugin and a wiki system being in development.

![](../../../.gitbook/assets/blocky-6.png)

We can use `gobuster` on the website to find some hidden content.

![](../../../.gitbook/assets/blocky-1.png)

Heading to the plugins directory, we find two .jar files.

![](../../../.gitbook/assets/blocky-2.png)

We can take a look at these jar files using `jd-gui`, and find some SQL credentials within the machine.

![](../../../.gitbook/assets/blocky-5.png)

So now we have a password but no user to use it with.

### Wordpress Scan

Earlier, we found some Wordpress-related directories, hence we can use `wpscan` to enumerate more about this machine. This would allow us to find this `notch` user.

![](../../../.gitbook/assets/blocky-3.png)

With the password and this username, we can SSH into the machine.

![](../../../.gitbook/assets/blocky-4.png)

## Privilege Escalation

Checking sudo privileges, we see this.

![](../../../.gitbook/assets/blocky-7.png)

Because we have the password from earlier, we can run `sudo su` to become root.
