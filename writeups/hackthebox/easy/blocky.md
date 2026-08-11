# Blocky

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(944).png>)

### Plugins

Port 80 is a Wordpress Site that has a post referencing a plugin and a wiki system being in development.

![](<../../../.gitbook/assets/image%20(2844).png>)

We can use `gobuster` on the website to find some hidden content.

![](<../../../.gitbook/assets/image%20(1600).png>)

Heading to the plugins directory, we find two .jar files.

![](<../../../.gitbook/assets/image%20(1816).png>)

We can take a look at these jar files using `jd-gui`, and find some SQL credentials within the machine.

![](<../../../.gitbook/assets/image%20(2648).png>)

So now we have a password but no user to use it with.

### Wordpress Scan

Earlier, we found some Wordpress-related directories, hence we can use `wpscan` to enumerate more about this machine. This would allow us to find this `notch` user.

![](<../../../.gitbook/assets/image%20(2138).png>)

With the password and this username, we can SSH into the machine.

![](<../../../.gitbook/assets/image%20(2262).png>)

## Privilege Escalation

Checking sudo privileges, we see this.

![](<../../../.gitbook/assets/image%20(3865).png>)

Because we have the password from earlier, we can run `sudo su` to become root.
