# Traceback

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/traceback-11.png)

### Finding Backdoor

Going to the website revealed that this website has some sort of backdoor left on it.

![](../../../.gitbook/assets/traceback-9.png)

Reading the page source gave another hint:

![](../../../.gitbook/assets/traceback-3.png)

For this, we can google 'Some of the best web shells that you might need' and be directed to this repository:

{% embed url="https://github.com/TheBinitGhimire/Web-Shells" %}

From there, we can create a wordlist of all the possible shells that are available, and use `gobuster` on the website. We would find that `smevk.php` is on the website.

![](../../../.gitbook/assets/traceback-7.png)

We can login with `admin:admin` and then find a functioning PHP web shell.

![](../../../.gitbook/assets/traceback-10.png)

Using the Execute part, we can gain a reverse shell on the machine as the `webadmin` user.

![](../../../.gitbook/assets/traceback-2.png)

## Privilege Escalation

### luvit

We can first check our sudo privileges.

![](../../../.gitbook/assets/traceback-6.png)

There's also a message left behind by the `sysadmin` user.

![](../../../.gitbook/assets/traceback-1.png)

`luvit` is a CLI tool that can be used to execute LUA code. Since we can use sudo on it, we can simply spawn in another shell using `os.execute()`.

![](../../../.gitbook/assets/traceback-5.png)

### Motd-d

When running LinPEAS, we can find that there are some interesting files we can write to:

![](../../../.gitbook/assets/traceback-8.png)

To exploit this, we would need to trigger the message to be displayed through SSH. As such, we can create a public key and echo it into the `authorized_keys` file for `sysadmin`. Afterwards, we need to execute this command:

```bash
echo "cp /bin/bash /home/sysadmin/bash && chmod u+s /home/sysadmin/bash" >> 00-header
```

This would create a `bash` SUID binary for us to escalate privileges. This 00-header file would need to be placed within the `/etc/update-motd.d/` file and then we can SSH in. Afterwards, spawning a root shell is simple.

![](../../../.gitbook/assets/traceback-4.png)
