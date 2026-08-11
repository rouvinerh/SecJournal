# Traceback

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(988).png>)

### Finding Backdoor

Going to the website revealed that this website has some sort of backdoor left on it.

![](<../../../.gitbook/assets/image%20(467).png>)

Reading the page source gave another hint:

![](<../../../.gitbook/assets/image%20(1879).png>)

For this, we can google 'Some of the best web shells that you might need' and be directed to this repository:

{% embed url="https://github.com/TheBinitGhimire/Web-Shells" %}

From there, we can create a wordlist of all the possible shells that are available, and use `gobuster` on the website. We would find that `smevk.php` is on the website.

![](<../../../.gitbook/assets/image%20(3511).png>)

We can login with `admin:admin` and then find a functioning PHP web shell.

![](<../../../.gitbook/assets/image%20(551).png>)

Using the Execute part, we can gain a reverse shell on the machine as the `webadmin` user.

![](<../../../.gitbook/assets/image%20(167).png>)

## Privilege Escalation

### luvit

We can first check our sudo privileges.

![](<../../../.gitbook/assets/image%20(3324).png>)

There's also a message left behind by the `sysadmin` user.

![](<../../../.gitbook/assets/image%20(1063).png>)

`luvit` is a CLI tool that can be used to execute LUA code. Since we can use sudo on it, we can simply spawn in another shell using `os.execute()`.

![](<../../../.gitbook/assets/image%20(2219).png>)

### Motd-d

When running LinPEAS, we can find that there are some interesting files we can write to:

![](<../../../.gitbook/assets/image%20(3790).png>)

To exploit this, we would need to trigger the message to be displayed through SSH. As such, we can create a public key and echo it into the `authorized_keys` file for `sysadmin`. Afterwards, we need to execute this command:

```bash
echo "cp /bin/bash /home/sysadmin/bash && chmod u+s /home/sysadmin/bash" >> 00-header
```

This would create a `bash` SUID binary for us to escalate privileges. This 00-header file would need to be placed within the `/etc/update-motd.d/` file and then we can SSH in. Afterwards, spawning a root shell is simple.

![](<../../../.gitbook/assets/image%20(1987).png>)
