# SolidState

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/solidstate-4.png)

### JAMES Server

SMTP is open, which is rather suspicious. I connected via `nc` and tested some default credentials, and found that `root:root` worked.

![](../../../.gitbook/assets/solidstate-5.png)

Now that we are logged in, we can read some emails:

![](../../../.gitbook/assets/solidstate-1.png)

With this, we can SSH in as `mindy`.

### Shell Escape

When in the user's directory, we find a restricted shell where we cannot execute a lot:

![](../../../.gitbook/assets/solidstate-7.png)

I researched a bit on how to escape this shell, and found that appending `-t "bash --noprofile"` works:

![](../../../.gitbook/assets/solidstate-2.png)

## Privilege Escalation

### Cronjob Injection

We can run `pspy32` on this machine to view processes:

![](../../../.gitbook/assets/solidstate-3.png)

I found that we have write access over this file, so we can just append a reverse shell to it:

![](../../../.gitbook/assets/solidstate-6.png)

After waiting for a bit, we would catch a reverse shell:

![](../../../.gitbook/assets/solidstate-8.png)
