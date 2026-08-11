# SolidState

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(2699).png>)

### JAMES Server

SMTP is open, which is rather suspicious. I connected via `nc` and tested some default credentials, and found that `root:root` worked.

![](<../../../.gitbook/assets/image%20(2958).png>)

Now that we are logged in, we can read some emails:

![](<../../../.gitbook/assets/image%20(1056).png>)

With this, we can SSH in as `mindy`.

### Shell Escape

When in the user's directory, we find a restricted shell where we cannot execute a lot:

![](<../../../.gitbook/assets/image%20(4073).png>)

I researched a bit on how to escape this shell, and found that appending `-t "bash --noprofile"` works:

![](<../../../.gitbook/assets/image%20(1201).png>)

## Privilege Escalation

### Cronjob Injection

We can run `pspy32` on this machine to view processes:

![](<../../../.gitbook/assets/image%20(2177).png>)

I found that we have write access over this file, so we can just append a reverse shell to it:

![](<../../../.gitbook/assets/image%20(3126).png>)

After waiting for a bit, we would catch a reverse shell:

![](<../../../.gitbook/assets/image%20(927).png>)
