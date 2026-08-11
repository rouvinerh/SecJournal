# Poison

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/poison-4.png)

### Base64 Password

We can do a `gobuster` scan on the machine to find all possible files present:

![](../../../.gitbook/assets/poison-9.png)

On the website itself, it was a simple application to read files:

![](../../../.gitbook/assets/poison-2.png)

This was hosted at `http://<IP>/browse.php/?file=<FILENAME>`, which had an obvious LFI. We can use this to read `listfiles.php`, which was present on the machine.

![](../../../.gitbook/assets/poison-8.png)

There was a `pwdbackup.txt` file, and when read it shows a password that has been encoded 13 times with base64:

![](../../../.gitbook/assets/poison-7.png)

When decrypted, it gives `Charix!2#4%6&8(0`. We can then use this to SSH in as the user `charix`.

![](../../../.gitbook/assets/poison-3.png)

## Privilege Escalation

### VNC

We can check the ports that are open with `netstat -an`.

![](../../../.gitbook/assets/poison-5.png)

VNC is open on port 5901, and normally, this requires a password file. Conveniently, we can find a `secret.zip` in the user's directory:

![](../../../.gitbook/assets/poison-6.png)

We can transfer this back to our machine via `base64`, and then use `vncviewer` to login to the VNC service after port forwarding it:

```bash
ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
vncviewer -passwd secret 127.0.0.1:5901
```

This would spawn a terminal as the `root` user:

![](../../../.gitbook/assets/poison-1.png)
