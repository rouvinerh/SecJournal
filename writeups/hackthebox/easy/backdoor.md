# Backdoor

## Gaining Access

First we start with an Nmap scan as usual.

<figure><img src="../../../.gitbook/assets/image (2907).png" alt=""><figcaption></figcaption></figure>

We can check out the HTTP server.

### Wordpress Instance

The HTTP server was powered by Wordpress, so immediately we can run `wpscan` to check for common exploits. However, this didn't really reveal much for me, and I wasn't able to amke this work.

### Port 1337

This was a port I had never seen before. A bit of googling revealed that this was a **remote gdbserver** being hosted on the website. There are many easy ways for us to upload a file and gain a reverse shell.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver" %}

I was really lazy, so I got the the `exploit/multi/gdb/gdb_server_exec` module from MSF to do the work. In my testing after rooting, I could not make the PoC work for me. Strange.

<figure><img src="../../../.gitbook/assets/image (2866).png" alt=""><figcaption></figcaption></figure>

Now we can grab the user flag easily.

## Privilege Escalation

I ran linpeas as early enumeration to see what was going on. Linpeas flagged out that `screen` was being run by root.

<figure><img src="../../../.gitbook/assets/image (1051).png" alt=""><figcaption></figcaption></figure>

`screen` is a software that allows for us to run multiple screens on a single terminal. Root running this means that the root user has multiple screens that are running some processes currently. The attack in this case would be to attach ourselves to this process.&#x20;

In this machine's case, what it is doing is creating a folder in the S-root directory with a session ID whenever it runs. This would allow us to find the specific process that we want to attach ourselves to.

Using the `screen` command itself, we can do the following to gain a root shell.

```bash
screen -x root/<PID>
```

However, this complains about a 'missing terminal type'. What remedies this is running the following commands to spawn a TTY shell

```bash
export TERM=xterm
python3 -c 'import pty;pty.spawn("/bin/bash")'
screen -x root/<PID>
```

This would drop us in a root shell and we can read the flag.

<figure><img src="../../../.gitbook/assets/image (805).png" alt=""><figcaption></figcaption></figure>
