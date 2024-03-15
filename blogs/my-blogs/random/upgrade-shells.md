# Upgrade Shells

## Upgrade?

Normally, when I get a reverse shell, there are some things that I cannot do. I cannot cancel processes with Ctrl + C, auto-complete file names with Tab, and some programs won't execute and cause the shell to freeze.

<figure><img src="../../../.gitbook/assets/image (1223).png" alt=""><figcaption></figcaption></figure>

The shell above ends when I enter ^C (Ctrl + C). This is pretty annoying, because if I had a reverse shell after a long and convuluted exploit, I may accidentally start a process that takes forever (or straight up crashes) and I cannot exit the process. This leaves me with 2 choices:

* Restart the entire shell process if I don't have a backdoor.
* Just hope the process dies and I can get my shell back.

Through my machines, I've learnt of ways to "upgrade the shell". Within the machines I have done on both HTB and PGP, I always use these commands to make the shell better:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
OR script /dev/null -c bash
^Z (Ctrl + Z) -> Suspend process
stty raw -echo; fg

# for Windows
rlwrap nc -lvnp 4444 
```

After doing these commands, the shell can process control characters and run all programs.

<figure><img src="../../../.gitbook/assets/image (2820).png" alt=""><figcaption></figcaption></figure>

So why does this work? And what exactly does it do? First, we need to understand what does TTY mean.

## Teletypewriter (TTY)

Teletypewriter (TTY) is the name of a keyboard or device used to communicate with computers in the early days of computing. The TTY in the past used to be a keyboard and a printer in one unit, and all information passes through a physical port.

Today, TTY has evolved and it now refers to a virtual terminal that provides a text-based interface for interacting with systems. A TTY in a Unix system is basically the user's terminal session, which allows the user to communicate with the OS.&#x20;

When we first start a terminal, we are greeted with a Command Line Interface (CLI) of which we can send commands to the computer and it replies us directly in the same window. This is because a TTY is assigned to us as we start the new `bash` process, and the TTY can handle the user input and device output for that session.

A session that is not a TTY is called a **non-interactive shell**. These shells cannot display interactive interfaces (like in `vim` or `nano`) and also cannot handle user input (such as entering passwords for `sudo`). However, not all commands require a TTY shell. Commands like `whoami` or `ls` work perfectly fine without it.

In reverse shells, we spawn without an interactive shell, and this causes some commands and inputs to not function properly. Hence, we can use `python` to 'stabilise' our shells.

## Shell Stabilisation

When we execute our reverse shells (with whatever method), the 'shells' are really processes running **inside a terminal**, instead of being in a new terminal.

Basically, when we connect to a reverse shell, we are NOT in a `bash`  instance of our own. Instead, `nc` is sending those commands to the main terminal and it is executed, with the output being redirected to our shell. This also explains why in reverse shells, sometimes there are no prompts like `user@ubuntu` or `$` in the command line, since commands are indirectly run in the interactive terminal.&#x20;

Here's a shell trying to run `sudo` without stabilisation:

<figure><img src="../../../.gitbook/assets/image (3802).png" alt=""><figcaption></figcaption></figure>

Suppose the top terminal is where the injection takes place (like in a webshell or something) and the bottom terminal is my listener port that catches a shell. Notice how running `sudo` causes the input to be printed on the top terminal? If we do something like `sudo -l`, then the bottom terminal would freeze as it waits for a password prompt from the top window.

This is because the top terminal is **interactive.** `sudo` requires interactive shells to be executed.&#x20;

Let's take a look at another example where I run `whoami`:

<figure><img src="../../../.gitbook/assets/image (561).png" alt=""><figcaption></figcaption></figure>

`whoami` is a command that does not require any interactive shell to be executed, hence running it without `sudo` does not require an interactive shell.&#x20;

When I execute `sudo whoami`, it asks for a password on the top terminal, and when entered it prints the output on the bottom terminal.&#x20;

Here it is after stabilisation:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

Now the output of `sudo` is output onto the same terminal because it is a TTY shell and it is interactive. Take note that commands like `sudo` can still work in non-interactive shells with the `-S` flag, but it is not recommended due to security reasons.&#x20;

However, we still cannot send control characters (like Ctrl + C) without ending the shell. More interestingly, after stabilising the shell via `python`, my password when using `sudo` is **sent in clear**. Normally, it is not shown for security purposes.&#x20;

This is where terminal drivers and `stty` comes in.

## Disabling Terminal Drivers

Terminal drivers are software components that interfaces between the hardware devices that provides input (the keyboard) and output to a user. Basically, it is the component that sends the keystrokes from my keyboard to the terminal device to be processed.&#x20;

**In short, it takes the input of the user.**&#x20;

When we have a reverse shell, the terminal driver that is processing raw input is **our own machine**. Through a reverse shell, our input is sent through our device to the remote device and processed there on an interactive shell. However, **our device's terminal driver would still be processing the raw input before sending it.**

This is no issue for regular printable characters, but it is an issue for **control characters**.

> Control characters are non-printable characters, such as Ctrl and Tab.

So even if we have an interactive shell, sending Ctrl + C would be processed by our machine and our machine would act first and kill the process. **This means that our Ctrl + C input is NOT sent to the device**.&#x20;

This is why sending control characters, like TAB and Ctrl + C don't work because our terminal driver is still active and it 'acts first'. Any raw input is processed by the terminal driver, and it explains why our password is printed in clear when using `sudo`.

### ^Z Stty raw -echo; fg

Set Teletype (stty) is a program that changes terminal line settings.&#x20;

{% embed url="https://www.computerhope.com/unix/ustty.htm" %}

When we run `stty raw`, we are setting our terminal driver to **raw mode**. In raw mode, the terminal driver **no longer processes any input and output**. If we were to do it on our own terminal, we would be unable to send control characters.&#x20;

<figure><img src="../../../.gitbook/assets/image (3958).png" alt=""><figcaption><p>I cannot execute Ctrl + C here.</p></figcaption></figure>

A side effect of this is the terminal output being a bit visually messy because **output is also no longer processed**.&#x20;

So by first suspending the process with Ctrl + Z and running `stty raw -echo`, we are telling our machine to stop processing our input. Then, we resume the process with `fg` to get our shell back. This would allow us to send the control characters to the remote machine **and be processed by the remote terminal driver instead of our machine's.**&#x20;

The end product is a fully functioning shell that can execute all commands and control characters.&#x20;

### Rlwrap

`rlwrap` is a readline wrapper that allows a more robust input handling mechanism. This is prepended to `nc` to add more terminal features. This binary itself provides the handling features required to handle certain inputs to the reverse shell.

## Summary

When we get a reverse shell, we are in a **non-interactive shell**. This means our inputs are **first processed by the local terminal driver**, then sent to the remote machine via the connection, which is then sent to the **remote interactive terminal that executes our command**. Programs with a visual interface like `vim` or require user input like `sudo` won't work properly as user input is requested in the **interactive terminal**.&#x20;

We have to spawn an interactive shell first using `python` or `script`, and this would allow our reverse shell to take user input and execute all commands properly.&#x20;

Then, we have to disable the terminal driver on our machine via `stty raw` to allow control characters to be sent to the remote machine **without processing by our machine**. The `-echo` removes the terminal printing commands entered on a newline. This is done by **suspending the process, disabling the driver, then resuming it**.

This is how shells are 'upgraded'.
