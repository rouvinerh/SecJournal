# CLI and Shells

## Unix

Unix based machines is just a name for machines that rely on the Command Line Interface (CLI) to interact with the machine. All Linux distros are considered Unix based systems, as well as MacOS (which is just built on Linux).

For Linux, the main language used here is called **Bourne Again SHell**, otherwise known as **Bash** for short. Bash is a scripting language that can be used for many purposes and is very fast to use.

Compared to using a Graphical User Interface (GUI), this is much faster if you know what you're doing. For security mains, we **must know how to interact with these CLIs and work fast in the terminal**.&#x20;

### Environment Variables (PATH)

When in bash, it relies on something called the `env` variables, which are basically sort of like the default variables that Bash loads when we are using our system.

<figure><img src="../../../.gitbook/assets/image (576).png" alt=""><figcaption></figcaption></figure>

Above is an example of a PATH variable from a Kali machine. What the PATH variable does is **tell bash where to start looking for binaries to run.** What this means is that when I run a binary **without the absolute path**, it would first check for all variables within the PATH and then if it returns true, it would run it.

Here's an example of using `cat` with and without the absolute path. The absolute path would mean specifying the whole directory that has the binary in it, as shown above.

<figure><img src="../../../.gitbook/assets/image (2913).png" alt=""><figcaption></figcaption></figure>

Within the earlier $PATH variable, we can see how there is the `/usr/bin` directory within it. As such, when we run `cat` , it would check all directories within the PATH directory for that directory and then once found, it would run it.

Here's what happens when we are using a binary that does not exist.

<figure><img src="../../../.gitbook/assets/image (3076).png" alt=""><figcaption></figcaption></figure>

Using this PATH variable, we can do things like run python3 scripts from the CLI.

<figure><img src="../../../.gitbook/assets/image (1029).png" alt=""><figcaption></figcaption></figure>

In Windows, there is also a PATH variable, but it would have to be manually configured. It also can do the same things as the Linux one, albeit a bit less straightforward.&#x20;

<figure><img src="../../../.gitbook/assets/image (2239).png" alt=""><figcaption></figcaption></figure>

Anyways, when we install all our tools and binaries in Linux, they would basically go into one of the PATH variables, and that's how we use these tools without the absolute paths.

### Bash

As said earlier, Bash is a scripting language that is used for many purposes in security. There are a lot of tools in Bash that would automate a lot of tasks, such as finding all files within a system that have a certain name, or renaming entire directories.&#x20;

Since Bash is a language, it too comes with its own set of logic, like functions, variables, loops and so on.

Both Linux and MacOS have Bash installed as the default interpreter for CLI commands.

Apart from that, there are many other special charaters in Linux that can be used to direct stuff from standard output into a file, or direct input from a file into a command using piping, chaining commands together, expressions and so on.

There are just simply loads of commands that can be used, so here's the resources that I used to learn terminal-fu since I can't possibly cover all of them here.

{% embed url="https://cmdchallenge.com/" %}

{% embed url="https://labex.io/courses/linux-basic-commands-practice-online" %}

### Shebangs #!

When we are writing scripts in Linux, we have to use #! to tell the system what intepreter to use for the rest of the file. This would have to be filled in with the **absolute directory** of the interpreter.

For example if we are creating a python3 script, it would look something like this:

```bash
#!/usr/bin/python3 

print('this is a shebang in action')
```

Then, we can just run the binary using this

```bash
chmod +x script.py # make script executable
./script.py

# if we don't use shebangs, we need to run it like this
python3 script.py
```

### Permissions and Files

Linux has permission that dictate whether someone can read, execute or write to a file as shown below.

<figure><img src="../../../.gitbook/assets/file_permissions.png" alt=""><figcaption></figcaption></figure>

These can be viewed using the `ls -la` command.

<figure><img src="../../../.gitbook/assets/image (1089).png" alt=""><figcaption></figcaption></figure>

From here, we can set the permissions using the `chmod` command, with numbers that would represent the different permissions.

* Read = 4
* Write = 2
* Execute = 1

When we do `chmod 777 hello.txt`this would make it such that our file would have full permissions across all 3 groups.&#x20;

<figure><img src="../../../.gitbook/assets/image (2051).png" alt=""><figcaption></figcaption></figure>

Similarly, we can adjust this depending on what the file requires.&#x20;

Another thing to take note of is that **Linux treats everything as a file.** This is just an underlying architecture of the OS to make things more convenient. Long story short, the files, directories, binaries, pipes, sockets and everything is represented by a file descriptor within the kernel.

Basically, everything here is a stream of bytes, and hence has permissions for it.

We can see in the picture above that `.` and `..` are considered files, although they are noted as directories.&#x20;

## Powershell

Windows uses the Command Prompt, otherwise known as cmd.exe. This has a different syntax and commands compared to Linux machines, and in my opinion, a bit harder to use.

<figure><img src="../../../.gitbook/assets/image (3437).png" alt=""><figcaption></figcaption></figure>

We can still do a lot of the stuff that Unix machines can do, but we would require Windows's own scripting language called **Powershell**.

> PowerShell is a task automation and configuration management program from Microsoft, consisting of a command-line shell and the associated scripting language.
>
> * Wikipedia, the best source

Powershell is highly integrated with the .NET framework, whereby it is built on top of it. As such, it allows for easy access to the .NET Framework API, Component Object Model, Windows Management Instrumentation and so on.

Being proficient in Powershell as an attacker would basically mean we are able to use Windows APIs to our advantage in things like enumeration, persistance and privilege escalations.

Powershell has its own help page too, and if we need help just do the following:

<figure><img src="../../../.gitbook/assets/image (3381).png" alt=""><figcaption></figcaption></figure>

### Cmdlets

Cmdlets are lightweight commands in the Powershell environment. They are denoted by the .ps1 extension. Popular cmdlets are stuff like PowerView, Invoke-Mimikatz and so on.

Think about them like defining a function that includes a bunch of stock Powershell commands, whereby calling a function like `Invoke-Bloodhound` would save us the hassle of having to run all the Powershell commands individually.

To import them, do the following:

```powershell
Import-Module . .\script.ps1
# or
. .\script.ps1
```

Either way, we would 'load' the cmdlet as a module. We can check what modules are loaded using the `get-module -listavailable` command.

<figure><img src="../../../.gitbook/assets/image (1973).png" alt=""><figcaption></figcaption></figure>

One popular Powershell framework is Powersploit, which is basically a pentesters suite of Powershell tools that can be imported and used easily.

### Execution Policies

Unlike Linux, which has permissions and stuff, Powershell has policies that dictate whether or not something can be run.

<figure><img src="../../../.gitbook/assets/image (3037).png" alt=""><figcaption></figcaption></figure>

&#x20;This command would basically tell the program whether or not to let a certain script execute.

### Scripts

Here's a simple Powershell script taht would basically help us print file inputs

{% code title="script.ps1" %}
```powershell
Param(
    [parameter(mandatory=$true)][string]$file
)
Get-Content $file
```
{% endcode %}

We can see that this script would define a command called Get-Content, which can be used with other files like so:

```powershell
.\script.ps1
$file = "users.txt"
Get-Content $file
# print content of files
```

Powershell doesn't require the usage of a #! like bash does.

### Similarities To Bash

Since Powershell is a language, it too has its own logic, like for loops, functions and whatever. In Powershell, there also exists the usage of piping and redirecting input/output to files or commands.

<figure><img src="../../../.gitbook/assets/image (3308).png" alt=""><figcaption></figcaption></figure>

Unfortunately, not many websites are out there with interactive games to use Powershell compared to that of Bash.

Documentation and StackOverflow are your best friends when trying to make Powershell do something you want it to.

{% embed url="https://livebook.manning.com/book/powershell-in-practice/chapter-1/52" %}

{% embed url="https://learn.microsoft.com/en-us/powershell/" %}

## Shell

A shell is basically because it wraps the OS and allows us to interact with the OS through a command line interface (CLI).&#x20;

<figure><img src="../../../.gitbook/assets/image (2318).png" alt=""><figcaption></figcaption></figure>

This would allow us to basically interact with the computer without a GUI. Powershell and Bash are interpreters for shells for Windows and Linux systems alike.

Getting a remote shell on a computer would mean that we have remote control of the device over a CLI, and can do whatever we want with it. Being able to remotely execute commands on another system is something called Remote Code Execution (RCE), and it can be achieved in a few methods.

### Payloads

Payloads are basically the piece of code or binary that the attacker intends to deliver to the victim, such as an exploit script sending commands, shellcode for buffer overflows, or a piece of malware. Most of the time, payloads are sent and run using whatever vulnerabilities that an organisation has.

### Reverse Shell

Reverse shells occur when the hackers are able to make the device connect back to their device to produce a CLI. Unlike the bind shell, the target host would actually conenct back to the hacker's machine, which is actively listening and waiting for an incoming connection on one port.

<figure><img src="../../../.gitbook/assets/image (3485).png" alt=""><figcaption><p><em>Gaining a reverse shell on port 21</em></p></figcaption></figure>

### Bind Shell

Bind shells are created when a port is opened on the victim machine and listens for incoming connections. The hacker can then connect to this one port, and be able to control the computer from there.

### Web Shells

Web shells are when attackers send an input to a web application, and is able to achieve some type output to signify that it is indeed executing commands on the victim machine.

Below is an example of how we are able to use a web vulnerability to write a web shell and confirm that we have RCE on the system.

<figure><img src="../../../.gitbook/assets/image (2471).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (891).png" alt=""><figcaption></figcaption></figure>

Sometimes, the output of the shell is not as explicit as the above, and it is hidden. As such, other methods, such as telling the victim machine to ping the attacker machine and listening for the ping packets (otherwise known as ICMP packets) to reach us.

Below is an example of a blind RCE.

<figure><img src="../../../.gitbook/assets/image (656).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2035).png" alt=""><figcaption></figcaption></figure>

### Secure Shell (SSH)

Not really an exploit per se, but rather a network protocol that allows for data to be exchanged using a secure channel between 2 networked devices. This is rather common in Unix based systems. The Secure in SSH means that communication is encrypted between the host and the recipient, and that it cannot be decrypted.

The predecessor of SSH is something called Telnet, which does the same thing, **but it is not encrypted.** Telnet is the worst because hackers can intercept packets and be able to view what you are doing exactly without trouble (more on sniffing later).&#x20;

<figure><img src="../../../.gitbook/assets/image (3518).png" alt=""><figcaption><p><em>SSH Tunnel</em></p></figcaption></figure>

In essence, both of which can provide for file transfer utilities, as well as a remote CLI on the target system. This would require us to know the target system's password and username.

<figure><img src="../../../.gitbook/assets/image (311).png" alt=""><figcaption><p><em>SSH using private key</em></p></figcaption></figure>

SSH runs on something called a private and public keys, which I will cover in a later section on cryptography.

