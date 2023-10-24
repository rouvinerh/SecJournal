# Metasploit Framework

The Metasploit framework is a project that owned by the security company Rapid7. It is a modular, Ruby-based platform that enables hackers to write, test and execute exploit codes. Apart form that, it also includes something called **msfvenom**, which is a CLI based tool used to generate payloads of various types.

Metasploit has a Pro version, which you need to pay for, as well as a free version. For this section, I will be elaborating on the free version.

**Take note, if you are doing the Offensive Security Certified Professional, Metasploit is considered an auto-exploiter and is hence banned.**

<figure><img src="../../../.gitbook/assets/metasploit-framework-logo.svg" alt=""><figcaption><p><em>Metasploit Framework</em></p></figcaption></figure>

## Modules

Metasploit has a few modules that can be used to do whatever you want. They are as follows:

1. Exploit
   * Run an exploit on a target
2. Auxiliary
   * Scan a target for certain vulnerabilities, such as detecting EternalBlue vulnerabilities
3. Payload
   * Contains all the different payloads for exploit codes, such as reverse shells, bind shells, code execution etc.
   * There are many different types of payloads, some for Windows 64-bit and 32-bit, Linux, Android, PHP shells etc.
4. Encoders
   * Encoders would reduce the size of the payload, and maybe help it bypass certain firewalls that are used and block the payload
5. Post-Exploitation
   * Modules here would involve the usage of a **meterpreter shell.**
   * Payloads here can dump credentials, do further scanning, find possible privsec vectors.

## Meterpreter

Meterpreter is sort of a special shell, because it not only provides for CLI access to the victim computer, but also allows for the usage of useful commands that would make post-exploitation or privilege escalation very easy.

For example, one of the things meterpreter can do is just privilege escalate for us through impersonation, as well as take screenshots of the computer's page so we can see what's going on there.

Another cool thing about meterpreter is that **it is loaded through in-memory DLL injection.** This means that it does not create a file on the computer, and it runs purely in memory. It helps us stay silent on the computer without drawing too much attention to our activities. Once we leave, the memory used would slowly be overwritten over time and there would be little to no trace of our presence.

However, it should be noted that Meterpreter shells are highly fingerprinted (which means a ton of anti-viruses know what it is), and can be significantly harder to try and load on a device with a good firewall. It is still possible, but would require a lot of modication to the payload such that the signatures don't match.

## Usage

Here's an example of a Metasploit exploitation on a vulnerable system from ScriptKiddie on HackTheBox.

Say we have enumerated that the system is vulnerable from a certain exploit. (using searchsploit)

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

We can launch Metasploit by using the `msfconsole` command. Most of the time it loads some cool ASCII art. We can cirumvent this using `msfconsole -q`.

<figure><img src="../../../.gitbook/assets/image (298).png" alt=""><figcaption></figcaption></figure>

We would be presented with a form of command line that is has bash integrated into it, so we can still do commands within this.

<figure><img src="../../../.gitbook/assets/image (1665).png" alt=""><figcaption></figcaption></figure>

Anyways, we can first search for the exploit using some keywords. For the example, we can use `Metasploit apk exploit` as one of the keywords.

This can be done using the `search` command.

<figure><img src="../../../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

Afterwards, we just pick the one we want using the `use` command. For this, I want to use the exploit #1, so I just type `use 1` . In other cases, we can just copy and paste the name of the module and use `use <name>.`

<figure><img src="../../../.gitbook/assets/image (916).png" alt=""><figcaption></figcaption></figure>

Once we are here, we need to configure the exploit to use the correct payload and options before launching it.

We can check options using the `options` command, and set them using the `set <option name>` command. For the payload, understanding that ScriptKiddie is a Linux system, we can use `set payload cmd/unix/reverse_netcat` to set the payload.

**LHOST would mean listening host, and LPORT would mean listening port.** In this case, my IP address is 10.10.16.9, and the port I'm listening on is 6666.

**RHOST means receiving host, and RPORT means receiving port, which may not be applicable to all exploits.** Generally, these are intended for the target port and IP address.

Once the options have been set, we can simply run `exploit` to make the exploit run.

<figure><img src="../../../.gitbook/assets/image (1543).png" alt=""><figcaption></figcaption></figure>

For this exploit, we can see that it creates a `msf.apk`file for us to use.

We can then go about using the exploit according to the exploit instructions.

<figure><img src="../../../.gitbook/assets/image (3899).png" alt=""><figcaption></figcaption></figure>

Now we can see how we have received a reverse shell on port 6666, as specified in Metasploit.&#x20;

We can see how Metasploit can be used to generate payloads instantly and then do more with it.

## Meterpreter Usage

Meterpreter can be accessed through the use of meterpreter payloads. There are meterpreter payloads for both Windows and Linux alike.

`exploit/multi/handler` module in Metasploit needs to be used and it's basically the equivalent of a listening port and configured in the same manner.

<figure><img src="../../../.gitbook/assets/image (2650).png" alt=""><figcaption></figcaption></figure>

We would see something like this if we were successful in executing our payload. For this, we can see how I spawned a shell using the `shell` command.

<figure><img src="../../../.gitbook/assets/image (2719).png" alt=""><figcaption></figcaption></figure>

### Migrating Processes

Migrating processes in Meterpreter helps to hide the process of the shell, gain persistence and avoid detection by using an innocent process, such as explorer.exe. The shell would also be more stable.

After getting in, we would need to use the `pid` and `migrate <pid>` commands to migrate to whatever process there is. Again, I recommend explorer.exe to prevent any anti-viruses from shutting you down.

<figure><img src="../../../.gitbook/assets/image (3226).png" alt=""><figcaption></figcaption></figure>

### Meterpreter Modules

There are tons of modules that can be used by meterpreter, one of them is called **espia.** This module enables the `screengrab` command which would take a screenshot of the victim machine.

Usage of these modules is also pretty simple to understand.

<figure><img src="../../../.gitbook/assets/image (3476).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (975).png" alt=""><figcaption><p><em>Screenshot captured (Acute HTB)</em></p></figcaption></figure>

There are other modules, such as being able to load **mimikatz** through the `load kiwi` module and proceed to dump credentials from the domain.

Pretty simple to use Metasploit and Meterpreter, and they are insanely powerful in doing stuff.

## MSFVenom

MSFVenom is sort of a payload generator that wouldn't require the usage of msfconsole.

This is how we generate a payload:

<figure><img src="../../../.gitbook/assets/image (1553).png" alt=""><figcaption><p><em>Generate .war file</em></p></figcaption></figure>

There are many types of payloads in msfvenom, like linux/shell/reverse\_tcp, which is a Linux reverse shell.

Apart from that, MSFVenom can also be used to generate encoded shellcode for building our own custom scripts.

<figure><img src="../../../.gitbook/assets/image (168).png" alt=""><figcaption></figcaption></figure>

MSFVenom is a really powerful and fast payload generator for exploits and file uploads.

Here's a full list of possible payloads:

{% embed url="https://medium.com/@hannahsuarez/full-list-of-546-msfvenom-payloads-39adb4d793c9" %}

## Sources

{% embed url="https://www.metasploit.com/" %}
