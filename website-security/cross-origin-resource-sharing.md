# Cross-Origin Resource Sharing

Cross-Origin Resource Sharing (CORS), is an exploit of a misconfigured website policy that dictates which external sources the website is allowed to interact with. This was created many years ago, initially to potentially malicious cross-domain interactions.

## Same-Origin Policy

The policy governing the resources accessible would look something like this:

<figure><img src="../.gitbook/assets/image (2341).png" alt=""><figcaption></figcaption></figure>

This would determine what kind of information a website is able to extract from another website. The policy can be used to protect user information, as it prevents other websites from stealing or reading information from users, for example.&#x20;

How this works is that it controls what kind of JS code is loaded across websites. For example, it would not allow the loading of user information on external websites.&#x20;

## Access-Control-Allow-Origin

This is a HTTP heaer that is included within a HTTP request from one website to another, and its purpose is to identify what an external website is allowed to access. The web browser would compare this header with the requesting website's orign to determine if the permission should be granted.&#x20;

For example, if the wesite has the Origin header as http://example.com and could access the credentials of a user, then there would be a header like `access-control-allow-credentials: true`

The usage of a wildcard \* is common as well.&#x20;

### Pre-Flight Checks

In some cases, there are pre-checks done before requests are processed. Under certain circumstances, when a cross-domain request includes a non-standard HTTP method, such as `OPTIONS` or `PUT`, then the website would kind of do a double check to ensure that it's allowed to carry out those HTTP methods.&#x20;

<figure><img src="../.gitbook/assets/image (3104).png" alt=""><figcaption><p><em>Pre-Flight Check</em></p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1974).png" alt=""><figcaption><p><em>Check Response</em></p></figcaption></figure>

This could potentially be useful for enumeration and seeing what's really allowed on websites. The process would look something like this:

<figure><img src="../.gitbook/assets/image (2052).png" alt=""><figcaption></figcaption></figure>

## Exploitation

Generally, we would want to find methods of which the website is loading other websites in requests and see if there are misconfigured policies present on the website.

Afterwards, malicious JS code can be used to load things that would be inaccessible to regular users but not the website, as shown below.

<figure><img src="../.gitbook/assets/image (3345).png" alt=""><figcaption></figcaption></figure>

## References

{% embed url="https://book.hacktricks.xyz/pentesting-web/cors-bypass" %}
