# Cross-Origin Resource Sharing

Cross-Origin Resource Sharing (CORS), is an exploit of a misconfigured website policy that dictates which external sources the website is allowed to interact with. 

## Same-Origin Policy

The policy governing accessible resources looks something like this:

<figure><img src="../.gitbook/assets/image (2341).png" alt=""><figcaption></figcaption></figure>

This determines what kind of information a website is able to extract from another website. The policy can be used to protect user information, as it prevents other websites from stealing or reading information from users. 

A website without CORS could be tricked into loading malicious JS code by attackers to do bad things.

## Access-Control-Allow-Origin

A HTTP header that is included within requests made from one website to another. It is used to identify what an external website is allowed to access. The web browser would compare this header with the requesting website's origin to determine if the permission should be granted.

If the website has a Origin header of `http://example.com` and was allowed to access the credentials of a user, then this is included in the request: `access-control-allow-credentials: true`

### Pre-Flight Checks

In some cases, there are pre-checks done before requests are processed. Under certain circumstances, when a cross-domain request includes a non-standard HTTP method, such as `OPTIONS` or `PUT`, then the website would kind of do a double check to ensure that it's allowed to carry out those HTTP methods.&#x20;

<figure><img src="../.gitbook/assets/image (3104).png" alt=""><figcaption><p><em>Pre-Flight Check</em></p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1974).png" alt=""><figcaption><p><em>Check Response</em></p></figcaption></figure>

This could potentially be useful for enumeration and seeing what's really allowed on websites. The process would look something like this:

<figure><img src="../.gitbook/assets/image (2052).png" alt=""><figcaption></figcaption></figure>

## Exploitation

Find methods where the website is loading other websites in requests and see if there are misconfigured policies present on the website.

Afterwards, malicious JS code can be used to load things that would be inaccessible to regular users but not the website, as shown below.

<figure><img src="../.gitbook/assets/image (3345).png" alt=""><figcaption></figcaption></figure>

## References

{% embed url="https://book.hacktricks.xyz/pentesting-web/cors-bypass" %}
