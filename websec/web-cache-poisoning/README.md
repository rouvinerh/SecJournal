# Web Cache Poisoning / Deception

Web cache poisoning is an exploit whereby an attacker exploits how a web server caches requests, allowing for malicious server requests to be returned to normal users. An attacker must first figure out how to get a response from the back-end server that contains a payload of some sort, cache that, and then serve it to other users on the website.

## Web Cache

Caches were developed in order to reduce the workload of servers when handling lots of requests. Imagine if a server has to send a new HTTP response with the webpage for every single HTTP request. This would overload the server and also make it run really slow. Similarly, imagine if you made a request to a website each time, and each time a new copy of the same window has to be fetched. This would result in significantly lower performance as it is slow to keep requesting a fresh copy of the same page.

It is faster to store a copy on a cache server for frequently requested pages / resources:

<figure><img src="../../.gitbook/assets/image (341).png" alt=""><figcaption><p><em>Taken from PortSwigger Web Security Academy</em></p></figcaption></figure>

The web cache technology uses a 'cache key' to fingerprint requests. The key is typically a set of request attributes, like cookies, headers or parameters that a web cache uses. If the cache does have a response stored using the same key, then it simply serves the stored response instead of going to the origin server to get a fresh response.

If the web cache can be controlled by an attacker, then they could use it to obtain the sensitive data or deliver malicious payloads. For example, an attacker can cache a XSS payload, which is delivered and executed when an innocent user views the same resource.

## Poisoning

Cache poisoning requires that an attacker figure out what part of their input is **not** part of the cache key but used by the origin server. For example, the origin server might process an extra header like `X-Forwarded-Host`, but the cache does not track this header as part of the key. Including it does not influence what gets cached.

Suppose that an attacker finds that the `X-Forwarded-Host` header does not have input validation, and the origin server uses the input there to generate script tags when visiting `/index.html` of a site (so setting to `evil.com` causes a `evil.com/script.js` to be loaded on the page). This header is not part of the cache key. To exploit this, an attacker just has to get this response cached on the CDN, and any subsequent user gets served the malicious JS file.

A more common attack is causing a DoS. Instead of injecting a malicious script, an attacker can use the same unkeyed input to make the origin server return a 500 response. By getting that error page cached and served to everyone else, the attacker essentially creates a DoS condition. This is easier to exploit than a script injection attack.

## Deception

Deception is the reverse of poisoning. Instead of exploiting the gap between the cache keys are and what the origin uses, an attacker is exploiting the cache's guess on what is static versus dynamic.

Caches generally do not cache everything, because some page content is generated dynamically. For instance, visiting a user's profile page is dynamic and should not be cached on the CDN. However, images, JS and CSS files are safe to cache since they're basically the same for every user.

Many caches use simple heuristics such as the file extensions to determine what is static or not. For example, everything ending on `.jpg` or `.css` is safe to cache. This is fast, but does not actually validate the content.

One example is a site that displays session tokens and other personal data on the `/account/settings` page, with a cache that only uses extensions to determine if something should be cached. The attacker can trick the victim to log into `/account/settings/fake.css`, which the origin server either redirects back to `/account/settings` or shows the user's details in the page contents. The cache looks at the `.css` extension and determine it is safe to cache since it is a static response.

As such, the cache store's the victim's private information. All an attacker has to do then is visit `/account/settings/fake.css` to retrieve the information of the victim.

## Exploitation

The main method of which web caches are exploited is done by finding out the flaws of the cache key. Caches typically transform keyed inputs before using it to build the key. This could mean that certain query parameters are filtered out, or input is normalised by stripping port numbers or other fields. The key idea here is to find out what data gets written into a cache key and what data gets passed into the application, since the attacks here hinge on fact that the application and cache process information differently.

The exploitation steps can be broken down into 3 stages.

1. Finding a page or endpoint that provides feedback about the cache. This is called a 'cache oracle'. This could be a page that returns a header indicating `HIT` / `MISS`, has timing differences, or provides visible changes in dynamic content. Ideally, this also reflects our input so parsing mismatches can be identified. Depending on the CDN used, there are headers that can be included to check the actual cache key (although this is likely blocked).

2. Identify how the key is handled. This portion is where the keyed input is dropped or normalised before being added to the key, even though the full value reaches the application. Parts of the data passed in are stripped, perhaps.

3. Finding an exploitable gadget. After finding a cache key flaw, something needs to be injected. This could be an open redirect or XSS. Chaining the key flaw with the gadget escalates the vulnerability, and is the main impact generator.

The above methodology roughly works for both poisoning and deception. The difference is that poisoning attempts to find gaps between what is written into the cache key versus what is passed to the application's code. Deception cares about finding gaps between how the cache and origin server each parse and map URLs to a resource, only caring about whether a cache mistakes a dynamic page with sensitive data as a static one. This is done by adding junk to the end of the path or static suffixes, then checking whether the page caches the response or not.

Lastly, a cache buster can be used for testing to force a cache miss. This is good for establishing a clean baseline, and also to avoid interference with real users. 