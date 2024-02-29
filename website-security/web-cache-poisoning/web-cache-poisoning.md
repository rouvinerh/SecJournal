# Web Cache Poisoning

Web cache poisoning is an exploit whereby an attacker exploits how a web server caches requests, allowing for malicious server requests to be returned to normal users. An attacker must first figure out how to get a response from the back-end server that contains a payload of some sort, cache that, and then serve it to other users on the website.&#x20;

## Web Cache

Caches were developed in order to reduce the workload of servers when handling lots of requests. Imagine if a server has to send a new HTTP response with the webpage for every single HTTP request. This would overload the server and also make it run really slow. Similarly, imagine if you made a request to a website each time, and each time a new copy of the same window has to be fetched. This would result in significantly lower performance as it is slow to keep requesting a fresh copy of the same page.

It is faster to store a copy on a cache server for frequently requested pages / resources:

<figure><img src="../../.gitbook/assets/image (341).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

To determine if there is a cached response within the cache, **cache keys** are used. This identifies whether a 'new copy' needs to be retrieved from the back-end server. The cache key typically contains the request line and the HTTP Host header. The components that aren't included in it are considered 'unkeyed'.

## Exploitation

First, identify the unkeyed inputs.
  * Unkeyed inputs are generally HTTP headers, and the cache decides whether to serve a cached response to the user using it.
  * Random inputs can be added to the headers and then comparing of responses to see if there are any differences.
  * **Burpsuite Param Miner** is a great tool for this.
  * During testing, it is important to **include cache busters**, which are in the form of unique (and random) parameters to the request. This would prevent our test requests from being cached and users finding out about our attack. Param Miner does this for us automatically.

Secondly, force the back-end server to respond to a malicious response:
  * Identify exactly how the website processes our request with our unkeyed input.
  * For example, if our random input is used to generate other data and is not validated, then this could be an entry point for the attack since payloads can be embedded into our request.

Lastly, get the response cache
  * Whether a response is cached or not would depend on a lot of factors, and one needs to  keep playing around with the application.
  * The `X-Cache` header tells would have a `hit` when it is cached, else it will state `miss`. Other useful headers are the `Cache-Control` header, which state when the resource is cached again (specifies a `max-age` of the cache).

Honestly, I hardly test for this, but there are some CVEs for proxy softwares that some websites use.