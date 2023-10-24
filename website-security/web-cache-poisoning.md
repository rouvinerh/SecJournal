# Web Cache Poisoning

Web cache poisoning is an exploit whereby an attacker exploits how a web server caches requests so that we can serve harmful HTTP responses to users. An attacker must first figure out how to get a response  from the back-end server that contains a payload of some sort, cache that, and then serve it to other users on the website.&#x20;

## Web Cache

Caches were developed in order to reduce the workload of servers when handling lots of requests. Imagine if a server has to send a new HTTP response with the webpage for every single HTTP request. This would overload the server and also make it run really slow. Similarly, imagine if you made a request to a wesbite each time, and each time a new copy of the same window has to be fetched. This would result in significantly lower performance as it is slow to keep requesting a fresh copy of the same page.

So, caches were developed to solve this problem. They are between the server and the user, and it stores copies of responses to particular requests for a period of time. If another user sends the same request, the cache simply serves a copy of the cached response instead of requesting for a new one, effectively allowing the back-end server to do nothing. After the period of time is up, the cache is deleted to prevent excessive memory usage.

This saves a load of time, as websites do not have to keep requesting the same copy over and over again. Below is visual representation of how caches work:

<figure><img src="../.gitbook/assets/image (341).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

To determine if there is a cached response within the cache, **cache keys** are used. This would identify whether or not the request needs to head to the back-end server. The cache key would typically contain the request line and the HTTP Host header. The components that aren't included in it are considered 'unkeyed'.&#x20;

## Exploitation

The exploitation of this would involve a few steps:

* [ ] Identify the unkeyed inputs&#x20;
  * Unkeyed inputs are generally HTTP headers, and the cache decides whether to serve a cached response to the user using it.
  * Random inputs can be added to the headers and then comparing of responses to see if there are any differences.
  * **Burpsuite Param Miner** is a great tool for this, as it sort of does it for you.
  * During testing, it is important to **include cache busters**, which are in the form of unique (and random) parameters to the request. This would prevent our test requests from being cached and users finding out about our attack. Param Miner does this for us automatically.
* [ ] Force back-end server to respond if harmful request has been sent
  * We would need to identify exactly how the website processes our request with our unkeyed input.
  * For example, if our random input is used to generate other data and is not validated, then this could be an entry point for the attack.
* [ ] Get the Response Cache
  * Perhaps the hardest step, because we can do all of the above but if our response isn't cached, we would be unable to distribute our attack.
  * Whether a response is cached or not would depend on a lot of factors, and we probably need to keep playing around with the application.
  * The `X-Cache` header tells would have a `hit` when it is cached, else it will state `miss`. Other useful headers are the `Cache-Control` header, which would basically tell us when wil lthe next time the resource be cached again (specifies a `max-age` of the cache).
  * Personally, I just keep testing with different variations of the request till I get a hit.

I personally have not done any exploitation of this yet on any machine or CTF, so stay tuned for a relevant example!
