---
description: What happens when we go to a URL in a browser?
---

# Combined Knowledge

With all the knowledge combined, we can answer this question. I'll be assuming that this search is not cached, so we would need to fetch a new copy of it from the Internet.&#x20;

## Clicking Enter

Starting from Layer 7, which is the Application Layer, we open our browser in some GUI and begin our search. The protocols that connect us to Google.com or Bing, such as HTTPS and DNS are all Layer 7 protocols.

Suppose we want to head to https://github.com for this. First, the browser checks the following:

* **Scheme**
  * The URL contains HTTPS:// to start, specifiying that the browser would have to use the HTTPS protocol to connect to the server.
  * In this case, Github uses Transport Layer Security (TLS), so a TLS connection is required later.
  * There are other schemes such as ftp://, file:/// and so on.
* **Domain**
  * The domain in this case is **github.com.** As specified earlier, the browser would make a request first to the cache to see if there exists a copy of the IP address there.
    * In specific, it would check the browser cache, then OS cache, then local network cache at my router, and a DNS server cache on my ISP server.
    * If it still cannot find it, then the DNS servers on my ISP would make a recursive DNS search, which basically means it will ask multiple DNS servers around the Internet.
    * The recursion continues until the reply is received.&#x20;
  * Based on earlier assumption, there is not, so the website makes a DNS request to the DNS servers and this results in a recursive search ensuing.&#x20;
  * DNS servers would reply with the public IP address of github.com and reply my device.&#x20;
* **Path**
  * Next, the website would check for the directory that is being request, such as /blog or /posts.
  * In this case, there are none, so we move on.
* **Resource**
  * Lastly, the website checks for any extension on website. Perhaps we are trying to access a static file, like an index.html page or something.
  * Without an extension, it usually indicates that the server would generate this content.&#x20;
  * If there is, then we would directly access that file which has been put in a public-facing area of the DMZ.

## Establishing Session

Our computer has now found the correct IP address to connect to, and the specifics of the search made. Next, it would make a TCP connection with the server.

Our device would send a TCP packet which would use the public Internet routing infrastructure to get our packet to the host. This is but one method of reaching the host.

The second, more efficient method would be to use a Content Delivery Network, or CDN, which is basically a huge caching server made to inmprove performance of the Internet. Without a CDN, our packet would have to travel to another country where Github is hosted. With the CDN, such as CloudFront, it would bring a cache of the website closer to Asia, and our packet travels less.&#x20;

The second method would reduce the extra hops and redeliveries needed. Then, the TCP handshake would take place. Since HTTPS is used, another TLS handshake would also be used to form that secure tunnel.&#x20;

## Sending HTTP

The session has been established, and now we can send our request. The request would be in the form of HTTP request to the server.

HTTP requests have multiple different 'verbs' which specify what our browser wants to do. This is called a request method. It also contains the path, such as /blog, and the HTTP version we want to use, which can be HTTP/2 or HTTP/1.1 depending on the server.

The HTTP request would look something like this when intercepted.&#x20;

<figure><img src="../.gitbook/assets/image (2377).png" alt=""><figcaption></figcaption></figure>

Important HTTP Headers are specified as follows:

* Host - The recipient host domain
* Cookie - Whatever cookies required to dictate the session type generated.
* User-Agent - The type of browser I am using

## Server Processing

The server at github.com would then take the request we have sent and process it, line by line and decide how to respond.&#x20;

A response would look like this:

<figure><img src="../.gitbook/assets/image (1415).png" alt=""><figcaption></figcaption></figure>

Pretty big, but runs on the same concept and uses HTTP headers to specify information that our browser needs to know.

HTTP Response Status Codes are specified as follows:

* 1XX - Informational
* 2XX - Sucess
* 3XX - Redirection
* 4XX - Client Error
* 5XX - Server-side error

In this case, we see a HTTP/2 200 OK, which means we are good to go.&#x20;

## Rendering Content&#x20;

The content received from the server would be dictated by the **Content-Type** HTTP Header. In this case, Github returns us content as `text/html; charset=utf-8`. Our browsers would then parse and render the HTML, making additional requests to get the Javascript, CSS, images and other data. Then, the page would slowly load as per how it was designed.&#x20;

The Content-Type header can be changed to whatever is required, doesn't always have to be text/html.

We would see the page as follows:

<figure><img src="../.gitbook/assets/image (2149).png" alt=""><figcaption></figcaption></figure>

And that's basically what happens when we go to a URL.&#x20;
