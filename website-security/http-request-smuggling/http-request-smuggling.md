# HTTP Request Smuggling

HTTP request smuggling is a technique that is used to mess up the sequence of HTTP requests a website processes. These exploits are often critical in nature, as this can allow attackers to bypass security controls and gain access to sensitive data.

## Smuggling

When HTTP requests are sent to a server, the user sends requests to a front-end server, and then forward the traffic to the back-end. Typically, there are several requests sent over the same connection for maximizing efficiency. When HTTP requests are sent one after another, the receiving server parses the HTTP request headers **to determine where one request ends and the next one begins.**

It is normally processed in a queue data structure:

<figure><img src="../../.gitbook/assets/image (145).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

Request smuggling happens when attackers embed a hidden request, which is then interpreted by the back-end as a separate request.

<figure><img src="../../.gitbook/assets/image (535).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

Generally, the manipulation of the `Content-Length` or `Transfer-Encoding` headers allows for this. These headers count the length of the request sent differently.

* `Content-Length`
  * Counts the length of the message in bytes.
  * If we are sending a POST request with a parameter of `q=smuggle`, then the `Content-Length` header has a value of 9 as there are 9 characters.
* `Transfer-Encoding`
  * Specifies that the request uses **chunked encoding**.
  * Terminated by with a chunk size of zero.
  * Normally, browsers do not use chunked encoding, as they are normally used for **server responses.** Take note that it is possible to sent messages using this encoding as requests.

The message below has 1 chunk within it:

<pre class="language-http"><code class="lang-http">POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

<strong>b
</strong>q=smuggling
0
</code></pre>

Since the HTTP has 2 methods for specifying the message length, there can be conflicts in how they are processing messages. Requests can pass through different servers, and these servers might not support chunked encoding. The difference in behavior is what gives rise to this exploit.

### CL.TE

In this scenario, the front-end server uses the `Content-Length` header and the back-end uses the `Transfer-Encoding` header.

To exploit this, we can send in a request like this:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked

0

hello!!!
```

The front-end server processes the Content-Length header and determines that the request body only contains 13 bytes of data (inclusive of `\r` characters) and forwards this request. The back-end then sees the request using chunked encoding, this processing the first chunk, which is stated to be 0 length and terminates the request.

The following bytes, the 'hello' portion is left unprocessed and the back-end server would treat this as **the start of the next request in sequence.** It is prepended to the next request in the queue.

One can send this request to check;

```http
POST /search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Transfer-Encoding: chunked

e
q=smuggle&x=
0

GET /404 HTTP/1.1
Foo: x
```

If the exploit works, 404 is returned, indicating that the request was changed. If this method does not work, then change the request to have one character, **which would cause a time delay**.

### TE.CL

In this scenario, the back-end server uses the `Content-Length` header and the front-end uses the `Transfer-Encoding` header.

We can now send this request:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 3
Transfer-Encoding: chunked

8
hello!!!
0
# \r\n\r\n goes here
```

The front-end uses TE to process the request, and sees that the first chunk of data is 8 bytes long. The back-end sees that the request body is 3 bytes long, which **is the newline and '8' character.** Then, the following bytes starting with the 'hello' portion is left unprocessed and the back-end server prepends this to the next request.

Here's one example payload, similar to the one above:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 3
Transfer-Encoding: chunked

8
GET /404 HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

a=
0
```

### TE.TE

In this scenario, both the front and back use `Transfer-Encoding` to process requests. The exploit here has to do with **obfuscating the header**. Here are some examples of changing the header:

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

The point of changing the header is to find whether the front and back end server processes it differently. Sometimes, obfuscation would change how the back-end server processes it, while the front-end sees it without difference. Fuzzing and good enumeration is key to identifying the vulnerability.

Depending on how the website processes information, the rest of the attack takes the same form as the CL.TE or TE.CL exploits.
