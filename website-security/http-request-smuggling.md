# HTTP Request Smuggling

HTTP request smuggling is a technique that is used to mess up the sequence of HTTP requests a website processes. These exploits are often critical in nature, as this can allow attackers to bypass security controls and gain access to sensitive data.&#x20;

## How it Works

When HTTP requests are sent to a server, the user sends requests to a front-end server, and then forward the traffic to the back-end. Typically, there are several requests sent over the same connection for maximizing efficiency. When HTTP requests are sent one after another, the receiving server parses the HTTP request headers **to determine where one request ends and the next one begins.**

It forms a queue like structure, and this can be represented like this:

<figure><img src="../.gitbook/assets/image (145).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

Request smuggling happens when attackers edit a single request to have another hidden request, which is then interpreted by the back-end as a separate request.&#x20;

<figure><img src="../.gitbook/assets/image (535).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

Generally, HTTP request smuggling happens because of manipulation of the `Content-Length` or `Transfer-Encoding` headers. These headers count the length of the request sent differently.

* `Content-Length`
  * Self-explanatory, counts the length of the message in bytes
  * If we are sending a POST request with a parameter of `q=smuggle`, then the `Content-Length` header has a value of 9 as there are 9 characters.
* `Transfer-Encoding`
  * This header is used to specify that the message uses **chunked encoding**.&#x20;
  * It specifies that the message is sent in one or more chunks, and each chunk consists of the message, **terminated by with a chunk size of zero.**
  * Normally, browsers do not use chunked encoding, as they are normally used for **server responses.** Take note that it is possible to sent messages using this encoding as requests.
  * The message below has 1 chunk within it.

<pre class="language-http"><code class="lang-http">POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
<strong>
</strong><strong>b
</strong>q=smuggling
0
</code></pre>

Since the HTTP specification provides two different methods for specifying the length of HTTP messages, there can be conflicts in how they are processing messages. This happens a lot, as requests can be passed through multiple different servers, and these servers might not support chunked encoding due to a variety of reasons. The difference in behavior is what gives rise to this exploit.

As such, HTTP Request Smuggling attacks are different depending on how the front and backend servers process the length of requests.

### CL.TE

In this scenario, the front-end server uses the `Content-Length` header and the back-end uses the `Transfer-Encoding` header.&#x20;

To exploit this, we can send in a request like this:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked

0

hello!!!
```

The front-end server processes the Content-Length header and determines that the request body only contains 13 bytes of data (inclusive of newlines to terminate request) and forwards this request. The back-end then sees the request using chunked encoding, this processing the first chunk, which is stated to be 0 length and terminates the request.&#x20;

The following bytes, the 'hello' portion is left unprocessed and the back-end server would treat this as **being  the start of the next request in sequence.** This means that it effectively prepends itself on the next request.&#x20;

Finding this vulnerablity would require us to send this request:

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

If the exploit works, then we would get a **status code 404 response,** indicating that the request was changed. If this method does not work, then we can change the request to have one character, **which would cause a time delay**.

### TE.CL

In this scenario, the back-end server uses the `Content-Length` header and the front-end uses the `Transfer-Encoding` header.&#x20;

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

The front-end uses TE to process the request, and sees that the first chunk of data is 8 bytes long. Then it sends this request to the backend, which uses CL. The back-end sees that the request body is 3 bytes long, which **is the newline and 8 character.** Then, the following bytes starting with the 'hello' portion is left unprocessed and the back-end server prepends this to the next request.

Finding this would require us to send this:

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

Same expected success reponse as earlier, we would want to test for either **time differences or an error response.**&#x20;

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

Depending on how the website processes information, the rest of the attack takes the same form as the CL.TE or TE.CL exploits.&#x20;

## Useful Tools

When exploiting this, I tend to use a script that crafts the request automatically for me before I proceed. This is because counting the letters is very time-consuming.

{% embed url="https://github.com/kleiton0x00/HTTP-Smuggling-Calculator" %}

I use this tool above mainly for CTFs and HTB. **Take note that the tool above does not work with HTTPS, only HTTP.** Other tools include:

{% embed url="https://github.com/ariary/HTTPCustomHouse" %}

On top of that, I just use HackTricks for whatever other information that I need.&#x20;

{% embed url="https://book.hacktricks.xyz/pentesting-web/http-request-smuggling" %}
