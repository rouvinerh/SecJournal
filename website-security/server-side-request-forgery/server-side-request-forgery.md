---
description: 127.0.0.1
---

# Server-Side Request Forgery

Server-Side Request Forgery (SSRF), as the name suggests, allows for an attacker to make a server send requests **on the attacker's behalf**.

## Basic SSRF

When testing, if I find a functionality within a website that has the ability to send requests to **user-controlled URLs**, I always test it by sending requests to my controlled server. This can be used to retrieve sensitive information from the internal network, since it can be used to bypass firewalls and access other objects within that internal network.

Suppose that a website has a URL requesting functionality and a hidden directory under the `/admin` directory that only allows for **local** accesses. This can be bypassed using:

```bash
http://example.com?url=http://127.0.0.1/admin
```

Alternatively, modified HTTP headers, like `X-Forwarded-For` can be used too.

SSRF is not limited to the `http://` wrapper. One can even combine wrappers like `php://` and `gopher://` to retrieve encoded file data.