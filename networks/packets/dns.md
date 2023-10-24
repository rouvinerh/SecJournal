---
description: The phonebook of the Internet
---

# DNS

## Domain Name System

DNS, otherwise known as Domain Name Resolution, is a protocol that is used to resolve IP addresses to domains and vice versa. This protocol serves as the phonebook of the Internet, basically telling our computers where everything is online. This is a Layer 7 Protocol, alongisde with HTTP, SMTP and POP3.&#x20;

When we search for google.com, our computer doesn't actually know where this domain is located on the Internet. So, instead, it would go to a DNS Server and it would tell us where it is.

> There isn't just 'one' DNS server. There are many layers of it, with some DNS servers being our at our Internet Service Provider (ISP). &#x20;

Websites depend on something called the Fully Qualified Domain Name (FQDN). This is a domain anme htat specifies its exact location in the tree for DNS. It specifies all the different levels, including the top-level domain and the root zone. For example, nus.edu.sg is a FQDN, and within it, there contains comp.nus.edu.sg, vafs.nus.edu.sg and so on.&#x20;

We can take a look at a packet capture portion for DNS using Wireshark. I made a request to github.com here:

<figure><img src="../../.gitbook/assets/image (3314).png" alt=""><figcaption></figcaption></figure>

We can see that our device (192.168.52.134) is first making a request to github.com via a 'standard query'. Then, the standard query response would be telling us the IP address of github.com, AKA where it is.&#x20;

From analysing such packet captures, we are also able to sometimes spot hidden directories or servers located within the network, and we can also leverage certain DNS misconfigurations to do DNS Zone Transfer Attacks.
