# ARP

Address Resolution Protocol (ARP) is a protocol that is used to resolve MAC addresses to IP addresses. In essence, it ties Layers 2 and 3 of the OSI Model together.&#x20;

As mentioned, every single device has a unique MAC address and without it, the device cannot really function. How ARP makes use of that is through a table.

<figure><img src="../../.gitbook/assets/image (3051).png" alt=""><figcaption><p>ARP Table</p></figcaption></figure>

We can see from my device, that there are a few IP addresses tied to MAC addresses, also known as physical addresses.&#x20;

When an unknown device communicates with my device, my device initially does not know what the IP address of this is. It's only when the packets are unpacked through the OSI Model that we get to find out the MAC address and IP address of this unknown host, and it is added to the ARP table.

ARP traffic exists as broadcast traffic, which basically floods everywhere (for switches). The conversaion generally goes like this:

* Client: Who is 192.168.123.45? Tell \<my IP>.
* Reply: 192.168.123.45 is at \<MAC Address>

This request is generally done once only to add the entry to the table. Now, take note that ARP requests are **broadcast traffic**. This means that they are not broadcasted by routers (unless specified through helper addresses), but switches would flood all ports except the receiving port to check on all devices. Devices that are not involved would discard this packet.
