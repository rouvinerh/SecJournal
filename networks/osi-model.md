# OSI Model

The Open Systems Interconnection (OSI) Model is a logical model that is used to represent the data that flows from our computer to another computer. This is commonly used to troubleshoot network issues and is a very useful tool in understanding how networks pack and unpack data.

The OSI Model is structured in 7 layers as shown below:

<figure><img src="../.gitbook/assets/image (2839).png" alt=""><figcaption></figcaption></figure>

When traffic is routed from our computer to another device, it is first 'packed' from Layer 7 down to Layer 1 from the sender, and then flows from Layer 1 to Layer 7 on the recipient's machine. Each layer of the model would sometimes add headers to the packet about the sender and recipient.

There are 3 sections of the OSI Model:

* Hardware Layers
  * Physical
  * Data Link
  * Network
* Transport - Heart of OSI
* Software Layers
  * Session
  * Presentation
  * Application

Each layer has their own data format of which they transfer information, and it varies from layer to layer.

## Physical

The Physical layer represents the actual physical connection between machines that transmits data. This can refer to the copper or fiber optic wires that used to transmit information in the form of **bits**. This layer would transfer stuff in 1s and 0s for Layer 2 to put back together.

Examples of Physical Layer devices are:

* Copper wiring
* Shielded Twisted Pair cables
* RJ-45 Connectors&#x20;

## Data Link

The Data Link layer is responsible for the node-to-node delivery of the message. The main function of this layer is to ensure that the data transfer occurs without error when going from one node to another through the Physical Layer. When a packet arrives in a network, the Data Link Layer would transmit it to the Host using its MAC address.

This layer can thus be sub-divided into 2 sub-layers:

* Logical Link Control&#x20;
* Media Access Control

The packet received is **divided into frames,** which is the main medium of transfer in this layer. This layer would encapsulate the Sender and Receiver's MAC address into the packet header.&#x20;

Layer 2 technologies include:

* Switches
* MAC Addresses
* Address Resolution Protocol (ARP)

ARP is a protocol that is used to link IP addresses with MAC addresses (see Packets). As such, the main purpose of this layer is **framing and adding physical addresses for the frames.**

## Network

The Network layer is in charge fo transmission of data from one host to another host that exists in a different network. This takes cares of the routing needed to move the packets to their destination. It's also in charge of moving identifying unique devices that are on the network.&#x20;

The IP addresses of the sender and recipient are added on the packet header. These addresses would distinguish devices.

Layer 3 Technologies include:

* Routers
* IP addresses
* Routing protocols, like OSPF and EIGRP
* Ping Packets / ICMP
* VPN and IPSec

The main data being transmitted here is called **packets**.&#x20;

## Transport

This layer is sort of the bridge builder of the layers. This layer is in charge of:

* End-to-end delivery of the message
* Providing acknowledgement on receiving the data
* Re-transmits data if there are errors found
* Establish data tunnels using Transport Layer Security (TLS) or Secure Sockets Layer (SSL) if needed&#x20;

The port numbers are also read by this layer and data is transmitted to the port needed. These can be configured manually or set by default. For example, SSH traffic goes via port 22 by default, and most other applications have their own default port. The data transmitted in this layer are called **segments**. One thing to note is that this layer is part of the OS and works with the Application Layer through making system calls.&#x20;

Common protocols that exist at this layer are:

* TLS / SSL (see Packets)
* TCP / UDP (see Packets)

## Session

This layer is in charge of the establishment of connection, maintenance of sessions, authenticating devices and security.

Session establishment allows for two devices to establish a connection, send whatever data is required through that connection and then terminate it. It can add checkpoints throughout the data transmission to make sure that the data is sent without data loss.&#x20;

## Presentation

This layer can also be called the Translation Layer. The data from the Application Layer is extracted here and manipulated into the format required to transmit over the network.

This means this layer is in charge of:

* Encryption or decryption of data&#x20;
* Compressing and packing data into a set number of bytes before sending
* Translating data, such as translating ASCII characters to hex, for example.

## Application

Lastly, this layer is in charge of producing the data that is to be transferred over the network. For example, this could be one's browser, which would generate requests and also display the output of reponses in a human-readable format.&#x20;

Think about this layer as the actual Application itself, such as a browser, or a computer game.&#x20;

## Summary

<figure><img src="../.gitbook/assets/image (1474).png" alt=""><figcaption></figcaption></figure>

The OSI Model is extremely useful in troubleshooting. For example, if we have a malfunctioning router, we can check each layer, starting from the physical device, and then the ARP cache and go up the layers until we have identified and isolated the problem to fix.

Take note that the technologies in the layers do not understand the layer above it. Meaning, switches, which exist in Layer 2, are basically completely unaware of IP addresses, which live in Layer 3 (unless we configure a Layer 3 switch).&#x20;
