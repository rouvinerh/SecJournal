# TCP / UDP

Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) are protocols that are used to dictate **how a packet is sent to its destination.**&#x20;

TCP and UDP are completely different, and their use cases vary. TCP is a connection-oriented protocol, whereas UDP is a connectionless protocol.

## TCP

TCP has the following headers:

<figure><img src="../../.gitbook/assets/image (3931).png" alt=""><figcaption></figcaption></figure>

The TCP headers contain all the information that the packet being sent out has. Take note that the TCP header is a lot larger than the UDP header.

The header is larger because TCP is connection-oriented, meaning that it is the more 'accurate' protocol. Here are some functions of the headers:

* Sequence and Acknowledgement number
  * Ensures that the data is sent in order
* Control Flags
  * Denotes what kind of packet is being sent (SYN, ACK etc.)

TCP sends packets in a stream, where they are received in sequential order. If a packet is dropped somewhere, then there would be a re-transmission of this lost packet. This ensures that **all the information is transmitted.** This is important for certain services, such as online banking, where accuracy is key.&#x20;

However, TCP is a lot slower because of the additional checks for accuracy and not prioritising speed.&#x20;

### 3 - Way Handshake

TCP communicates with hosts using something called the 3-way handshake. This handshake helps to establish a solid connection between the host and recipient.&#x20;

<figure><img src="../../.gitbook/assets/image (2005).png" alt=""><figcaption></figcaption></figure>

I generally like to think of the conversation like this:

* Client: Hello Server, may I send you information? (SYN)
* Server: Hello Client, I acknowledge your request and I am ready (SYN + ACK)
* Client: Hello Server, I acknowledge you are ready, here comes the information (ACK)

This is generally how the handshake works. All TCP connections are initiated in this manner. For TCP packets, they have multiple different states used here, each denoted by the **9 bits representing the Control Flags.** Each bit of the Control Flag represents a certain type of packet. For example, if the packet is a SYN + ACK packet, then it would have 1s in the control flag part for SYN and ACK, and 0s for the rest.

The establishment of this handshake ensures that the connection is stable and accurate.

## UDP

While TCP prioritises accuracy, UDP is like the opposite. UDP is what I like to call 'best-effort'. UDP headers are like so:

<figure><img src="../../.gitbook/assets/image (2518).png" alt=""><figcaption></figcaption></figure>

We can see how UDP headers are typically about 8 bytes long, whereas TCP headers are 20-60 bytes long. This is because UDP does not have the retransmission property of TCP, and it just sends the data, hoping it gets there. Packets that are dropped are not cared about at all.

UDP also does not make use of any handshake, it just sends the data, making it a **connectionless protocol**. The data sent is also not in sequential order.&#x20;

Because of having lesser checks and stuff, UDP is a lot faster than TCP in transmitting data, and is used when accuracy is less important than speed. One example of UDP traffic is when we are streaming videos. Having a few packets dropped for videos is not detectable by us, and the speed of which UDP transmit at helps keep the video playing continuous.&#x20;

## Summary

In short, TCP is sort of like a sniper rifle, a lot slowerb also accurate. UDP is like a machine gun, less accurate but fires a lot faster. TCP also transmits data in order, while UDP just shoots data out and hope that majority gets there.&#x20;
