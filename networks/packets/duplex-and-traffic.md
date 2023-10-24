# Duplex & Traffic

There are few terms used for different types of traffic and messages in networking. Some of them are covered here.

## Duplex

### Half-Duplex

In a half-duplex system, hosts can communicate with each other, but not at the same time.&#x20;

<figure><img src="../../.gitbook/assets/image (2077).png" alt=""><figcaption></figcaption></figure>

This means that hosts have to wait for each other to finish sending traffic before being able to send traffic over. This is really slow, and half-duplex systems are generally used to conserve **bandwidth**.&#x20;

Some examples of half-duplex systems are:

* Walkie-Talkies
* Two-way radio that has push-to-talk buttons
* USB
* Browsing the Internet (requests and responses)

### Full-Duplex

As the name implies, this is the same as half-duplex, but hosts can communicate with each other simultaneously. Bidirectional transmissions make networks a lot faster at the cost of bandwidth. Full-duplex systems include:

* Voice or Video calls
* Chat rooms
* Remote Desktop Protocol

### Simplex

Simplex systems are unidirectional, meaning that only one of the devices can transmit data, and the other one can only receive. These systems are useful for networks that don't need to have active receivers on one end and just need to transmit data. Some examples of simplex systems are:

* Megaphones
* Keyboards
* Television and remote
* Communications between computers and printers.

## Traffic Types

Regarding traffic types, the CCNA covered a few in basic-depth

### Unicast

Unicast traffic is used to send traffic to a single destination host. This means that within the packet headers, there is a specific receiver IP address (that is not the broadcast address) and the packet will go there.

<figure><img src="../../.gitbook/assets/image (1500).png" alt=""><figcaption></figcaption></figure>

Unicast can also be sent to multiple hosts. However, this is rather inefficient in terms of bandwidth. Let's say we want to send 3 hosts the same packet of 1kb. If we use unicast, we would need to send 3 copies out, amounting to 3kb in total.&#x20;

Multicast solves this problem by only requiring one copy to be sent out, using only 1kb of traffic.

<figure><img src="../../.gitbook/assets/image (4066).png" alt=""><figcaption></figcaption></figure>

### Multicast

This method is how we sent one copy that goes to multiple different destinations. The sender would send one copy of data, and then that one copy is sent out to all interested receivers.

Multicast traffic is targeted. Hosts have to specifically request for the traffic to get it.

<figure><img src="../../.gitbook/assets/image (2641).png" alt=""><figcaption></figcaption></figure>

### Broadcast

Broadcast traffic is where one copy of traffic would come into the switch and get flooded out all other ports but the receiving port on that part of the network. It goes to all the different hosts connected to that switch, and only one copy is sent everywhere.

What's important to note here is that **switches flood broadcast traffic, whereas routers do not send them at all and discard the packet**. When the broadcast traffic hits the router, it will just drop it as routers are configured not to forward all broadcast traffic.&#x20;

Logically speaking, if routers flooded broadcast traffic, then the Internet would be really slow and completely swarmed with these packets.

<figure><img src="../../.gitbook/assets/image (440).png" alt=""><figcaption></figcaption></figure>
