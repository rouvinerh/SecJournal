# Networking

Computer networks are basically interconnected devices that can exchange information and send data to one another using a set of communication protocols. The transferring of information can be done either physically through wire, or wirelessly.&#x20;

Networking is an indispensable asset for security, and InfoSec people must understand this pretty well. Plus, it's quite interesting and fun as well. Learning how things like the OSI model and routers work is essential for exploitation.&#x20;

The knowledge here is based off on the Cisco Certified Network Associate (CCNA) exam, which I found really enjoyable to learn from. Not all the topics would be covered, like Hot Standy Router Protocol (HSRP), but rather the core fundamentals.

I've heard the stuff covered in CCNA is similar to CS2105, Introduction to Computer Networks minus all the proprietary technlogies.&#x20;

If you want to go for the CCNA course or learn more, I **highly recommend Neil Anderson's Udemy CCNA Course.** He explains the topics really well, and it comes with some hands-on labs to test your concepts! Networking can be a bit dry, but he makes it really interesting.

{% embed url="https://www.udemy.com/course/ccna-complete/" %}

## Terminologies

There are a few terms that are used, and I will attempt to explain what they are.&#x20;

### Routers

<figure><img src="../.gitbook/assets/image (2759).png" alt=""><figcaption><p>Routers</p></figcaption></figure>

I think most of us have seen this and are aware of what it is. Routers route traffic between networks.&#x20;

### NIC

Within each device, there exists something called a Network Interface Card (NIC), which basically Wifi-enables a device. This allows for the reception of network signals and protocols.

### Switches

<figure><img src="../.gitbook/assets/image (2182).png" alt=""><figcaption><p>Switches</p></figcaption></figure>

These are devices that basically connect different machines together via a cable, most commonly Ethernet. They have loads of ports for this purpose, and are generally the "middleman" in data transmissions. Here's an example of a network topology for switches:

<figure><img src="../.gitbook/assets/image (3367).png" alt=""><figcaption></figcaption></figure>

### Firewalls

These look like switches, but they aren't.

<figure><img src="../.gitbook/assets/image (3719).png" alt=""><figcaption><p>Cisco Firewall</p></figcaption></figure>

### Network Topologies

<figure><img src="../.gitbook/assets/image (3728).png" alt=""><figcaption></figcaption></figure>

This is how we represent networks in a company, sort of like a graph of nodes that have connections to one another. Take note of the symbols used!

### Ports

Think of them like the destinations for packets to get to. These **are not phyiscal ports on the device**, but rather are logical things. Logical in this case measn that they exist within the computer only.

There are 65535 ports in total, and any of them can be open and listening. There are default ports for certain services, as shown here:

<figure><img src="../.gitbook/assets/image (2499).png" alt=""><figcaption></figcaption></figure>

There's no need to memorize all 65535 ports, but knowing a few is good enough.
