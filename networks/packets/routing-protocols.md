# Routing Protocols

Routing Protocols are used for packets to find their way around a network, and to also take the most efficient path there based on something called **cost** or **metric,** depending on the protocol used. These protocols send information about the path finding, which is stored in the **routing tables of routers.** This is a small database to let the router remember which route to take for certain destinations.&#x20;

There are loads of protocols, and the ones covered in the CCNA are RIP, RIPv2, IGRP, EIGRP, IS-IS and BGP. We only need to know how to configure RIP, RIPv2, EIGRP and OSPF. I won't be going in-depth for IS-IS and BGP.

There are 2 types of routing protocols, namely **distance vector** (RIP, IGRP) and **link state (**OSPF, IS-IS). EIGRP is considered an advanced distance vector protocol, and is a Cisco Proprietary protocol, meaning that only Cisco devices can use this.&#x20;

The routing protocols mentioned above are all interior routing protocols, meaning they are used to exchange information and send packets within one system, such as a LAN. External routing protocols are used to exchange information between multiple systems, and are used to route information across the Internet.

Configuration of these protocols is not covered here, but rather just the concepts of routing.

## Distance Vector&#x20;

Routers that use this protocol do not possess topological information about the network, but rather rely on the neighbours information. Everytime a new connection is made to a new router on one side, the new router would start to send information about the network on the other side. Specifically, they would send their routing table to other routers on the network.&#x20;

The name is derived from how the routes are advertised as vectors of distance, where distance is defined in terms of **metric** or cost. They would use a **hop count** to determine which path is the optimal one to take.&#x20;

Distance Vector protocols are generally used on smaller networks where there are few routers. However, it has issues with scalability as it struggles to provide the services required.&#x20;

### RIP / RIPv2

RIP is one of the oldest routing protocols. It is easy to configure and maintain, but lacks a lot of advanced features that the newer protocols have. The main thing that RIP uses hop count as a metric. Hop count is basically the number of devices that the traffic passes by when it travels to its host.&#x20;

<figure><img src="../../.gitbook/assets/image (1764).png" alt=""><figcaption></figcaption></figure>

Take note that for RIP, the defualt maximum hop count is 15, and any route with a higher hop count is considered unreachable.&#x20;

The difference between RIP and RIPv2 is that RIPv2 is capable of advertising subnet masks and uses multicast to send routing updates, while version 1 doesn't advertise subnet masks and uses **broadcast** for updates. Version 2 is backwards compatible with version 1. RIPv2 also sends the entire routing table every 30 seconds to other routers to ensure they are up to date. This can take up a lot of bandwidth on the network, which is why RIP isn't too popular.&#x20;

We can analyse how RIP works using this topology:

<figure><img src="../../.gitbook/assets/image (321).png" alt=""><figcaption></figcaption></figure>

R1 connects directly to another subnet, and RIP has been configured. R1 would send routing updates to R2 and R3, and the routing updates list the subnet, subnet mask and hop count (metric) for this route. Each router would receive this update and add to their routing tables. In this case, both routers would have a metric of 1 because they are one hop away.

So RIP calculates the path with the least hop count from point A to point B, and then just uses that path for packets to travel. There are some limitations to this, however. One is the failure to consider the bandwidth of a specific route. For example, a route with a hop count of 5 with an average bandwidth of 100Mbps is a lot faster than another route with a hop count of 4 with an average bandwidth of 10Mbps. RIP would choose the route with a hop count of 4!

### IGRP

IGRP is an advanced distance vector protocol. There are a few features that distinguish it from RIP, namely the improved scalability and improved routing.

Earlier I mentioned that RIP has a max hop count of 15. In IGRP, this maximum is 100 by default. The metric that IGRP uses is also not solely based on hop count, and internetwork delay and bandwidth are used to arrive at a composite metric. Reliability, load and MTU can also be included.

IGRP can maintain up to 6 unequal cost paths between one source and one destination, but only the route with the lowest metric is in the routing table. RIP on the other hand, keeps one and disregards the rest.&#x20;

IGRP is sort of like advanced RIP that takes more into consideration when determining the route for traffic to take in larger networks.&#x20;

## Link State Protocols

These protocols serve the same purpose as distance vector protocols, but they do it in a different manner. Earlier, I mentioned that Distance Vector Protocols make routers send their routing table around. Link state protocols to not do so, but instead they would 'advertise' their information about a network topology, such as directly connected hosts or routers. This would ensure that the routers in this system all have the same topology database.&#x20;

These protocols converge a lot faster (meaning all routers are on same page faster) and send updates using multicast addresses. They also require more CPU and RAM usage and can be significantly harder to configure.

### OSPF

OSPF is a non-proprietary routing protocols (which means any brand router can run it, not just Cisco). In general, OSPF relies on 3 tables:

* Neighbour Table
  * Table of other routers that are running the same routing protocol.&#x20;
* Topology Table
  * Stores information about the topology of the entire network using routing by rumour
* Routing Table
  * Stores the best routes for each path

#### OSPF Neighbours

OSPF establish relationships with neighbours before they start exchanging routing updates. OSPF neighbours are dynamically discovered by sending Hello packets out reach OSPF-enabled interface on a router. **OSPF Hello packets** are sent between each router to establish a relationship, and take note that ther router needs to be OSPF enabled first. OSPF sends these packets ia multicast to 224.0.0.5 or 224.0.0.6 for routing updates.&#x20;

Each router is assigned a router ID by OSPF, and the router ID is determined from the following:

* Manually set IDs
* Highest IP address of the router's loopback interfaces
* Highest IP address of the router's physical addresses

The following fields in Hello packets **need to be the same for routers to become neighbours, else the routers will disregard the packet.**

* Subnet
* Area ID
* Hello and Dead Interval Timers
* Authentication
* Area Stub Flag
* Maximum Transmission Unit (how often routing updates are sent)

By default, OSPF protocols would cause routers to send hello packets every 10 seconds on an Ethernet network**.** This time is known as the Hello Interval. A Dead Interval would be 4 times the value of the Hello Interval by default. If a router does not receive another OSPF Hello packet for 40 seconds, then the router declares that neighbour to be down and does not send packets there.

#### OSPF Neighbour States

Before establishing a neighbour relationship, OSPF routers have several state changes to go through. (This is summarised)

1. Init State - Received a hello packet from another OSPF enabled router.
2. 2 - Way state - Router has replied with a Hello packet of its own.
3. Exstart state - Beginning to send link state information to one another.
4. Exchange State - Checking which information needs to be sent to one another.
5. Loading State - Both would request and receive information that is needed / missing from their tables
6. Full state - Both routers have a fully synced database and are now neighbours!

#### OSPF Areas

OSPF uses 'areas' to send information. This idea was used because, not every single router needs to know about the entire network. This would cause the network to be a lot slower due to the memory and CPU usage demanded.&#x20;

As such, I like to think that OSPF appoints an 'area in-charge' router that is in charge of linking areas together. This router is normally the newest or fastest router within a specified area, that would be responsible for updataing information between areas as required. This way, older routers don't need to process so much data. We can visualise areas using this:

<figure><img src="../../.gitbook/assets/image (1521).png" alt=""><figcaption></figcaption></figure>

So within Area 0, which is known as the backbone area, we can see that R3 is in charge of ensuring that updates are sent between the Areas. R3 is called the **Area Border Router** (basically the router IC!) as it is present in two areas simultaneously.&#x20;

Routing information is localized, meaning if R5 fails, then R4 will update R3 and other routers within Area 1 accordingly. Area 0 would be unaware of R5's existence, so they won't care or need to be updated anyway. This area routing saves a lot of overhead.&#x20;

#### OSPF Cost and Path Finding

After forming all the relationships and stuff, routers are basically aware of the entire topology and bandwidth of the network. Then this is a travelling salesman problem!&#x20;

OSPF uses SPF or Djikstra's Algorithm to find the shortest path between each node. If you know graph theory, you would be familiar with how this works.

{% embed url="https://www.geeksforgeeks.org/dijkstras-shortest-path-algorithm-greedy-algo-7/" %}

The intricacies of Djikstra's Algorithm is not covered within CCNA. Anyways, the cost of each route is indeed calculated before forming the final graph and sending traffic in that manner. OSPF relies on costs that are inversely proportional to the bandwidth of the link, and naturally higher bandwidth routes are preferred.&#x20;

These are the default Cost values for each interface:

| Gigabit Ethernet Interface (1 Gbps) | 1   |
| ----------------------------------- | --- |
| Fast Ethernet Interface (100 Mbps)  | 1   |
| Ethernet Interface (10 Mbps)        | 10  |
| DS1 (1.544 Mbps)                    | 64  |
| DSL (768 Kbps)                      | 133 |

The Cost Formula would be the reference bandwidth divided by the interface bandwidth. **The default reference bandwidth is 100Mbps for OSPF cost calculation**.&#x20;

### EIGRP

So EIGRP is a Cisco Proprietary protocol, and it functions similar to that of OSPF, which is the open stadard implementation. It uses same tables, and also routes via forming neighbour relationships within routers, btu there is a slight difference in how it forms neighbours.

#### EIGRP Neighbours and Cost

EIGRP neighbours would need to send hello packets to one another every so often. The following values need to be the same for routers to become neighbours:

* ASN (Autonomous System Number)
* Subnet Number
* K values (part of the path metric, AKA cost of path)&#x20;

We will often see these two terms for EIGRP routing

* Feasible Distance (FD) - The metric of the best route to reach a network.
* Reported Distance (RD) - Metric advertised by a neighbouring router for a specific route.

To visualise, we can use this:

<figure><img src="../../.gitbook/assets/image (3475).png" alt=""><figcaption></figcaption></figure>

Take note that EIGRP has been configured on both of these networks. So R1 would see that the RD is 28160 to the host. The FD would be 30720, which is the actual distance between the paths.&#x20;

The cost calculation for EIGRP is quite different from OSPF:

EIGRP Metric = 256\*((K1_Bandwidth) + (K2_Bandwidth)/(256-Load) + K3_Delay)_(K5/(Reliability + K4)))

This formula can be reduced to:

**EIGRP Metric = 256\*(Bandwidth + Delay)**

I believe CCNA has removed this from the syllabus, so I won't be going in-depth.&#x20;
