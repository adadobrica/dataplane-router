Copyright: Dobrica Nicoleta-Adriana 321CA

# Dataplane Router

## Description

This homework implements the dataplane component of a router, which consists of the forwarding process. The router intercepts packets from each one of its interfaces and forwards them accordingly.

## IP

> Note: there were some entries in the routing table that were never going to
be used (if the prefix & mask != prefix), so I filtered the routing table to skip over the unused entries.

- When the router receives an IP message, the packet has to be checked for integrity first.

- The first step is verifying the checksum of the packet. The router recalculates the checksum of the IP header and if it doesn't match with the actual checksum, then the packet contains erronated information, so it gets dropped.


- After the checksum has been verified, the router checks the TTL field (time to live) of the IP header. The packet gets dropped if its TTL is smaller than or equal to 1, and the router sends an ICMP packet back.


- Afterwards, the router checks if the destination is the router, or if it has to forward it.


- If the packet is for the router, then it means we have an **ICMP Echo Request packet (ping)**. In this case, the router creates another ICMP packet **(echo reply)**, and sends it back to the host source that sent the echo request message.

- If the packet is not for the router, then it has to forward it to its destination. To do so, we need to update the L2 header of the packet (decrementing the TTL and recalculate the checksum), and to find the best route for the packet to get to its destination. If there is no such route, then the router sends an **ICMP destination unreachable packet**. Otherwise, the router knows where to forward the packet next, but it needs to know the MAC address of the next hop for the packet; if there are no available MAC addresses in the ARP cache for the router, then it will send an ARP packet request, otherwise it simply sends the packet to the next hop.


## ICMP

- There are three possible cases for the router to send an ICMP packet: if we have
**timeout**, **destination unreachable** or **echo reply**.

- An ICMP packet has the following structure: an ethernet header, an ip header and an icmp header.

> **Timeout and destination unreachable**: these cases are for error ICMP packets, where the ICMP header of the packet the router will send will contain certain data: the header of the old IP header (the discarded one) and the first 64 bits of the entire packet.

> **Echo reply & echo request**: normal ICMP message, doesn't need to have the old IP header and the first 64 bits of the payload

## ARP

- **ARP REPLY**: If the router gets an ARP reply packet, then the sender IP address and the sender MAC address will be added to the router's local cache. Then, the router checks the waiting packets (which are in a queue), and forwards the packets with the known MAC address of the next hop. 

- **ARP REQUEST**: If a router gets an ARP request packet, then it means that a host wants to know the router's MAC address. In response to it, the router sends an ARP reply packet.

- **ARP REQUEST BROADCAST**: if the MAC address of the next hop for the router is not known, then the router sends an ARP request packet on the interface of the best route to find the corresponding MAC address.