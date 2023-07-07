#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROUTE_ENTRIES 	100000
#define ETHERTYPE_ARP		0x0806
#define ETHERTYPE_IP		0x0800
#define ECHO_REPLY			0
#define DEST_UNREACHABLE 	3
#define TIMEOUT				11
#define MAX_ARP_ENTRIES		100
#define ARP_REQUEST			1
#define ARP_REPLY			2

struct route_table_entry *rtable;
int rtable_len;

struct route_table_entry *rtable_filtered;
int rtable_filtered_len;

struct arp_entry *arp_table;
int arp_table_len;

/** structure that contains our queue for the entries, the router's local cache
 *  and their sizes **/

struct cache {
	queue cache_queue;
	struct arp_entry *entries;
	size_t len;
	size_t arp_len;
};

/** comparator function for sorting the entries before using binary search  */


int cmp(const void* a, const void* b) {

	const struct route_table_entry *o1 = (const struct route_table_entry*)a;
	const struct route_table_entry *o2 = (const struct route_table_entry*)b;

 	if (ntohl(o1->prefix) > ntohl(o2->prefix)) {
 		return 1;
 	} else if (ntohl(o1->prefix) < ntohl(o2->prefix)) {
 		return -1;
 	}

 	return ntohl(o1->mask) - ntohl(o2->mask);
}

/** finding the best route for the ip destination using binary search */


struct route_table_entry *get_best_route(uint32_t ip_dest) {

	struct route_table_entry *max_mask = NULL;
	int left = 0, right = rtable_filtered_len - 1;

	while (left <= right) {
		int mid = left + (right - left) / 2;

		if (ntohl(ip_dest & rtable_filtered[mid].mask) == ntohl(rtable_filtered[mid].prefix & rtable_filtered[mid].mask)) {
			if (max_mask == NULL || rtable_filtered[mid].mask > max_mask->mask) {
				max_mask = &rtable_filtered[mid];
			}
			left = mid + 1;
		} else if (ntohl(ip_dest & rtable_filtered[mid].mask) < ntohl(rtable_filtered[mid].prefix & rtable_filtered[mid].mask)) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}
    
    return max_mask;
}

struct arp_entry *get_mac_entry(uint32_t given_ip, struct cache* local_cache) {
	for (int i = 0; i < local_cache->arp_len; ++i) {
		if (local_cache->entries[i].ip == given_ip) {
			return &local_cache->entries[i];
		}
	}
	return NULL;
}

/** function that creates and initializes an ethernet header */

struct ether_header *init_eth(uint16_t type, uint8_t dmac[6], uint8_t smac[6]) {
	struct ether_header *eth = malloc(sizeof(struct ether_header));
	eth->ether_type = htons(type);
	memcpy(eth->ether_dhost, dmac, 6 * sizeof(char));
	memcpy(eth->ether_shost, smac, 6 * sizeof(char));
	return eth;	
}

/** function that creates and initializes an icmp header */

struct icmphdr *init_icmp(uint8_t type, uint8_t code, uint16_t id, uint16_t sequence) {
	struct icmphdr *icmp = malloc(sizeof(struct icmphdr));
	icmp->type = type;
	icmp->code = code;
	icmp->un.echo.sequence = sequence;
	icmp->un.echo.id = id;
	icmp->checksum = 0;
	icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(struct icmphdr)));

	return icmp;
}

/** function that creates and initalizes an ip header */

struct iphdr* init_ip(uint8_t ihl, uint8_t version, uint32_t daddr, uint32_t saddr) {
	struct iphdr *ip_hdr = malloc(sizeof(struct iphdr));
	ip_hdr->tos = 0;
	ip_hdr->ihl = ihl;
	ip_hdr->version = version;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = htons(64);
	ip_hdr->check = 0;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->saddr = saddr;
	ip_hdr->daddr = daddr;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	return ip_hdr;

}

/** this function creates a new icmp packet for the router to send */ 

void send_icmp_packet(int interface, int is_error, struct ether_header* old_eth_hdr, struct iphdr* old_ip_hdr,
				struct icmphdr* old_icmp_hdr, uint8_t type, uint8_t code, char* router_packet) {
	uint8_t dmac[6], smac[6];
	memcpy(dmac, old_eth_hdr->ether_dhost, 6 * sizeof(char));
	memcpy(smac, old_eth_hdr->ether_shost, 6 * sizeof(char));

	char new_packet[MAX_PACKET_LEN];
	size_t eth_hdr_len = sizeof(struct ether_header);
	size_t icmp_len = sizeof(struct icmphdr);
	size_t ip_hdr_len = sizeof(struct iphdr);
	size_t new_packet_len = eth_hdr_len + icmp_len + ip_hdr_len;

	struct ether_header *new_eth = init_eth(ETHERTYPE_IP, smac, dmac);

	struct icmphdr* icmp_hdr = init_icmp(type, code, 0, 0);

	struct iphdr* new_iphdr = init_ip(old_ip_hdr->ihl, old_ip_hdr->version, old_ip_hdr->saddr, old_ip_hdr->daddr);

	// if we have destination unreachable or timeout, then we have to add extra data to our packet

	if (is_error == 1) {
		memcpy(new_packet, new_eth, sizeof(struct ether_header));
		memcpy(new_packet + eth_hdr_len, new_iphdr, sizeof(struct iphdr));
		memcpy(new_packet + eth_hdr_len + ip_hdr_len, icmp_hdr, sizeof(struct icmphdr));
		memcpy(new_packet + new_packet_len, router_packet, 8);
		new_packet_len += 8;
	} else if (is_error == 0) {
		icmp_hdr->un.echo.sequence = old_icmp_hdr->un.echo.sequence;
		icmp_hdr->un.echo.id = old_icmp_hdr->un.echo.sequence;

		memcpy(new_packet, new_eth, sizeof(struct ether_header));
		memcpy(new_packet + eth_hdr_len, new_iphdr, sizeof(struct iphdr));
		memcpy(new_packet + eth_hdr_len + ip_hdr_len, icmp_hdr, sizeof(struct icmphdr));
	}
	send_to_link(interface, new_packet, new_packet_len);
}

/** function that initalizes the router cache */

struct cache* init_cache() {
	struct cache *c = malloc(sizeof(struct cache));
	c->entries = malloc(sizeof(struct arp_entry) * MAX_ARP_ENTRIES);
	c->cache_queue = queue_create();
	c->len = 0;
	c->arp_len = 0;
	return c;
}

/** this function adds a new arp entry in the local cache, which consists of ip and mac addresses */

void add_entry_in_cache(uint8_t mac_addr[6], uint32_t ip_addr, struct cache* local_cache) {
	struct arp_entry new_entry;
	new_entry.ip = ip_addr;
	memcpy(new_entry.mac, mac_addr, 6 * sizeof(char));
	local_cache->entries[local_cache->arp_len++] = new_entry;
}

/** this structure is used when enqueuing or dequeuing our packets, since we need to know
 * the packet's length before sending it */

struct packet {
	char *content;
	size_t len;
};

/** function that sends an arp broadcast packet */

void send_arp_broadcast(struct route_table_entry *best_route, char* buf, size_t len, struct ether_header* eth_hdr,
						struct cache* cache_table) {
	struct packet *buf_packet = malloc(sizeof(struct packet));
	buf_packet->content = malloc(len * sizeof(char));
	buf_packet->len = len;
	memcpy(buf_packet->content, buf, len);

	queue_enq(cache_table->cache_queue, &buf_packet);
	cache_table->len++;

	char broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	memcpy(eth_hdr->ether_dhost, broadcast, 6 * sizeof(char));

	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	char new_arp_packet[MAX_PACKET_LEN];
	size_t arp_packet_len = sizeof(struct ether_header) + sizeof(struct arp_header);

	memcpy(new_arp_packet, eth_hdr, sizeof(struct ether_header));

	struct arp_header new_arp_hdr;
	new_arp_hdr.htype = htons(1);
	new_arp_hdr.ptype = htons(ETHERTYPE_IP);
	new_arp_hdr.hlen = 6;
	new_arp_hdr.plen = 4;
	new_arp_hdr.op = htons(ARP_REQUEST);
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	memcpy(new_arp_hdr.sha, eth_hdr->ether_shost, 6 * sizeof(char));
	new_arp_hdr.spa = inet_addr(get_interface_ip(best_route->interface));
	memset(new_arp_hdr.tha, 0, 6 * sizeof(char));
	new_arp_hdr.tpa = best_route->next_hop;

	memcpy(new_arp_packet + sizeof(struct ether_header), &new_arp_hdr, sizeof(struct arp_header));

	send_to_link(best_route->interface, new_arp_packet, arp_packet_len);
}

/** the handler for the ip packets */

void ipv4_handler(char *buf, size_t len, int interface, struct ether_header* eth_hdr, struct cache* cache_table) {
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *r_icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	uint16_t old_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	char *router_packet = (char *) malloc(sizeof(struct iphdr) + 8);
	memcpy(router_packet, ip_hdr, sizeof(struct iphdr));
	memcpy(router_packet + sizeof(struct iphdr), buf, 8);


	if (new_checksum != old_checksum) {
		return;
	}

	if (ip_hdr->ttl <= 1) {
		send_icmp_packet(interface, 1, eth_hdr, ip_hdr, r_icmp, TIMEOUT, 0, router_packet);
		return;
	}

	if (ip_hdr->ttl > 1) {

		struct in_addr router_addr;
		if (inet_pton(AF_INET, get_interface_ip(interface), &router_addr) == 1) {
			if (memcmp(&ip_hdr->daddr, &router_addr.s_addr, sizeof(uint32_t)) == 0) {
				send_icmp_packet(interface, 0, eth_hdr, ip_hdr, r_icmp, ECHO_REPLY, 0, router_packet);
				return;
			}
		}

		uint32_t dest_ip = ip_hdr->daddr;

		struct route_table_entry *best_route = get_best_route(dest_ip);

		if (best_route == NULL) {
			send_icmp_packet(interface, 1, eth_hdr, ip_hdr, r_icmp, DEST_UNREACHABLE, 0, router_packet);
			return;
		}

		ip_hdr->ttl = ip_hdr->ttl - 1;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		struct arp_entry *dest_MAC_addr = get_mac_entry(best_route->next_hop, cache_table);

		if (!dest_MAC_addr) {
			send_arp_broadcast(best_route, buf, len, eth_hdr, cache_table);
			return;
		}

		memcpy(eth_hdr->ether_dhost, dest_MAC_addr->mac, 6 * sizeof(char));

		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		send_to_link(best_route->interface, buf, len);

	}
}

/** the handler function used when the router gets an arp request packet */ 

void arp_request_handler(struct ether_header* eth_hdr, int interface, struct arp_header* arp_hdr) {
	struct in_addr router_addr;
	if (inet_pton(AF_INET, get_interface_ip(interface), &router_addr) == 1) {
		if (memcmp(&arp_hdr->tpa, &router_addr.s_addr, sizeof(uint32_t)) == 0) {

			uint8_t mac_dst[6], mac_src[6];
			memcpy(mac_dst, eth_hdr->ether_dhost, 6 * sizeof(char));
			memcpy(mac_src, eth_hdr->ether_shost, 6 * sizeof(char));
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(char));
			get_interface_mac(interface, eth_hdr->ether_shost);

			eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			struct arp_header reply;
			reply.tpa = arp_hdr->spa;
			reply.spa = arp_hdr->tpa;
			reply.htype = htons(1);
			reply.ptype = htons(ETHERTYPE_IP);
			reply.hlen = 6;
			reply.plen = 4;
			reply.op = htons(ARP_REPLY);
			memcpy(reply.sha, eth_hdr->ether_shost, 6 * sizeof(char));
			memcpy(reply.tha, eth_hdr->ether_dhost, 6 * sizeof(char));

			char reply_packet[MAX_PACKET_LEN];
			memcpy(reply_packet, eth_hdr, sizeof(struct ether_header));
			memcpy(reply_packet + sizeof(struct ether_header), &reply, sizeof(struct arp_header));

			send_to_link(interface, reply_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
		}
	} 
}

/** the handler used when the router gets an arp reply packet */

void arp_reply_handler(struct arp_header* arp_hdr, struct cache* cache_table) {
	add_entry_in_cache(arp_hdr->sha, arp_hdr->spa, cache_table);

	int i = 0;

	while (i < cache_table->len) {
		struct packet **arp_packet_ptr = (struct packet **)queue_deq(cache_table->cache_queue);
		struct packet *arp_packet = *arp_packet_ptr;
		cache_table->len--;

		struct ether_header *arp_eth_hdr = (struct ether_header *) (arp_packet->content);
		struct iphdr *arp_ip_hdr = (struct iphdr *)(arp_packet->content + sizeof(struct ether_header));

		struct route_table_entry *best_route_arp = get_best_route(arp_ip_hdr->daddr);

		struct arp_entry *dest_addr = get_mac_entry(best_route_arp->next_hop, cache_table);

		if (!dest_addr) {
			queue_enq(cache_table->cache_queue, &arp_packet);
			cache_table->len++;
			continue;
		}
		size_t pack_size = arp_packet->len;
		memcpy(arp_eth_hdr->ether_dhost, dest_addr->mac, 6 * sizeof(char));

		get_interface_mac(best_route_arp->interface, arp_eth_hdr->ether_shost);

		send_to_link(best_route_arp->interface, arp_packet->content, pack_size);
		i++;
	}
}

int main(int argc, char *argv[])
{
	struct cache *cache_table = init_cache();
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	rtable_filtered = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	DIE(rtable == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);
	rtable_filtered_len = 0;

	for (int i = 0; i < rtable_len; ++i) {
		if (ntohl(rtable[i].prefix & rtable[i].mask) != ntohl(rtable[i].prefix)) {
			continue;
		}
		rtable_filtered[rtable_filtered_len++] = rtable[i];
	}

	qsort(rtable_filtered, rtable_filtered_len, sizeof(struct route_table_entry), cmp);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			ipv4_handler(buf, len, interface, eth_hdr, cache_table);
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == ARP_REQUEST) {
				arp_request_handler(eth_hdr, interface, arp_hdr);
			} else if (ntohs(arp_hdr->op) == ARP_REPLY) {
				arp_reply_handler(arp_hdr, cache_table);
			}
		}
	}
}

