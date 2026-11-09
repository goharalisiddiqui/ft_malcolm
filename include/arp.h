#ifndef ARP_H
# define ARP_H

# include <stdint.h>

# ifndef ETH_ALEN
#  define ETH_ALEN          6
# endif
# ifndef ETH_HLEN
#  define ETH_HLEN          14
# endif
# define IP4_ALEN           4
# define ARP_PACKET_LEN     28
# define TOTAL_PACKET_LEN   (ETH_HLEN + ARP_PACKET_LEN)

# define ETHERTYPE_ARP      0x0806
# define ARPHRD_ETHER       1
# define ETHERTYPE_IP       0x0800
# define ARPOP_REQUEST      1
# define ARPOP_REPLY        2

typedef struct s_eth_hdr {
	uint8_t  dest[ETH_ALEN];
	uint8_t  src[ETH_ALEN];
	uint16_t proto;
} __attribute__((packed)) t_eth_hdr;

typedef struct s_arp_hdr {
	uint16_t hrd;
	uint16_t pro;
	uint8_t  hln;
	uint8_t  pln;
	uint16_t op;
	uint8_t  sha[ETH_ALEN];
	uint8_t  spa[IP4_ALEN];
	uint8_t  tha[ETH_ALEN];
	uint8_t  tpa[IP4_ALEN];
} __attribute__((packed)) t_arp_hdr;

typedef struct s_arp_packet {
	t_eth_hdr eth;
	t_arp_hdr arp;
} __attribute__((packed)) t_arp_packet;

#endif
