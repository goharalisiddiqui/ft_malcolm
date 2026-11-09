#ifndef FT_MALCOLM_H
# define FT_MALCOLM_H

# include <sys/types.h>
# include <sys/socket.h>
# include <linux/if_packet.h>
# include <net/ethernet.h>
# include <net/if.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <ifaddrs.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <errno.h>
# include <netdb.h>

# include "arp.h"
# include "../libft/libft.h"

/* Single global variable permitted by 42 curriculum */
extern volatile sig_atomic_t g_running;

typedef struct s_malcolm_ctx {
	char		ifname[IFNAMSIZ];
	int			ifindex;
	int			sockfd;
	uint8_t		src_ip[IP4_ALEN];
	uint8_t		src_mac[ETH_ALEN];
	uint8_t		tgt_ip[IP4_ALEN];
	uint8_t		tgt_mac[ETH_ALEN];
	char		src_ip_str[INET_ADDRSTRLEN];
	char		src_mac_str[18];
	char		tgt_ip_str[INET_ADDRSTRLEN];
	char		tgt_mac_str[18];
	int			verbose;
	int			bonus_mode;
}	t_malcolm_ctx;

/* Signal Handling */
void	init_signals(void);

/* Parsing & Formatting */
int		parse_mac(const char *str, uint8_t mac[ETH_ALEN]);
int		parse_ip(const char *str, uint8_t ip[IP4_ALEN], int bonus_mode);
void	format_mac(const uint8_t mac[ETH_ALEN], char *buf, size_t size);
void	format_ip(const uint8_t ip[IP4_ALEN], char *buf, size_t size);

/* Network & Sockets */
int		find_active_interface(t_malcolm_ctx *ctx);
int		open_arp_socket(t_malcolm_ctx *ctx);

/* Packet Handling */
int		send_arp_reply(t_malcolm_ctx *ctx);
void	print_packet_verbose(const uint8_t *packet, size_t len);

/* Sniffing & Matching */
int		listen_and_spoof(t_malcolm_ctx *ctx);

#endif
