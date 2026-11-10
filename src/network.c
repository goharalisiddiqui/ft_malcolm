/*
** ============================================================================
** MACRO DEFINITIONS & DOCUMENTATION
** ============================================================================
** IFNAMSIZ: System constant for max network interface name length.
** AF_INET: Address family for IPv4 protocol.
** IFF_UP: Interface is operationally up.
** IFF_RUNNING: Resources are allocated for the interface.
** IFF_LOOPBACK: Interface is a loopback device.
** IFF_NOARP: Interface does not support ARP.
** SOCK_RAW: Socket type for raw access to protocol packets.
** ETH_P_ARP: Protocol type for ARP packets (Ethernet).
** SOL_SOCKET: Socket level for setsockopt.
** SO_RCVTIMEO: Timeout option for socket receive calls.
*/

#include "ft_malcolm.h"

/**
 * is_matching_subnet - Determines if the interface is on the same subnet as the target.
 * @addr: Pointer to interface address.
 * @netmask: Pointer to interface netmask.
 * @tgt_ip: Target IPv4 to check.
 * @return: 1 if matches, 0 otherwise.
 */
static int	is_matching_subnet(struct sockaddr *addr, struct sockaddr *netmask,
	const uint8_t tgt_ip[IP4_ALEN])
{
	struct sockaddr_in	*sa;
	struct sockaddr_in	*sm;
	uint32_t			target;
	uint32_t			interface_ip;
	uint32_t			mask;

	if (!addr || !netmask || addr->sa_family != AF_INET)
		return (0);
	sa = (struct sockaddr_in *)addr;
	sm = (struct sockaddr_in *)netmask;
	ft_memcpy(&target, tgt_ip, IP4_ALEN);
	interface_ip = sa->sin_addr.s_addr;
	mask = sm->sin_addr.s_addr;
	return ((interface_ip & mask) == (target & mask));
}

/**
 * find_active_interface - Locates a broadcast-capable network interface.
 * @ctx: Context structure to store ifname and ifindex.
 * @return: 0 on success, -1 on failure.
 */
int	find_active_interface(t_malcolm_ctx *ctx)
{
	struct ifaddrs	*ifaddr;
	struct ifaddrs	*ifa;
	char			candidate[IFNAMSIZ];

	if (getifaddrs(&ifaddr) == -1)
	{
		fprintf(stderr, "ft_malcolm: getifaddrs failed: %s\n", strerror(errno));
		return (-1);
	}
	candidate[0] = '\0';
	ifa = ifaddr;
	while (ifa != NULL)
	{
		if (ifa->ifa_flags & IFF_UP
			&& ifa->ifa_flags & IFF_RUNNING
			&& !(ifa->ifa_flags & IFF_LOOPBACK)
			&& !(ifa->ifa_flags & IFF_NOARP))
		{
			if (candidate[0] == '\0')
				ft_strlcpy(candidate, ifa->ifa_name, sizeof(candidate));
			if (is_matching_subnet(ifa->ifa_addr, ifa->ifa_netmask, ctx->tgt_ip))
			{
				ft_strlcpy(candidate, ifa->ifa_name, sizeof(candidate));
				break ;
			}
		}
		ifa = ifa->ifa_next;
	}
	freeifaddrs(ifaddr);
	if (candidate[0] == '\0')
	{
		fprintf(stderr, "ft_malcolm: no suitable active network interface found\n");
		return (-1);
	}
	ft_strlcpy(ctx->ifname, candidate, sizeof(ctx->ifname));
	ctx->ifindex = if_nametoindex(ctx->ifname);
	if (ctx->ifindex == 0)
	{
		fprintf(stderr, "ft_malcolm: failed to get interface index for %s\n", ctx->ifname);
		return (-1);
	}
	printf("Found available interface: %s\n", ctx->ifname);
	return (0);
}

/**
 * open_arp_socket - Creates and configures a raw ARP socket.
 * @ctx: Context structure to store sockfd.
 * @return: 0 on success, -1 on failure.
 */
int	open_arp_socket(t_malcolm_ctx *ctx)
{
	struct timeval	tv;

	ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (ctx->sockfd < 0)
	{
		fprintf(stderr, "ft_malcolm: socket error: %s\n", strerror(errno));
		return (-1);
	}
	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	if (setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		fprintf(stderr, "ft_malcolm: setsockopt failed: %s\n", strerror(errno));
		close(ctx->sockfd);
		ctx->sockfd = -1;
		return (-1);
	}
	return (0);
}
