#include "ft_malcolm.h"

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

int	open_arp_socket(t_malcolm_ctx *ctx)
{
	struct timeval	tv;

	ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (ctx->sockfd < 0)
	{
		fprintf(stderr, "ft_malcolm: socket error: %s\n", strerror(errno));
		return (-1);
	}
	/* Timeout of 500ms so recvfrom can react promptly to SIGINT */
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
