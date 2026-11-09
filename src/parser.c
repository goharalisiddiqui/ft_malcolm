#include "ft_malcolm.h"

static int	hex_char_to_val(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

int	parse_mac(const char *str, uint8_t mac[ETH_ALEN])
{
	int	i;
	int	hi;
	int	lo;

	if (!str || ft_strlen((char *)str) != 17)
		return (-1);
	i = 0;
	while (i < ETH_ALEN)
	{
		hi = hex_char_to_val(str[i * 3]);
		lo = hex_char_to_val(str[i * 3 + 1]);
		if (hi < 0 || lo < 0)
			return (-1);
		mac[i] = (uint8_t)((hi << 4) | lo);
		if (i < ETH_ALEN - 1 && str[i * 3 + 2] != ':')
			return (-1);
		i++;
	}
	return (0);
}

static int	resolve_hostname(const char *str, uint8_t ip[IP4_ALEN])
{
	struct addrinfo	hints;
	struct addrinfo	*res;
	int				status;

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	res = NULL;
	status = getaddrinfo(str, NULL, &hints, &res);
	if (status != 0 || !res)
		return (-1);
	ft_memcpy(ip, &((struct sockaddr_in *)res->ai_addr)->sin_addr, IP4_ALEN);
	freeaddrinfo(res);
	return (0);
}

int	parse_ip(const char *str, uint8_t ip[IP4_ALEN], int bonus_mode)
{
	struct in_addr	addr;

	if (!str)
		return (-1);
	if (inet_pton(AF_INET, str, &addr) == 1)
	{
		ft_memcpy(ip, &addr.s_addr, IP4_ALEN);
		return (0);
	}
	if (bonus_mode)
	{
		in_addr_t	num_addr;

		num_addr = inet_addr(str);
		if (num_addr != (in_addr_t)(-1))
		{
			ft_memcpy(ip, &num_addr, IP4_ALEN);
			return (0);
		}
		if (resolve_hostname(str, ip) == 0)
			return (0);
	}
	return (-1);
}

void	format_mac(const uint8_t mac[ETH_ALEN], char *buf, size_t size)
{
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void	format_ip(const uint8_t ip[IP4_ALEN], char *buf, size_t size)
{
	inet_ntop(AF_INET, ip, buf, (socklen_t)size);
}
