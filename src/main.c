/*
** ============================================================================
** MACRO DEFINITIONS & DOCUMENTATION
** ============================================================================
** IFNAMSIZ: System constant for max network interface name length.
** INET_ADDRSTRLEN: Standard length for IPv4 string representation.
*/

#include "ft_malcolm.h"

/**
 * print_usage - Prints the program usage instructions.
 * @prog: The program name (argv[0]).
 * @bonus_mode: Boolean indicating if bonus flags are enabled.
 */
static void	print_usage(const char *prog, int bonus_mode)
{
	if (bonus_mode)
		fprintf(stderr, "Usage: %s [-v] <source ip> <source mac> <target ip> <target mac>\n", prog);
	else
		fprintf(stderr, "Usage: %s <source ip> <source mac> <target ip> <target mac>\n", prog);
}

/**
 * parse_cli_args - Parses and validates command line arguments.
 * @argc: Argument count.
 * @argv: Argument vector.
 * @ctx: Context structure.
 * @args: Parsed positional arguments.
 * @return: 0 on success, -1 on failure.
 */
static int	parse_cli_args(int argc, char **argv, t_malcolm_ctx *ctx, char **args)
{
	int	pos;
	int	i;

	pos = 0;
	i = 1;
	while (i < argc)
	{
		if (ft_strncmp(argv[i], "-v", 3) == 0)
		{
			if (!ctx->bonus_mode)
			{
				fprintf(stderr, "ft_malcolm: flags are only supported in bonus mode\n");
				return (-1);
			}
			ctx->verbose = 1;
		}
		else
		{
			if (pos >= 4)
				return (-1);
			args[pos++] = argv[i];
		}
		i++;
	}
	if (pos != 4)
		return (-1);
	return (0);
}

/**
 * main - Entry point for ft_malcolm.
 * @argc: Number of arguments.
 * @argv: Array of argument strings.
 * @return: 0 on success, 1 on failure.
 */
int	main(int argc, char **argv)
{
	t_malcolm_ctx	ctx;
	char			*args[4];
	int				ret;

	ft_bzero(&ctx, sizeof(ctx));
#ifdef BONUS
	ctx.bonus_mode = 1;
#else
	ctx.bonus_mode = 0;
#endif

	if (parse_cli_args(argc, argv, &ctx, args) != 0)
	{
		print_usage(argv[0], ctx.bonus_mode);
		return (1);
	}

	if (parse_ip(args[0], ctx.src_ip, ctx.bonus_mode) != 0)
	{
		fprintf(stderr, "ft_malcolm: unknown host or invalid IP address: (%s).\n", args[0]);
		return (1);
	}
	if (parse_mac(args[1], ctx.src_mac) != 0)
	{
		fprintf(stderr, "ft_malcolm: invalid mac address: (%s)\n", args[1]);
		return (1);
	}
	if (parse_ip(args[2], ctx.tgt_ip, ctx.bonus_mode) != 0)
	{
		fprintf(stderr, "ft_malcolm: unknown host or invalid IP address: (%s).\n", args[2]);
		return (1);
	}
	if (parse_mac(args[3], ctx.tgt_mac) != 0)
	{
		fprintf(stderr, "ft_malcolm: invalid mac address: (%s)\n", args[3]);
		return (1);
	}

	if (getuid() != 0)
	{
		fprintf(stderr, "ft_malcolm: must be run as root (uid 0)\n");
		return (1);
	}

	format_ip(ctx.src_ip, ctx.src_ip_str, sizeof(ctx.src_ip_str));
	format_mac(ctx.src_mac, ctx.src_mac_str, sizeof(ctx.src_mac_str));
	format_ip(ctx.tgt_ip, ctx.tgt_ip_str, sizeof(ctx.tgt_ip_str));
	format_mac(ctx.tgt_mac, ctx.tgt_mac_str, sizeof(ctx.tgt_mac_str));

	init_signals();

	if (find_active_interface(&ctx) != 0)
		return (1);

	if (open_arp_socket(&ctx) != 0)
		return (1);

	ret = listen_and_spoof(&ctx);

	if (ctx.sockfd >= 0)
		close(ctx.sockfd);

	return (ret == 0 ? 0 : 1);
}
