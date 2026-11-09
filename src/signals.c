#include "ft_malcolm.h"

volatile sig_atomic_t g_running = 1;

static void	sigint_handler(int signum)
{
	(void)signum;
	g_running = 0;
}

void	init_signals(void)
{
	struct sigaction	sa;

	ft_bzero(&sa, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}
