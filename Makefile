NAME		= ft_malcolm

CC			= gcc
CFLAGS		= -Wall -Wextra -Werror -Iinclude -Ilibft

LIBFT_DIR	= libft
LIBFT		= $(LIBFT_DIR)/libft.a

SRCDIR		= src
OBJDIR		= obj

SRCS		= $(SRCDIR)/main.c \
			  $(SRCDIR)/signals.c \
			  $(SRCDIR)/parser.c \
			  $(SRCDIR)/network.c \
			  $(SRCDIR)/packet.c \
			  $(SRCDIR)/listener.c

OBJS		= $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
BONUS_OBJS	= $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%_bonus.o, $(SRCS))

all: $(NAME)

$(LIBFT):
	@$(MAKE) -C $(LIBFT_DIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%_bonus.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -DBONUS -c $< -o $@

$(NAME): $(LIBFT) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LIBFT) -o $(NAME)

bonus: $(LIBFT) $(BONUS_OBJS)
	$(CC) $(CFLAGS) -DBONUS $(BONUS_OBJS) $(LIBFT) -o $(NAME)

clean:
	@rm -rf $(OBJDIR)
	@$(MAKE) -C $(LIBFT_DIR) clean

fclean: clean
	@rm -f $(NAME)
	@$(MAKE) -C $(LIBFT_DIR) fclean

re: fclean all

.PHONY: all bonus clean fclean re
