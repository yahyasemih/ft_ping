NAME = ft_ping
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror

SRC = ft_ping.c utilities.c
OBJ := $(patsubst %.c,%.o,$(SRC))
DEPENDS := $(patsubst %.c,%.d,$(SRC))

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	/bin/rm -f $(OBJ) $(DEPENDS)

fclean: clean
	/bin/rm -f $(NAME)

re: fclean all

.PHONY: clean fclean all re

-include $(DEPENDS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@
