//
// Created by Yahya Ez-zainabi on 3/25/22.
//

#ifndef FT_PING_FT_PING_H
#define FT_PING_FT_PING_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "utilities.h"

#define FLAG_DEBUG	0x1
#define FLAG_DAY	0x2
#define FLAG_NUM	0x4
#define FLAG_QUIET	0x8
#define FLAG_VERB	0x10

#define DATA_SIZE	56

typedef struct stats_s {
	int min;
	int max;
	int sum;
	int received;
	int transmitted;
	int errors;
	int total_time;
} stats_t;

typedef struct ft_ping_context {
	int64_t count;
	int interval;
	unsigned flags;
	int ttl;
	int socket_fd;
	stats_t stats;
	char *host;
	char host_ip[INET_ADDRSTRLEN];
	struct sockaddr_in *dst;
	struct addrinfo *addr;
	char send_buf[DATA_SIZE];
	char recv_buf[DATA_SIZE];
} ping_context_t;

#endif //FT_PING_FT_PING_H
