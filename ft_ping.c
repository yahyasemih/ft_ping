#include "ft_ping.h"

ping_context_t g_ctx;

void statistics_handler(int sig) {
	(void)sig;
	char buff[NI_MAXHOST];
	if (is_fqdn(g_ctx.host)) {
		printf("\n--- %s ping statistics ---\n", g_ctx.host);
	} else {
		if (dns_resolve(g_ctx.host_ip, buff, NI_MAXHOST)) {
			printf("\n--- %s ping statistics ---\n", g_ctx.host);
		} else {
			printf("\n--- %s ping statistics ---\n", buff);
		}
	}
	double min = g_ctx.stats.min / 1000.0;
	double avg = g_ctx.stats.sum / (g_ctx.stats.received * 1000.0);
	double max = g_ctx.stats.max / 1000.0;
	double mdev = (max - min) / 2.0;

	g_ctx.stats.total_time = (g_ctx.stats.transmitted - 1) * 1000 + g_ctx.stats.sum / 1000;
	printf("%d packets transmitted, %d received,", g_ctx.stats.transmitted, g_ctx.stats.received);
	if (g_ctx.stats.errors > 0) {
		printf(" +%d errors,", g_ctx.stats.errors);
	}
	printf(" %d%% packet loss, time %dms\n",
			(int)((g_ctx.stats.transmitted - g_ctx.stats.received) * 100.0) / g_ctx.stats.transmitted,
			g_ctx.stats.total_time);
	if (g_ctx.stats.received > 0) {
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, mdev);
	} else {
		printf("\n");
	}
	close(g_ctx.socket_fd);
	freeaddrinfo(g_ctx.addr);
	if (g_ctx.count == 0) {
		exit(0);
	} else {
		exit(1);
	}
}

void random_statistics_handler(int sig) {
	(void)sig;
	printf("\r%d/%d packets, %d%% loss", g_ctx.stats.received, g_ctx.stats.transmitted,
			(int)((g_ctx.stats.transmitted - g_ctx.stats.received) * 100.0) / g_ctx.stats.transmitted);
	if (g_ctx.stats.received > 0) {
		double min = g_ctx.stats.min / 1000.0;
		double avg = g_ctx.stats.sum / (g_ctx.stats.received * 1000.0);
		double max = g_ctx.stats.max / 1000.0;
		printf(", min/avg/ewma/max = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, (avg + max) / 2.0, max);
	} else {
		printf("\n");
	}
}

int send_packet() {
	int sent;
	ft_memset(g_ctx.send_buf, 0, sizeof(g_ctx.send_buf));
	socklen_t dst_addr_len = sizeof(*g_ctx.dst);
	struct ip *ip = (struct ip *)g_ctx.send_buf;
	struct icmp *icmp = (struct icmp *)(ip + 1);

	inet_pton(AF_INET, "0.0.0.0", &ip->ip_src);
	inet_pton(AF_INET, g_ctx.host_ip, &ip->ip_dst);
	ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
	ip->ip_len = ft_htons(sizeof(g_ctx.send_buf));
    ip->ip_id = ft_htons(123);
    ip->ip_off = 0;
    ip->ip_ttl = g_ctx.ttl;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_sum = cksum((unsigned short *)ip, ip->ip_hl);

	icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = ft_htons(123);
    icmp->icmp_seq = g_ctx.stats.transmitted;
    icmp->icmp_cksum = cksum((unsigned short *)icmp, sizeof(g_ctx.send_buf) - sizeof(struct icmp));
	g_ctx.dst->sin_family = AF_INET;

	sent = sendto(g_ctx.socket_fd, g_ctx.send_buf, sizeof(g_ctx.send_buf), 0, (struct sockaddr *)g_ctx.dst,
			dst_addr_len);
	if (sent >= 0) {
		g_ctx.stats.transmitted++;
	} else {
		if (g_ctx.flags & FLAG_VERB) {
			fprintf(stderr, "Error while sending packet: %s\n", strerror(errno));
		}
		return 0;
	}
	return 1;
}

int receive_packet() {
	int received;
	ft_memset(g_ctx.recv_buf, 0, sizeof(g_ctx.recv_buf));
	socklen_t dst_addr_len;

	dst_addr_len = sizeof(*g_ctx.dst);
	received = recvfrom(g_ctx.socket_fd, g_ctx.recv_buf, sizeof(g_ctx.recv_buf), 0, (struct sockaddr *)g_ctx.dst,
			&dst_addr_len);
	if (ft_memcmp(g_ctx.recv_buf + 16, g_ctx.send_buf + 16, 40) == 0) {
		received = recvfrom(g_ctx.socket_fd, g_ctx.recv_buf, sizeof(g_ctx.recv_buf), 0, (struct sockaddr *)g_ctx.dst,
				&dst_addr_len);
	}

	if (received < 0) {
		if (g_ctx.flags & FLAG_VERB) {
			fprintf(stderr, "Error while receiving packet: %s\n", strerror(errno));
		}
		return 0;
	}
	return 1;
}

void socket_handler(const char *str) {
	int options = 1;
	struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
	int type = SOCK_RAW;

	if (g_ctx.flags & FLAG_DEBUG) {
		type |= SO_DEBUG;
	}
	g_ctx.socket_fd = socket(AF_INET, type, IPPROTO_ICMP);
	if (g_ctx.socket_fd < 0) {
		fprintf(stderr, "%s: socket: %s\n", str, strerror(errno));
		exit(2);
	}
	if(setsockopt(g_ctx.socket_fd, IPPROTO_IP, IP_HDRINCL, &options, sizeof(options)) < 0)
    {
        fprintf(stderr, "%s: socket: %s\n", str, strerror(errno));
		exit(2);
    }
	if (setsockopt (g_ctx.socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
		fprintf(stderr, "%s: socket: %s\n", str, strerror(errno));
		exit(2);
	}
	if (setsockopt (g_ctx.socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		fprintf(stderr, "%s: socket: %s\n", str, strerror(errno));
		exit(2);
	}
}

const char *get_icmp_error(int type, int code) {
	if (type == ICMP_TIME_EXCEEDED) {
		if (code == ICMP_EXC_TTL) {
			return "Time to live exceeded";
		} else {
			return "Fragment Reass time exceeded";
		}
	} else if (type == ICMP_DEST_UNREACH) {
		if (code == ICMP_NET_UNREACH) {
			return "Destination Network Unreachable";
		} else if (code == ICMP_HOST_UNREACH) {
			return "Destination Host Unreachable";
		} else if (code == ICMP_PROT_UNREACH) {
			return "Destination Protocol Unreachable";
		} else if (code == ICMP_PORT_UNREACH) {
			return "Destination Port Unreachable";
		} else {
			return "Destination Unreachable";
		}
	} else {
		return "ICMP Response Error";
	}
}

int get_precision(double duration) {
	if (duration >= 100) {
		return 0;
	} else if (duration >= 10) {
		return 1;
	} else if (duration >= 1) {
		return 2;
	} else {
		return 3;
	}
}

void ping_handler(int sig) {
	(void)sig;
	struct timeval start, end;
	int duration;
	int sent;
	int received;
	struct ip *ip = (struct ip *)g_ctx.recv_buf;
	struct icmp *icmp = (struct icmp *)(ip + 1);

	gettimeofday(&start, NULL);
	sent = send_packet();
	if (!(g_ctx.flags & FLAG_QUIET) && (g_ctx.flags & FLAG_DAY)) {
		printf("[%ld.%ld] ", start.tv_sec, start.tv_usec);
	}
	if (sent) {
		received = receive_packet();
		char src_name[INET_ADDRSTRLEN];
		char dst_name[INET_ADDRSTRLEN];
		char src_dns[NI_MAXHOST];
		inet_ntop(AF_INET, &ip->ip_src, src_name, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip->ip_dst, dst_name, INET_ADDRSTRLEN);
		if (received) {
			gettimeofday(&end, NULL);
			duration = end.tv_usec - start.tv_usec;
			if (duration < 0) {
				duration += 1000000;
			}
			if (duration > g_ctx.stats.max) {
				g_ctx.stats.max = duration;
			}
			if (duration < g_ctx.stats.min) {
				g_ctx.stats.min = duration;
			}
			g_ctx.stats.sum += duration;
			int show_ip = is_ip(g_ctx.host) || (g_ctx.flags & FLAG_NUM);
			if (icmp->icmp_type == ICMP_ECHOREPLY || icmp->icmp_type == ICMP_ECHO) {
				g_ctx.stats.received++;
				if (!(g_ctx.flags & FLAG_QUIET)) {
					printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.*f ms\n", DATA_SIZE + 8,
							get_from_addr(src_name, src_dns, show_ip), g_ctx.stats.transmitted, ip->ip_ttl,
							get_precision(duration / 1000.0), duration / 1000.0);
				}
			} else {
				g_ctx.stats.errors++;
				if (!(g_ctx.flags & FLAG_QUIET)) {
					printf("From %s icmp_seq=%d %s\n", get_from_addr(src_name, src_dns, show_ip),
							g_ctx.stats.transmitted, get_icmp_error(icmp->icmp_type, icmp->icmp_code));
				}
			}
		} else {
			g_ctx.stats.errors++;
			if (!(g_ctx.flags & FLAG_QUIET)) {
				printf("From %s icmp_seq=%d %s\n", src_name, g_ctx.stats.transmitted, strerror(errno));
			}
		}
	} else {
		g_ctx.stats.errors++;
		if (!(g_ctx.flags & FLAG_QUIET)) {
			printf("From %s icmp_seq=%d %s\n", g_ctx.host_ip, g_ctx.stats.transmitted, strerror(errno));
		}
	}
	if (g_ctx.count <= -1) {
		alarm(g_ctx.interval);
	} else {
		if (--g_ctx.count > 0) {
			alarm(g_ctx.interval);
		} else {
			statistics_handler(SIGALRM);
		}
	}
}

void start_pinging(const char *str) {
	struct addrinfo hints;

	ft_memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	int ret = getaddrinfo(g_ctx.host, NULL, &hints, &g_ctx.addr);
    if (ret) {
        fprintf(stderr, "%s: %s: %s\n", str, g_ctx.host, gai_strerror(ret));
		freeaddrinfo(g_ctx.addr);
		exit(2);
    }
	g_ctx.dst = (struct sockaddr_in *)g_ctx.addr->ai_addr;
	if (inet_ntop(g_ctx.addr->ai_family, &g_ctx.dst->sin_addr, g_ctx.host_ip, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr, "%s: %s\n", str, strerror(errno));
		freeaddrinfo(g_ctx.addr);
		exit(2);
	}
	char buff[NI_MAXHOST];
	if (is_fqdn(g_ctx.host)) {
		printf("PING %s (%s) %d(%d) bytes of data.\n", g_ctx.host, g_ctx.host, DATA_SIZE, DATA_SIZE + 28);
	} else {
		if (dns_resolve(g_ctx.host_ip, buff, NI_MAXHOST)) {
			printf("PING %s (%s) %d(%d) bytes of data.\n", g_ctx.host, g_ctx.host_ip, DATA_SIZE, DATA_SIZE + 28);
		} else {
			printf("PING %s (%s) %d(%d) bytes of data.\n", buff, g_ctx.host_ip, DATA_SIZE, DATA_SIZE + 28);
		}
	}
	ping_handler(SIGALRM);
}

void print_options() {
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  <destination>\t\tdns name or ip address\n");
	fprintf(stderr, "  -c <count>\t\tstop after <count> replies\n");
	fprintf(stderr, "  -D\t\t\tprint timestamps\n");
	fprintf(stderr, "  -d\t\t\tuse SO_DEBUG socket option\n");
	fprintf(stderr, "  -h\t\t\tprint help and exit\n");
	fprintf(stderr, "  -i <interval>\t\tseconds between sending each packet\n");
	fprintf(stderr, "  -n\t\t\tno dns name resolution\n");
	fprintf(stderr, "  -q\t\t\tquiet output\n");
	fprintf(stderr, "  -t <ttl>\t\tdefine time to live\n");
	fprintf(stderr, "  -v\t\t\tverbose output\n");
}

void print_usage(int exit_status) {
	fprintf(stderr, "\nUsage\n  ping [options] <destination>\n");
	print_options();
	exit(exit_status);
}

void flags_handler(char c) {
	if (c == 'D') {
		g_ctx.flags |= FLAG_DAY;
	} else if (c == 'd') {
		g_ctx.flags |= FLAG_DEBUG;
	} else if (c == 'n') {
		g_ctx.flags |= FLAG_NUM;
	} else if (c == 'q') {
		g_ctx.flags |= FLAG_QUIET;
	} else if (c == 'v') {
		g_ctx.flags |= FLAG_VERB;
	}
}

int modifiers_handler(char c, char *argv[], int *x, int *y) {
	int i = *x;
	int j = *y;
	long value = 0;
	int ret = 0;
	char *str = NULL;
	char *end = NULL;

	if (argv[i][j + 1] != '\0') {
		str = argv[i] + j + 1;
		ret = 1;
	} else {
		if (argv[i + 1] == NULL) {
			fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], c);
			print_usage(2);
		}
		str = argv[i + 1];
		i++;
		ret = 1;
	}
	value = strtoll(str, &end, 10);
	if (errno == ERANGE) {
		fprintf(stderr, "%s: invalid argument: '%s': Numerical result out of range\n",
				argv[0], str);
		exit(1);
	} else if (end != NULL && *end != '\0') {
		fprintf(stderr, "%s: invalid argument: '%s'\n", argv[0], str);
		exit(1);
	}
	if (c == 'c') {
		if (value <= 0 || value > __LONG_MAX__) {
			fprintf(stderr, "%s: invalid argument: '%ld': out of range: %ld <= value "
					"<= %ld\n", argv[0], value, 1L, __LONG_MAX__);
			exit(1);
		}
		g_ctx.count = value;
	} else if (c == 'i') {
		if (value <= 0 || value >= 2147484) {
			fprintf(stderr, "%s: bad timing interval: '%ld'\n", argv[0], value);
			exit(2);
		}
		g_ctx.interval = (int)value;
	}  else if (c == 't') {
		if (value < 0 || value > 255) {
			fprintf(stderr, "%s: invalid argument: '%ld': out of range: %d <= value "
					"<= %d\n", argv[0], value, 0, 255);
			exit(1);
		}
		g_ctx.ttl = (int)value;
	}
	*x = i;
	*y = j;
	return ret;
}

void arguments_handler(int argc, char *argv[]) {
	int end_of_flags = 0;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && !end_of_flags) {
			if (argv[i][1] == '-' && argv[i][2] == '\0') {
				end_of_flags = 1;
			} else {
				for (int j = 1; argv[i][j] != '\0'; j++) {
					if (search_char("qnvdD", argv[i][j])) {
						flags_handler(argv[i][j]);
					} else if (search_char("cit", argv[i][j])) {
						if (modifiers_handler(argv[i][j], argv, &i, &j)) {
							break;
						}
					} else {
						if (argv[i][j] != 'h') {
							fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], argv[i][j]);
						}
						print_usage(2);
					}
				}
			}
		} else {
			g_ctx.host = argv[i];
		}
	}
	if (g_ctx.host == NULL) {
		fprintf(stderr, "%s: usage error: Destination address required\n", argv[0]);
		exit(1);
	}
}

void init_context() {
	g_ctx.flags = 0;
	g_ctx.interval = 1;
	g_ctx.count = -1;
	g_ctx.ttl = 255;
	g_ctx.host = NULL;
	g_ctx.socket_fd = -1;
	g_ctx.stats.min = __INT_MAX__;
	g_ctx.stats.max = -1;
	g_ctx.stats.sum = 0;
	g_ctx.stats.received = 0;
	g_ctx.stats.transmitted = 0;
	g_ctx.stats.errors = 0;
}

int main(int argc, char *argv[]) {
	if (getuid() != 0) {
		fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	init_context();
	arguments_handler(argc, argv);
	signal(SIGALRM, ping_handler);
	signal(SIGINT, statistics_handler);
	signal(SIGQUIT, random_statistics_handler);
	socket_handler(argv[0]);
	start_pinging(argv[0]);
	while (1);
}
