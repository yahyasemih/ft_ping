#include "utilities.h"

unsigned short ft_htons(unsigned short n) {
	return (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8));
}

void *ft_memset(void *s, int c, size_t n) {
	char *data = s;
	for (size_t i = 0; i < n; i++) {
		data[i] = c;
	}
	return s;
}

int ft_memcmp(const void *s1, const void *s2, size_t n) {
	const unsigned char *data1 = s1;
	const unsigned char *data2 = s2;
	for (size_t i = 0; i < n; i++) {
		if (data1[i] != data2[i]) {
			return data1[i] - data2[i];
		}
	}
	return 0;
}

int dns_resolve(const char *host, char *dest, int size) {
   struct sockaddr_in socket_address;
   socket_address.sin_family = AF_INET;
   inet_pton(AF_INET, host, &(socket_address.sin_addr));
   return getnameinfo((struct sockaddr *)&socket_address, sizeof(socket_address), dest, size, NULL, 0, NI_NAMEREQD);
}

unsigned short cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1)
    {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

int search_char(const char *s, char c) {
	if (s == NULL) {
		return 0;
	}
	for (int i = 0; s[i] != '\0'; i++) {
		if (s[i] == c) {
			return 1;
		}
	}
	return 0;
}

int is_ip(const char *host) {
	for (int i = 0; host[i] != '\0'; i++) {
		if (host[i] != '.' && (host[i] < '0' || host[i] > '9')) {
			return 0;
		}
	}

	return 1;
}

int is_fqdn(const char *host) {
	int nb_dots = 0;
	for (int i = 0; host[i] != '\0'; i++) {
		if (host[i] == '.') {
			nb_dots++;
		}
	}

	return nb_dots > 0;
}

const char *get_from_addr(const char *host, char *dest, int show_ip) {
	char buff[NI_MAXHOST];

	if (show_ip) {
		sprintf(dest, "%s", host);
	} else {
		int ret = dns_resolve(host, buff, NI_MAXHOST);
		if (ret) {
			sprintf(dest, "%s (%s)", host, host);
		} else {
			sprintf(dest, "%s (%s)", buff, host);
		}
	}
	return dest;
}
