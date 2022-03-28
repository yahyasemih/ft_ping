#ifndef UTILITIES_H
#define UTILITIES_H

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

unsigned short ft_htons(unsigned short n);
void *ft_memset(void *s, int c, size_t n);
int ft_memcmp(const void *s1, const void *s2, size_t n);
int dns_resolve(const char *host, char *dest, int size);
unsigned short ft_checksum(unsigned short *addr, int len);
int search_char(const char *s, char c);
int is_ip(const char *host);
int is_fqdn(const char *host);
const char *get_from_addr(const char *host, char *dest, int show_ip);

#endif
