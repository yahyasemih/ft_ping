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

unsigned short ft_checksum(unsigned short *addr, int len) {
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

const char *ft_gai_strerror(int errcode) {
	if (errcode == EAI_BADFLAGS) {
		return "Bad value for ai_flags";
	} else if (errcode == EAI_NONAME) {
		return "Name or service not known";
	} else if (errcode == EAI_AGAIN) {
		return "Temporary failure in name resolution";
	} else if (errcode == EAI_FAIL) {
		return "Non-recoverable failure in name resolution";
	} else if (errcode == EAI_FAMILY) {
		return "ai_family not supported";
	} else if (errcode == EAI_SOCKTYPE) {
		return "ai_socktype not supported";
	} else if (errcode == EAI_SERVICE) {
		return "Servname not supported for ai_socktype";
	} else if (errcode == EAI_MEMORY) {
		return "Memory allocation failure";
	} else if (errcode == EAI_SYSTEM) {
		return "System error";
	} else if (errcode == EAI_OVERFLOW) {
		return "Argument buffer overflow";
	} else {
		return "Unknown error";
	}
}

const char *ft_strerror(int errcode) {
	if (errcode == 0) {
        return "Success";
	} else if (errcode == 1) {
		return "Operation not permitted";
	} else if (errcode == 2) {
		return "No such file or directory";
	} else if (errcode == 3) {
		return "No such process";
	} else if (errcode == 4) {
		return "Interrupted system call";
	} else if (errcode == 5) {
		return "Input/output error";
	} else if (errcode == 6) {
		return "No such device or address";
	} else if (errcode == 7) {
		return "Argument list too long";
	} else if (errcode == 8) {
		return "Exec format error";
	} else if (errcode == 9) {
		return "Bad file descriptor";
	} else if (errcode == 10) {
		return "No child processes";
	} else if (errcode == 11) {
		return "Resource temporarily unavailable";
	} else if (errcode == 12) {
		return "Cannot allocate memory";
	} else if (errcode == 13) {
		return "Permission denied";
	} else if (errcode == 14) {
		return "Bad address";
	} else if (errcode == 15) {
		return "Block device required";
	} else if (errcode == 16) {
		return "Device or resource busy";
	} else if (errcode == 17) {
		return "File exists";
	} else if (errcode == 18) {
		return "Invalid cross-device link";
	} else if (errcode == 19) {
		return "No such device";
	} else if (errcode == 20) {
		return "Not a directory";
	} else if (errcode == 21) {
		return "Is a directory";
	} else if (errcode == 22) {
		return "Invalid argument";
	} else if (errcode == 23) {
		return "Too many open files in system";
	} else if (errcode == 24) {
		return "Too many open files";
	} else if (errcode == 25) {
		return "Inappropriate ioctl for device";
	} else if (errcode == 26) {
		return "Text file busy";
	} else if (errcode == 27) {
		return "File too large";
	} else if (errcode == 28) {
		return "No space left on device";
	} else if (errcode == 29) {
		return "Illegal seek";
	} else if (errcode == 30) {
		return "Read-only file system";
	} else if (errcode == 31) {
		return "Too many links";
	} else if (errcode == 32) {
		return "Broken pipe";
	} else if (errcode == 33) {
		return "Numerical argument out of domain";
	} else if (errcode == 34) {
		return "Numerical result out of range";
	} else if (errcode == 35) {
		return "Resource deadlock avoided";
	} else if (errcode == 36) {
		return "File name too long";
	} else if (errcode == 37) {
		return "No locks available";
	} else if (errcode == 38) {
		return "Function not implemented";
	} else if (errcode == 39) {
		return "Directory not empty";
	} else if (errcode == 40) {
		return "Too many levels of symbolic links";
	} else if (errcode == 41) {
		return "Unknown error 41";
	} else if (errcode == 42) {
		return "No message of desired type";
	} else if (errcode == 43) {
		return "Identifier removed";
	} else if (errcode == 44) {
		return "Channel number out of range";
	} else if (errcode == 45) {
		return "Level 2 not synchronized";
	} else if (errcode == 46) {
		return "Level 3 halted";
	} else if (errcode == 47) {
		return "Level 3 reset";
	} else if (errcode == 48) {
		return "Link number out of range";
	} else if (errcode == 49) {
		return "Protocol driver not attached";
	} else if (errcode == 50) {
		return "No CSI structure available";
	} else if (errcode == 51) {
		return "Level 2 halted";
	} else if (errcode == 52) {
		return "Invalid exchange";
	} else if (errcode == 53) {
		return "Invalid request descriptor";
	} else if (errcode == 54) {
		return "Exchange full";
	} else if (errcode == 55) {
		return "No anode";
	} else if (errcode == 56) {
		return "Invalid request code";
	} else if (errcode == 57) {
		return "Invalid slot";
	} else if (errcode == 58) {
		return "Unknown error 58";
	} else if (errcode == 59) {
		return "Bad font file format";
	} else if (errcode == 60) {
		return "Device not a stream";
	} else if (errcode == 61) {
		return "No data available";
	} else if (errcode == 62) {
		return "Timer expired";
	} else if (errcode == 63) {
		return "Out of streams resources";
	} else if (errcode == 64) {
		return "Machine is not on the network";
	} else if (errcode == 65) {
		return "Package not installed";
	} else if (errcode == 66) {
		return "Object is remote";
	} else if (errcode == 67) {
		return "Link has been severed";
	} else if (errcode == 68) {
		return "Advertise error";
	} else if (errcode == 69) {
		return "Srmount error";
	} else if (errcode == 70) {
		return "Communication error on send";
	} else if (errcode == 71) {
		return "Protocol error";
	} else if (errcode == 72) {
		return "Multihop attempted";
	} else if (errcode == 73) {
		return "RFS specific error";
	} else if (errcode == 74) {
		return "Bad message";
	} else if (errcode == 75) {
		return "Value too large for defined data type";
	} else if (errcode == 76) {
		return "Name not unique on network";
	} else if (errcode == 77) {
		return "File descriptor in bad state";
	} else if (errcode == 78) {
		return "Remote address changed";
	} else if (errcode == 79) {
		return "Can not access a needed shared library";
	} else if (errcode == 80) {
		return "Accessing a corrupted shared library";
	} else if (errcode == 81) {
		return ".lib section in a.out corrupted";
	} else if (errcode == 82) {
		return "Attempting to link in too many shared libraries";
	} else if (errcode == 83) {
		return "Cannot exec a shared library directly";
	} else if (errcode == 84) {
		return "Invalid or incomplete multibyte or wide character";
	} else if (errcode == 85) {
		return "Interrupted system call should be restarted";
	} else if (errcode == 86) {
		return "Streams pipe error";
	} else if (errcode == 87) {
		return "Too many users";
	} else if (errcode == 88) {
		return "Socket operation on non-socket";
	} else if (errcode == 89) {
		return "Destination address required";
	} else if (errcode == 90) {
		return "Message too long";
	} else if (errcode == 91) {
		return "Protocol wrong type for socket";
	} else if (errcode == 92) {
		return "Protocol not available";
	} else if (errcode == 93) {
		return "Protocol not supported";
	} else if (errcode == 94) {
		return "Socket type not supported";
	} else if (errcode == 95) {
		return "Operation not supported";
	} else if (errcode == 96) {
		return "Protocol family not supported";
	} else if (errcode == 97) {
		return "Address family not supported by protocol";
	} else if (errcode == 98) {
		return "Address already in use";
	} else if (errcode == 99) {
		return "Cannot assign requested address";
	} else if (errcode == 100) {
		return "Network is down";
	} else if (errcode == 101) {
		return "Network is unreachable";
	} else if (errcode == 102) {
		return "Network dropped connection on reset";
	} else if (errcode == 103) {
		return "Software caused connection abort";
	} else if (errcode == 104) {
		return "Connection reset by peer";
	} else if (errcode == 105) {
		return "No buffer space available";
	} else if (errcode == 106) {
		return "Transport endpoint is already connected";
	} else if (errcode == 107) {
		return "Transport endpoint is not connected";
	} else if (errcode == 108) {
		return "Cannot send after transport endpoint shutdown";
	} else if (errcode == 109) {
		return "Too many references: cannot splice";
	} else if (errcode == 110) {
		return "Connection timed out";
	} else if (errcode == 111) {
		return "Connection refused";
	} else if (errcode == 112) {
		return "Host is down";
	} else if (errcode == 113) {
		return "No route to host";
	} else if (errcode == 114) {
		return "Operation already in progress";
	} else if (errcode == 115) {
		return "Operation now in progress";
	} else if (errcode == 116) {
		return "Stale file handle";
	} else if (errcode == 117) {
		return "Structure needs cleaning";
	} else if (errcode == 118) {
		return "Not a XENIX named type file";
	} else if (errcode == 119) {
		return "No XENIX semaphores available";
	} else if (errcode == 120) {
		return "Is a named type file";
	} else if (errcode == 121) {
		return "Remote I/O error";
	} else if (errcode == 122) {
		return "Disk quota exceeded";
	} else if (errcode == 123) {
		return "No medium found";
	} else if (errcode == 124) {
		return "Wrong medium type";
	} else if (errcode == 125) {
		return "Operation canceled";
	} else if (errcode == 126) {
		return "Required key not available";
	} else if (errcode == 127) {
		return "Key has expired";
	} else if (errcode == 128) {
		return "Key has been revoked";
	} else if (errcode == 129) {
		return "Key was rejected by service";
	} else if (errcode == 130) {
		return "Owner died";
	} else if (errcode == 131) {
		return "State not recoverable";
	} else if (errcode == 132) {
		return "Operation not possible due to RF-kill";
	} else if (errcode == 133) {
		return "Memory page has hardware error";
	} else {
		return "Unknown error";
	}
}

int ft_isspace(char c) {
	return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}

int ft_isdigit(char c) {
	return c >= '0' && c <= '9';
}

long ft_strtol(const char *nptr, char **endptr) {
	if (nptr == NULL) {
		*endptr = NULL;
		return 0;
	}
	int sign = 1;
	long long res = 0;
	int i = 0;
	while (ft_isspace(nptr[i])) {
		i++;
	}
	if (nptr[i] == '-' || nptr[i] == '+') {
		sign = (nptr[i] == '-' ? -1 : 1);
		i++;
	}
	while (nptr[i] != '\0' && ft_isdigit(nptr[i])) {
		int digit = nptr[i] - '0';
		if (sign == 1) {
			if (res * 10 + digit < 0) {
				errno = ERANGE;
				return __LONG_LONG_MAX__;
			}
		} else {
			if (-res * 10 - digit > 0) {
				errno = ERANGE;
				return -(__LONG_LONG_MAX__) - 1;
			}
		}
		res *= 10;
		res += digit;
		i++;
	}
	if (endptr != NULL) {
		*endptr = (char *)(nptr + i);
	}
	return res * sign;
}
