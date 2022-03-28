#include "ft_ping.h"

unsigned short cksum(unsigned short *addr, int len);

int main(int argc, char *argv[])
{
    int sock;
    char send_buf[400], recv_buf[400], src_name[256], src_ip[16], dst_ip[16];
    struct ip *ip = (struct ip *)send_buf;
    struct ip *ip2 = (struct ip *)recv_buf;
    struct icmp *icmp = (struct icmp *)(ip + 1);
    struct icmp *icmp2 = (struct icmp *)(ip2 + 1);
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in dst;
    struct timeval t;
    int on;
    int num = 10;
    int failed_count = 0;
    int bytes_sent, bytes_recv;
    int dst_addr_len;
    int result;
    fd_set socks;
    /* Initialize variables */
    on = 1;
    //memset(send_buf, 0, sizeof(send_buf));
    //memset(recv_buf, 0, sizeof(recv_buf));

    /* Check for valid args */
    struct addrinfo hints;
    struct addrinfo *res, *tmp;
    char host[INET_ADDRSTRLEN];
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    int ret = getaddrinfo(argv[1], NULL, &hints, &res);
    printf("ret is %d\n", ret);
    if (ret) {
        printf("%s\n", gai_strerror(ret));
    }
    for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
        getnameinfo(tmp->ai_addr, tmp->ai_addrlen, host, sizeof(host), NULL, 0, NI_NAMEREQD);
        perror("host");
        puts(host);
        /*if (tmp->ai_family == AF_INET) {
            inet_ntop(tmp->ai_family, &((struct sockaddr_in *)tmp->ai_addr)->sin_addr, host, INET_ADDRSTRLEN);
            puts(host);
        }*/
    }
    //getaddrinfo(argv[1], NULL, NULL, &res);
    //printf("----> '%s' '%s'\n", res->ai_canonname, res->ai_addr->sa_data);
    if(argc < 2)
    {
        printf("\nUsage: %s <dst_server>\n", argv[0]);
        printf("- dst_server is the target\n");
        exit(EXIT_FAILURE);
    }

    /* Check for root access */
    if (getuid() != 0)
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    for(int i = 1; i <= num; i++)
    {
    struct addrinfo hints;
    struct addrinfo *res, *tmp;
    char host[INET_ADDRSTRLEN];
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    int ret = getaddrinfo(argv[1], NULL, &hints, &res);
    printf("ret is %d\n", ret);
    if (ret) {
        printf("%s\n", gai_strerror(ret));
    }
    for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
        getnameinfo(tmp->ai_addr, tmp->ai_addrlen, host, sizeof(host), NULL, 0, NI_NAMEREQD);
        puts(host);
        /*if (tmp->ai_family == AF_INET) {
            inet_ntop(tmp->ai_family, &((struct sockaddr_in *)tmp->ai_addr)->sin_addr, host, INET_ADDRSTRLEN);
            puts(host);
        }*/
    }
    /* Get source IP address */
    if(gethostname(src_name, sizeof(src_name)) < 0)
    {
        perror("gethostname() error");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("src_name '%s'\n", src_name);
        if((src_hp = gethostbyname("0.0.0.0")) == NULL)
        {
            fprintf(stderr, "%s: Can't resolve, unknown source.\n", src_name);
            exit(EXIT_FAILURE);
        }
        else
        {
            ip->ip_src = (*(struct in_addr *)src_hp->h_addr);
        }
    }

    /* Get destination IP address */
    if((dst_hp = gethostbyname(argv[1])) == NULL)
    {
        if((ip->ip_dst.s_addr = inet_addr(argv[1])) == -1)
        {
            fprintf(stderr, "%s: Can't resolve, unknown destination.\n", argv[1]);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        ip->ip_dst = (*(struct in_addr *)dst_hp->h_addr);
        dst.sin_addr = (*(struct in_addr *)dst_hp->h_addr);
    }

    sprintf(src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(dst_ip, "%s", inet_ntoa(ip->ip_dst));
    printf("Source IP: '%s' -- Destination IP: '%s'\n", src_ip, dst_ip);

    /* Create RAW socket */
    if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket() error");

        /* If something wrong, just exit */
        exit(EXIT_FAILURE);
    }

    /* Socket options, tell the kernel we provide the IP structure */
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt() for IP_HDRINCL error");
        exit(EXIT_FAILURE);
    }

    /* IP structure, check the ip.h */
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(send_buf));
    ip->ip_id = htons(321);
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_sum = 0;

    /* ICMP structure, check ip_icmp.h */
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = 123;
    icmp->icmp_seq = 0;

    /* Set up destination address family */
    dst.sin_family = AF_INET;

    /* Loop based on the packet number */
    struct timeval tv;
        /* Header checksums */
        icmp->icmp_cksum = 0;
        ip->ip_sum = cksum((unsigned short *)send_buf, ip->ip_hl);
        icmp->icmp_cksum = cksum((unsigned short *)icmp,
                           sizeof(send_buf) - sizeof(struct icmp));

        /* Get destination address length */
        dst_addr_len = sizeof(dst);

        /* Set listening timeout */
        t.tv_sec = 5;
        t.tv_usec = 0;

        /* Set socket listening descriptors */
        //FD_ZERO(&socks);
        //FD_SET(sock, &socks);

        /* Send packet */
        gettimeofday(&tv, NULL);
        printf("--- begin %ld %ld\n", tv.tv_sec, tv.tv_usec);
        if((bytes_sent = sendto(sock, send_buf, sizeof(send_buf), 0,
                         (struct sockaddr *)&dst, dst_addr_len)) < 0)
        {
            perror("sendto() error");
            failed_count++;
            printf("Failed to send packet.\n");
            fflush(stdout);
        }
        else
        {
            printf("Sent %d byte packet... ", bytes_sent);
            printf(" %d %d ... ", icmp->icmp_code, icmp->icmp_type);

            fflush(stdout);

            /* Listen for the response or timeout */
            /*if((result = select(sock + 1, &socks, NULL, NULL, &t)) < 0)
            {
                perror("select() error");
                failed_count++;
                printf("Error receiving packet!\n");
            }
            else if (result > 0)
            {*/
                printf("Waiting for packet... ");
                fflush(stdout);

                if((bytes_recv = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                        (struct sockaddr *)&dst, (socklen_t *)&dst_addr_len)) < 0)
                {
                    perror("recvfrom() error");
                    failed_count++;
                    fflush(stdout);
                }
                else {
                    gettimeofday(&tv, NULL);
                    printf("--- end %ld %ld\n", tv.tv_sec, tv.tv_usec);
                    printf("Received %d byte packet ! ", bytes_recv);
                    if (icmp2->icmp_type == ICMP_DEST_UNREACH || icmp2->icmp_code == ICMP_HOST_UNREACH) {
                        printf(" host unreachable\n");
                    }
                    printf(" %d %d ... \n", icmp2->icmp_code, icmp2->icmp_type);

                }
            /*}
            else
            {
                printf("Failed to receive packet!\n");
                failed_count++;
            }*/

            fflush(stdout);
            memset(recv_buf, 0, sizeof(recv_buf));
            //memset(send_buf, 0, sizeof(recv_buf));
            // ip->ip_v = 4;
            // ip->ip_hl = 5;
            // ip->ip_tos = 0;
            // ip->ip_len = htons(sizeof(send_buf));
            // ip->ip_id = htons(321);
            // ip->ip_off = htons(0);
            // ip->ip_ttl = 255;
            // ip->ip_p = IPPROTO_ICMP;
            // ip->ip_sum = 0;

            // /* ICMP structure, check ip_icmp.h */
            // icmp->icmp_type = ICMP_ECHO;
            // icmp->icmp_code = 0;
            // icmp->icmp_id = 123;
            icmp->icmp_seq++;
        }
        //sleep(1);
    }

    /* Display success rate */
    printf("Ping test completed with %d%% success rate.\n",
           (((num - failed_count) / num) * 100));

    /* close socket */
    close(sock);

    return 0;
}

/* One's Complement checksum algorithm */
unsigned short cksum(unsigned short *addr, int len)
{
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
