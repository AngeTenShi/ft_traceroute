#include "ft_traceroute.h"

int do_ping = 1;

unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;
	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return (result);
}

char *reverse_dns_lookup(char *ip)
{
	struct sockaddr_in temp_addr;
	socklen_t len;
	char buf[NI_MAXHOST], *ret_buf;
	temp_addr.sin_family = AF_INET;
	temp_addr.sin_addr.s_addr = inet_addr(ip);
	len = sizeof(struct sockaddr_in);
	if (getnameinfo((struct sockaddr *)&temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD))
		return (NULL);
	ret_buf = (char *)malloc((strlen(buf) + 1) * sizeof(char));
	strcpy(ret_buf, buf);
	return (ret_buf);
}

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) {
    struct hostent *host_entity;
    char *ip = (char *)malloc(NI_MAXHOST * sizeof(char));

    if ((host_entity = gethostbyname(addr_host)) == NULL) {
        return (NULL);
    }
    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr)); // Convert IP into string
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons(0);
    (*addr_con).sin_addr.s_addr = *(long *)host_entity->h_addr; // Copy IP address from DNS to addr_con

    return ip;
}

char *create_icmp_packet(int sequence_number, int packet_size)
{
	char *packet;
	struct icmp *icmp;
	packet = (char *)malloc(packet_size);
	icmp = (struct icmp *)packet;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = sequence_number;
	icmp->icmp_id = getpid();
	memset(icmp->icmp_data, 0, packet_size);
	icmp->icmp_cksum = checksum((unsigned short *)packet, packet_size);
	return (packet);
}

char *create_udp_packet(int packet_size, int port)
{
	char *packet;
	struct udphdr *udp;
	packet = (char *)malloc(packet_size);
	udp = (struct udphdr *)packet;
	udp->source = htons(port);
	udp->dest = htons(port);
	udp->len = htons(packet_size);
	udp->check = checksum((unsigned short *)packet, packet_size);
	return (packet);
}

void ft_traceroute(int socket_fd, struct sockaddr_in *traceroute_addr, char *hostname, char *dest_ip, t_options *opts)
{
	int i = 0;
	char *packet;
	int retry = 3;
	int packet_size = 84;
	printf("traceroute to %s (%s), %d hops max\n", hostname, dest_ip, opts->max_hops);
	for (int ttl = opts->first_ttl; ttl <= opts->max_hops; ttl++)
	{
		setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		if (opts->method == 0)
			packet = create_icmp_packet(i, 84);
		else
		{
			packet = create_udp_packet(60, opts->port);
			packet_size = 60;
		}
		struct timeval tv_out;
		tv_out.tv_sec = 3;
		tv_out.tv_usec = 0;
		if (sendto(socket_fd, packet, packet_size, 0, (struct sockaddr *)traceroute_addr, sizeof(*traceroute_addr)) <= 0)
		{
			print_error("sendto failed");
			return;
		}
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(socket_fd, &readfds);
		int ret = select(socket_fd + 1, &readfds, NULL, NULL, &tv_out);
		if (ret == 0)
		{
			if (retry == 3)
			{
				printf("  %d\t*", ttl);
				retry--;
				ttl--;
			}
			else if (retry == 0)
			{
				printf("\n");
				retry = 3;
			}
			else
			{
				retry--;
				ttl--;
				printf(" *");
			}
			fflush(stdout);
		}
		else
		{
			if (FD_ISSET(socket_fd, &readfds))
			{
				char *packet = malloc(64);
				struct sockaddr_in r_addr;
				socklen_t addr_len = sizeof(r_addr);
				recvfrom(socket_fd, packet, 64, 0, (struct sockaddr *)&r_addr, &addr_len);
				char *ip = inet_ntoa(r_addr.sin_addr);
				char *hostname = reverse_dns_lookup(ip);
				if (hostname == NULL)
				{
					if (strncmp(ip, dest_ip, strlen(dest_ip)) == 0)
						hostname = ip;
					else
						hostname = dest_ip;
				}
				if (opts->resolve_dns)
					printf("  %d\t%s (%s)\n", ttl, hostname, ip);
				else
					printf("  %d\t%s\n", ttl, ip);
				if (strncmp(ip, dest_ip, strlen(dest_ip)) == 0)
				{
					free(packet);
					break;
				}
				free(packet);
			}
		}
		free(packet);
		i++;
	}
}

int main(int ac, char **av)
{
	t_options *options;
	char *dest_addr;
	struct sockaddr_in addr_con;
	char *ip_addr;
	char *hostname;
	int socket_fd;
	if (ac < 2)
	{
		print_error("missing host operand");
		return (1);
	}
	options = init_options();
	parse_args(ac, av, options);
	dest_addr = av[ac - 1];
	parse_fdqn(&dest_addr); // remove http:// or https:// or www. from the address
	hostname = dest_addr;
	ip_addr = dns_lookup(dest_addr, &addr_con);
	if (ip_addr == NULL)
	{
		char *error = malloc(100 + strlen(dest_addr));
		sprintf(error, "%s: Name or service not known", dest_addr);
		print_error(error);
		free(error);
		free(options);
		return (1);
	}
	if (options->method == 1)
		socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	else
		socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	ft_traceroute(socket_fd, &addr_con, hostname, ip_addr, options);
	free(ip_addr);
	free(options);
	return (0);
}
