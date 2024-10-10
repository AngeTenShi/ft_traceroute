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

char *dns_lookup(char *addr, struct sockaddr_in *addr_con)
{
	// get the ip address of the host from the hostname with getaddrinfo
	struct addrinfo hints = {0}, *res = NULL;
	int ret = 0;
	char ip[INET_ADDRSTRLEN];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(addr, NULL, &hints, &res);
	if (ret != 0)
		return (NULL);
	char *ret_buf = NULL;
	struct addrinfo *p = res;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
	void *address = &(ipv4->sin_addr);
	inet_ntop(p->ai_family, address, ip, sizeof(ip));
	ret_buf = (char *)malloc((strlen(ip) + 1) * sizeof(char));
	strcpy(ret_buf, ip);
	memcpy(addr_con, ipv4, sizeof(struct sockaddr_in));
	freeaddrinfo(res);
	return (ret_buf);
}

char *create_icmp_packet(int sequence_number, int packet_size)
{
	char *packet;
	struct icmphdr *icmp;
	packet = (char *)malloc(packet_size);
	icmp = (struct icmphdr *)packet;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = sequence_number;
	icmp->un.echo.id = getpid();
	memset(packet + sizeof(struct icmphdr) , 'A', packet_size - sizeof(struct icmphdr));
	icmp->checksum = checksum((unsigned short *)packet, packet_size);
	return (packet);
}

char *create_udp_packet(int packet_size, int port, struct sockaddr_in *src_addr, struct sockaddr_in *dest_addr)
{
	char *packet;
	struct udphdr *udp;
	packet = (char *)malloc(packet_size);
	udp = (struct udphdr *)packet;
	udp->source = src_addr->sin_port;
	printf("port sent from src: %d\n", ntohs(udp->source));
	udp->dest = htons(port);  
	udp->len = htons(packet_size);
	udp->check = 0;
	memset(packet + sizeof(struct udphdr), 'A', packet_size - sizeof(struct udphdr));
	return (packet);
}

void ft_traceroute(int socket_fd, struct sockaddr_in *traceroute_addr, char *hostname, char *dest_ip, t_options *opts)
{
	int i = 0;
	char *packet = NULL;
	int retry = 3;
	int packet_size = 84;
	char *p = NULL;
	char ip[INET_ADDRSTRLEN];
	struct timeval start_time, end_time;
	printf("traceroute to %s (%s), %d hops max\n", hostname, dest_ip, opts->max_hops);
	for (int ttl = opts->first_ttl; ttl <= opts->max_hops; ttl++)
	{
		setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		if (opts->method == 0)
			packet = create_icmp_packet(i, 84);
		else
		{
			packet = create_udp_packet(32, opts->port, traceroute_addr, traceroute_addr);
			packet_size = 40;
		}
		struct timeval tv_out;
		tv_out.tv_sec = 5;
		tv_out.tv_usec = 0;
		gettimeofday(&start_time, NULL);
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(socket_fd, &readfds);
		int ret = select(socket_fd + 1, &readfds, NULL, NULL, &tv_out);
		if (sendto(socket_fd, packet, packet_size, 0, (struct sockaddr *)traceroute_addr, sizeof(*traceroute_addr)) <= 0)
		{
			print_error("sendto failed");
			free(packet);
			packet = NULL;
			return;
		}
		if (ret == 0)
		{
			if (retry == 3)
				printf("  %d\t*", ttl);
			else
				printf(" *");
			fflush(stdout);
		}
		else
		{
			if (FD_ISSET(socket_fd, &readfds))
			{
				p = (char *)malloc(0x10000);
				struct sockaddr_in r_addr;
				socklen_t addr_len = sizeof(r_addr);
				recvfrom(socket_fd, p, 0x10000, 0, (struct sockaddr *)&r_addr, &addr_len);
				gettimeofday(&end_time, NULL);
				double rtt_msec = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0;
				struct iphdr *ip_hdr = (struct iphdr *)p;
				inet_ntop(AF_INET, &(ip_hdr->saddr), ip, INET_ADDRSTRLEN);
				if (retry == 3)
				{
					if (opts->resolve_dns)
					{
						char *temp_host = reverse_dns_lookup(inet_ntoa(r_addr.sin_addr));
						printf("  %d   %s (%s)  %.3fms", ttl, ip, temp_host, rtt_msec);
						free(temp_host);
					}
					else
						printf("  %d   %s  %.3fms", ttl, ip, rtt_msec);
					fflush(stdout);
				}
				else
					printf("  %.3fms", rtt_msec);
				free(p);
				p = NULL;
			}
		}
		if (retry > 0)
		{
			ttl--;
			retry--;
		}
		if (retry == 0)
		{
			printf("\n");

			if (strncmp(ip, dest_ip, strlen(dest_ip)) == 0)
			{
				free(packet);
				FD_CLR(socket_fd, &readfds);
				packet = NULL;
				break;
			}
			retry = 3;
			ttl++;
		}
		free(packet);
		packet = NULL;
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
	int socket_fd = -1;
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
	if (socket_fd < 0)
	{
		print_error("Lack of privileges");
		free(ip_addr);
		free(options);
		return (1);
	}
	addr_con.sin_family = AF_INET;
	addr_con.sin_port = htons(0);
	addr_con.sin_addr.s_addr = inet_addr(ip_addr);
	ft_traceroute(socket_fd, &addr_con, hostname, ip_addr, options);
	free(ip_addr);
	free(options);
	return (0);
}
