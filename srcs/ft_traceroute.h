#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <netinet/udp.h>
typedef struct options
{
	int first_ttl; // first hop
	int max_hops; // max hops
	int port; // port
	int method; // 0 = ICMP, 1 = UDP
	int resolve_dns; // resolve DNS
} t_options; // -f ttl -m max_hops -p port -M method

typedef struct icmp_packet
{
	struct icmphdr hdr;
	char *msg;
} t_packet;

typedef struct udp_packet
{
	struct udphdr hdr;
	char *msg;
} t_udp_packet;

void print_usage(void);
void parse_args(int ac, char **av, t_options *options);
t_options *init_options();
void print_error(char *error);
double sqrt(double x);
int	is_ipv4(char *ip);
void parse_fdqn(char **dest_addr);

#endif
