#include "ft_traceroute.h"

void print_usage(void)
{
    printf("Usage:\n");
    printf("  traceroute [options] <destination>\n\n");
    printf("Options:\n");
    printf("  -f <first_ttl>         Set the first TTL value (1-255, default: 1)\n");
    printf("  -m <max_hops>          Set the maximum number of hops (1-255, default: 64)\n");
    printf("  -p <port>              Set the destination port (1-65535, default: 33434)\n");
    printf("  -M <method>            Set the probe method (icmp or udp, default: icmp)\n");
    printf("  --resolve-hostnames    Resolve IP addresses to hostnames\n");
    printf("  --help                 Display this help and exit\n");
}

void parse_args(int ac, char **av, t_options *options)
{
	int i = 0;
	while (i < ac)
	{
		if (av[i][0] == '-')
		{
			if (av[i][1] == '-')
			{
				if (strncmp(av[i], "--resolve-hostnames", 19) == 0)
					options->resolve_dns = 1;
				else if (strncmp(av[i], "--help", 6) == 0)
				{
					print_usage();
					free(options);
					exit(0);
				}
				else
				{
					char *error = malloc(100);
					sprintf(error, "invalid option: '%s'", av[i]);
					print_error(error);
					free(error);
					free(options);
					exit(1);
				}
			}
			if (av[i][1] == 'f')
			{
				if (i + 1 < ac)
				{
					options->first_ttl = atoi(av[i + 1]);
					if (options->first_ttl < 1 || options->first_ttl > 255)
					{
						char *error = malloc(100);
						sprintf(error, "impossible distance: '%d'", options->first_ttl);
						print_error(error);
						free(error);
						free(options);
						exit(1);
					}
					i++;
				}
			}
			if (av[i][1] == 'm')
			{
				if (i + 1 < ac)
				{
					options->max_hops = atoi(av[i + 1]);
					if (options->max_hops < 1 || options->max_hops > 255)
					{
						char *error = malloc(100);
						sprintf(error, "invalid hops value '%d'", options->max_hops);
						print_error(error);
						free(error);
						free(options);
						exit(1);
					}
					i++;
				}
			}
			if (av[i][1] == 'p')
			{
				if (i + 1 < ac)
				{
					options->port = atoi(av[i + 1]);
					if (options->port < 1 || options->port > 65535)
					{
						char *error = malloc(100);
						sprintf(error, "invalid port value '%d'", options->port);
						print_error(error);
						free(error);
						free(options);
						exit(1);
					}
					i++;
				}
			}
			if (av[i][1] == 'M')
			{
				if (i + 1 < ac)
				{
					if (strncmp(av[i + 1], "icmp", 4) == 0 && strlen(av[i + 1]) == 4)
						options->method = 0;
					else if (strncmp(av[i + 1], "udp", 3) == 0 && strlen(av[i + 1]) == 3)
						options->method = 1;
					else
					{
						print_error("invalid method");
						free(options);
						exit(1);
					}
					i++;
				}
			}
		}
		i++;
	}
}

t_options *init_options()
{
	t_options *options;

	options = malloc(sizeof(t_options));
	options->first_ttl = 1;
	options->max_hops = 64;
	options->port = 33434;
	options->method = 1; // default is UDP
	options->resolve_dns = 0;
	return (options);
}

void print_error(char *msg)
{
	printf("traceroute: %s\n", msg);
}

void parse_fdqn(char **dest_addr)
{
	// parse fully qualified domain name
	// if it is a FQDN, remove the domain part https://www.google.com -> google.com https:://google.com -> google.com www.google.com -> google.com
	int i = 0;
	char *str = *dest_addr;
	if (strlen(str) < 4)
		return;
	if (str[0] == 'w' && str[1] == 'w' && str[2] == 'w' && str[3] == '.')
		i = 4;
	else if (str[i] == 'h' && str[i + 1] == 't' && str[i + 2] == 't' && str[i + 3] == 'p' && str[i + 4] == 's' && str[i + 5] == ':' && str[i + 6] == '/' && str[i + 7] == '/')
	{
		if (strlen(str) < 8)
			return;
		if (str[i + 8] == 'w' && str[i + 9] == 'w' && str[i + 10] == 'w' && str[i + 11] == '.')
			i += 12;
		else
			i += 8;
	}
	else if (str[i] == 'h' && str[i + 1] == 't' && str[i + 2] == 't' && str[i + 3] == 'p' && str[i + 4] == ':' && str[i + 5] == '/' && str[i + 6] == '/')
	{
		if (strlen(str) < 7)
			return;
		if (str[i + 7] == 'w' && str[i + 8] == 'w' && str[i + 9] == 'w' && str[i + 10] == '.')
			i += 11;
		else
			i += 7;
	}
	*dest_addr = *dest_addr + i;

}
