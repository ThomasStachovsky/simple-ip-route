#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <list>
#include <iostream>
#include <string>
#include <vector>

#define STARTING_TIMEOUT 3      // wait this many turns before declaring network unreachable
#define TIMEOUT_TO_DEL_ENTRY 3  // wait this many turns before deleting an unreachable network entry
#define UNREACHABLE_DISTANCE 30 // arbitrary constant - used as an indicator of unreachability and as an upper limit in counting to infinity problem
#define PORT 54321              // used port
#define TURN 6                  // time of one turn in seconds, ideally it should be divisible by 2

struct entry
{
    in_addr_t ip;
    unsigned netmask;
    long long distance;
    bool neighbour;
    in_addr_t via;
    int timeout;
    bool garbage = false;
};

struct message
{
    struct sockaddr_in sender;
    in_addr_t ip;
    unsigned netmask;
    long long distance;
};

// struct entry used in both 'routing' list and 'neighbours' vector, however usage of fields in struct entry differs a bit
extern std::list<struct entry> routing;
extern std::vector<struct entry> neighbours;
extern std::vector<in_addr_t> my_addresses;
extern std::vector<struct message> broadcasts;
extern std::vector<in_addr_t> ignored; // we want to ignore routing entries about unreachable networks after some time
extern int sockfd;
extern int broadcast_permission;

void router();
void set_up_socket();
void delete_garbage_routing_entries();
in_addr_t network_ip_hostorder(in_addr_t ip_hostorder, unsigned netmask);
in_addr_t network_ip_netorder(in_addr_t ip_netorder, unsigned netmask);
in_addr_t broadcast_ip_netorder(in_addr_t ip_netorder, unsigned netmask);
in_addr_t broadcast_ip_hostorder(in_addr_t ip_hostorder, unsigned netmask);
void get_configuration();
void print_routing();
void mark_routing_entries_as_unreachable(struct entry neigh, bool net_down);
void handle_timeouts();
void get_broadcasts();
bool is_address_mine(in_addr_t ip);
bool is_neighbour(in_addr_t ip);
void reset_neighbour_timeout(in_addr_t ip);
long long get_neighbour_distance(in_addr_t ip);
unsigned int get_neighbour_netmask(in_addr_t ip);
void update_routing_entry(struct message m);
void successful_sendto(struct entry neigh);
void analyze_broadcasts();
void construct_packet_data(char *packet, struct entry e);
void broadcast();
void ignore(in_addr_t ip);
void dont_ignore(in_addr_t ip);
bool is_ignored(in_addr_t ip);