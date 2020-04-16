/*
Tomasz Stachowski
309675
*/

#include "router.h"
#include "error.h"

std::list<struct entry> routing;
std::vector<struct entry> neighbours;
std::vector<in_addr_t> my_addresses;
std::vector<struct message> broadcasts;
std::vector<in_addr_t> ignored; // we want to ignore routing entries about unreachable networks after some time
int sockfd;
int broadcast_permission;

void router()
{
    get_configuration();
    set_up_socket();

    while (true)
    {
        print_routing();
        sleep(TURN / 2);
        handle_timeouts();
        get_broadcasts();
        analyze_broadcasts();
        broadcast();
        print_routing();
        sleep(TURN / 2);
    }

    close(sockfd);
}

void set_up_socket()
{
    sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_address;
    bzero(&server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    Bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address));
    broadcast_permission = 1;
    Setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_permission, sizeof(broadcast_permission));
}

void delete_garbage_routing_entries()
{
    for (auto i = routing.begin(); i != routing.end();)
    {
        if (i->garbage)
            i = routing.erase(i);
        else
            ++i;
    }
}

in_addr_t network_ip_hostorder(in_addr_t ip_hostorder, unsigned netmask)
{
    return ip_hostorder & (0xffffffff << (32 - netmask));
}

in_addr_t network_ip_netorder(in_addr_t ip_netorder, unsigned netmask)
{
    return htonl(ntohl(ip_netorder) & (0xffffffff << (32 - netmask)));
}

in_addr_t broadcast_ip_netorder(in_addr_t ip_netorder, unsigned netmask)
{
    return htonl(ntohl(ip_netorder) | (~(0xffffffff << (32 - netmask))));
}

in_addr_t broadcast_ip_hostorder(in_addr_t ip_hostorder, unsigned netmask)
{
    return ip_hostorder | (~(0xffffffff << (32 - netmask)));
}

void get_configuration()
{
    routing.clear();
    int n, slash_pos, nm_begin, temp;
    std::cin >> n;
    std::string input;
    char ip_str[20];
    char netmask_str[5];
    struct entry current_entry;
    for (int i = 0; i < n; i++)
    {
        std::cin >> input;
        slash_pos = input.find_first_of('/');
        temp = input.copy(ip_str, slash_pos, 0);
        ip_str[temp] = '\0';
        nm_begin = temp + 1;
        temp = input.copy(netmask_str, input.size() - nm_begin + 1, nm_begin);
        netmask_str[temp] = '\0';
        std::cin >> input;
        std::cin >> input;
        current_entry.distance = std::stoi(input, NULL, 10);
        Inet_pton(AF_INET, ip_str, &current_entry.ip);
        current_entry.netmask = atoi(netmask_str);
        current_entry.neighbour = true;
        current_entry.via = 0;
        current_entry.timeout = STARTING_TIMEOUT;
        current_entry.garbage = false;
        my_addresses.push_back(current_entry.ip);
        current_entry.ip = network_ip_netorder(current_entry.ip, current_entry.netmask);
        neighbours.push_back(current_entry);
        current_entry.timeout = TIMEOUT_TO_DEL_ENTRY;
        routing.push_back(current_entry);
    }
}

void print_routing()
{
    char ip_str[20];
    char via_str[20];
    for (auto &e : routing)
    {
        Inet_ntop(AF_INET, &e.ip, ip_str, 20);
        Inet_ntop(AF_INET, &e.via, via_str, 20);
        std::cout << ip_str << '/' << e.netmask << " ";
        if (e.distance < UNREACHABLE_DISTANCE)
        {
            std::cout << "distance " << e.distance << " ";
            if (e.neighbour)
                std::cout << "connected directly" << std::endl;
            else
                std::cout << "via " << via_str << std::endl;
        }
        else
        {
            std::cout << "unreachable ";
            if (is_neighbour(e.ip))
                std::cout << "connected directly" << std::endl;
            else
                std::cout << "not directly connected" << std::endl;
        }
    }
    std::cout << std::endl;
}

void mark_routing_entries_as_unreachable(struct entry neigh, bool net_down)
{
    for (auto &e : routing)
    {
        if ((neigh.ip == network_ip_netorder(e.via, neigh.netmask)) && !e.neighbour) // function is called after neighbour timeout, we dont want to erase the neighbour's network because of it
            if (e.distance < UNREACHABLE_DISTANCE)
            {
                e.distance = UNREACHABLE_DISTANCE;
                e.timeout = TIMEOUT_TO_DEL_ENTRY;
            }
        if (net_down)
            if (e.ip == neigh.ip && e.neighbour)
                if (e.distance < UNREACHABLE_DISTANCE)
                {
                    e.distance = UNREACHABLE_DISTANCE;
                    e.timeout = TIMEOUT_TO_DEL_ENTRY;
                }
    }
}

void ignore(in_addr_t ip)
{
    bool already_ignored = false;
    for (auto &a : ignored)
        if (a == ip)
            already_ignored = true;
    if (!already_ignored)
        ignored.push_back(ip);
}

void dont_ignore(in_addr_t ip)
{
    for (size_t i = 0; i < ignored.size(); i++)
        if (ignored[i] == ip)
            ignored.erase(ignored.begin() + i);
}
bool is_ignored(in_addr_t ip)
{
    for (auto &a : ignored)
        if (a == ip)
            return true;
    return false;
}

void handle_timeouts()
{
    // marking new entries as unreachable based on neighbours' timeout
    for (auto &n : neighbours)
    {
        n.timeout--;
        if (n.timeout <= 0)
        {
            n.timeout = 0; // underflow prevention
            mark_routing_entries_as_unreachable(n, false);
        }
    }

    // marking old unreachable entries as garbage
    for (auto &e : routing)
        if (e.distance >= UNREACHABLE_DISTANCE)
        {
            e.timeout--;
            if (e.timeout <= 0)
            {
                ignore(e.ip);
                e.garbage = true;
            }
        }

    // deleting garbage routing entries
    delete_garbage_routing_entries();
}

void get_broadcasts()
{
    ssize_t packet_len = 0;
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];
    struct message m;
    long dist_netorder;

    while (1)
    {
        packet_len = Recvfrom(sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&sender, &sender_len);
        if (packet_len == -1) // Recvfrom returned so packet_len == -1 implies errno == EWOULDBLOCK
            break;

        m.sender = sender;
        m.ip = ((in_addr_t)buffer[0] << 24) | ((in_addr_t)buffer[1] << 16) | ((in_addr_t)buffer[2] << 8) | (buffer[3]);
        m.netmask = buffer[4];
        dist_netorder = ((in_addr_t)buffer[5] << 24) | ((in_addr_t)buffer[6] << 16) | ((in_addr_t)buffer[7] << 8) | (buffer[8]);
        m.distance = (long long)ntohl(dist_netorder);
        broadcasts.push_back(m);
    }
}

bool is_neighbour(in_addr_t ip)
{
    for (auto &n : neighbours)
        if (ip == n.ip)
            return true;
    return false;
}

bool is_address_mine(in_addr_t ip)
{
    for (auto &a : my_addresses)
        if (a == ip)
            return true;
    return false;
}

void reset_neighbour_timeout(in_addr_t ip)
{
    for (auto &n : neighbours)
        if (network_ip_netorder(ip, n.netmask) == n.ip)
        {
            n.timeout = STARTING_TIMEOUT;
            return;
        }
}

long long get_neighbour_distance(in_addr_t ip)
{
    for (auto &n : neighbours)
        if (network_ip_netorder(ip, n.netmask) == n.ip)
            return n.distance;
    return UNREACHABLE_DISTANCE;
}

unsigned int get_neighbour_netmask(in_addr_t ip)
{
    for (auto &n : neighbours)
        if (network_ip_netorder(ip, n.netmask) == n.ip)
            return n.netmask;
    return 0;
}

long long get_network_distance(in_addr_t ip)
{
    for (auto &e : routing)
        if (ip == e.ip)
            return e.distance;
    return 0; // 0 means theres no such entry in the 'routing' list
}

void update_routing_entry(struct message m)
{
    bool entry_exists = false;
    bool neighbour_exists = false;
    struct entry elem1, elem2;
    struct entry *entry_ptr = &elem1;
    struct entry *neighbour_ptr = &elem2;
    for (auto &e : routing)
        if (m.ip == e.ip)
        {
            entry_exists = true;
            entry_ptr = &e;
            break;
        }

    for (auto &e : routing)
        if (network_ip_netorder(m.sender.sin_addr.s_addr, e.netmask) == e.ip)
        {
            neighbour_exists = true;
            neighbour_ptr = &e;
            break;
        }

    long long dist_to_neigh = get_neighbour_distance(m.sender.sin_addr.s_addr);
    entry_ptr->ip = m.ip;
    entry_ptr->netmask = m.netmask;
    entry_ptr->garbage = false;
    if (dist_to_neigh + m.distance < UNREACHABLE_DISTANCE)
        entry_ptr->timeout = TIMEOUT_TO_DEL_ENTRY;
    // it is safe to set timeout here, because the only case we call this function and ip is ignored is when it is the first time we get a broadcast about it
    if (is_ignored(entry_ptr->ip))
        entry_ptr->timeout = TIMEOUT_TO_DEL_ENTRY;
    if (entry_exists)
    {
        if (m.sender.sin_addr.s_addr == entry_ptr->via)
        {
            entry_ptr->neighbour = false;
            entry_ptr->distance = m.distance + dist_to_neigh; //m.distance can be as big as 0xffffffff and our unreachable distance is only UNREACHABLE_DISTANCE, but it isnt a problem
        }
        else if (dist_to_neigh + m.distance < entry_ptr->distance)
        {
            entry_ptr->neighbour = false;
            entry_ptr->distance = dist_to_neigh + m.distance;
            entry_ptr->via = m.sender.sin_addr.s_addr;
        }
    }
    else // !entry_exists
    {
        entry_ptr->neighbour = false;
        entry_ptr->distance = dist_to_neigh + m.distance;
        entry_ptr->via = m.sender.sin_addr.s_addr;
        entry_ptr->timeout = TIMEOUT_TO_DEL_ENTRY;
        routing.push_back(elem1);
    }

    neighbour_ptr->garbage = false;
    neighbour_ptr->distance = dist_to_neigh;
    neighbour_ptr->neighbour = true;
    neighbour_ptr->netmask = get_neighbour_netmask(m.sender.sin_addr.s_addr);
    neighbour_ptr->ip = network_ip_netorder(m.sender.sin_addr.s_addr, neighbour_ptr->netmask);

    if (!neighbour_exists)
    {
        elem2.timeout = TIMEOUT_TO_DEL_ENTRY;
        routing.push_back(elem2);
    }
}

void successful_sendto(struct entry neigh)
{
    bool entry_exists = false;
    struct entry elem;
    struct entry *entry_ptr = &elem;
    for (auto &e : routing)
        if (neigh.ip == e.ip)
        {
            entry_exists = true;
            entry_ptr = &e;
            break;
        }
    entry_ptr->ip = neigh.ip;
    entry_ptr->garbage = false;
    entry_ptr->distance = neigh.distance;
    entry_ptr->neighbour = true;
    entry_ptr->netmask = neigh.netmask;
    entry_ptr->timeout = TIMEOUT_TO_DEL_ENTRY;
    entry_ptr->via = 0;
    if (!entry_exists)
        routing.push_back(elem);
}

void analyze_broadcasts()
{
    for (auto &m : broadcasts)
    {
        if (is_address_mine(m.sender.sin_addr.s_addr)) // we can read our own broadcast and want to ignore it
            continue;
        reset_neighbour_timeout(m.sender.sin_addr.s_addr);
        if ((m.distance >= UNREACHABLE_DISTANCE) && (get_network_distance(m.ip) == 0))
            continue;
        if ((m.distance >= UNREACHABLE_DISTANCE) && (get_network_distance(m.ip) >= UNREACHABLE_DISTANCE))
        {
            if (is_ignored(m.ip))
                continue;
            else
                ignore(m.ip);
        }
        else
            dont_ignore(m.ip);
        update_routing_entry(m);
    }
    broadcasts.clear();
}

void construct_packet_data(char *packet, struct entry e)
{
    packet[0] = e.ip >> 24;
    packet[1] = (e.ip & 0x00ff0000) >> 16;
    packet[2] = (e.ip & 0x0000ff00) >> 8;
    packet[3] = e.ip & 0x000000ff;
    packet[4] = e.netmask & 0xff;
    if (e.distance >= UNREACHABLE_DISTANCE)
    {
        packet[5] = 0xff;
        packet[6] = 0xff;
        packet[7] = 0xff;
        packet[8] = 0xff;
    }
    else
    {
        long dist_netorder = htonl((long)(e.distance & 0xffffffff));
        packet[5] = dist_netorder >> 24;
        packet[6] = (dist_netorder & 0x00ff0000) >> 16;
        packet[7] = (dist_netorder & 0x0000ff00) >> 8;
        packet[8] = dist_netorder & 0x000000ff;
    }
}

void broadcast()
{
    struct sockaddr_in address;
    char packet[20];
    int bytes_sent;
    for (auto &n : neighbours)
    {
        bzero(&address, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(PORT);
        address.sin_addr.s_addr = broadcast_ip_netorder(n.ip, n.netmask);
        for (auto &e : routing)
        {

            construct_packet_data(packet, e);
            bytes_sent = Sendto(sockfd, packet, 9, MSG_DONTROUTE, (struct sockaddr *)&address, sizeof(address));
            if (bytes_sent == -1) // Sendto returned, so bytes_sent == -1 implies errno == ENETUNREACH
            {
                n.timeout = 0;
                mark_routing_entries_as_unreachable(n, true);
                delete_garbage_routing_entries(); // its safe, because were calling it just before break;
                break;
            }
            else
                successful_sendto(n);
        }
    }
}
