
//====================================================================================================================
// File:        main.cpp
// Case:        VUT, FIT, IPK, project 2
// Date:        9. 4. 2021
// Author:      David Mihola
// Contact:     xmihol00@stud.fit.vutbr.cz
// Compiled:    gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
// Description: IP version 4, IP version 6 and ARP packet sniffer, supporting TCP, UDP and ICMP transport protocols.
//====================================================================================================================

#include "sniffer.h"

int main(int argc, char **argv)
{
    // register function that frees used resources
    atexit(free_resources);

    // register signal handler for correct termination at ctr + c
    std::signal(SIGINT, sig_int_handler);

    parsed_args_t data{0, };

    // Parses the command line arguments, constructs the packet filter and provides 
    // the specified interface to be scanned.
    parse_arguments(argc, argv, data);

    // Creates a pcap connection to the specified interface with a given packet filter.
    create_pcap_connection(data.interface, data.filter);

    std::cerr << data.filter << std::endl;

    // Engages the packet collection and their parsing wit hte packet_parser function
    pcap_loop(get_connection(), data.number_of_packets, (pcap_handler) packet_parser, data.flags);

    // Successful termination, all resources are freed at exit.
    exit(0);
}
