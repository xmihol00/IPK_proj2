
//====================================================================================================================
// File:        sniffer.cpp
// Case:        VUT, FIT, IPK, project 2
// Date:        24. 4. 2021
// Author:      David Mihola
// Contact:     xmihol00@stud.fit.vutbr.cz
// Compiled:    gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
// Description: IP version 4, IP version 6 and ARP packet sniffer, supporting TCP, UDP and ICMP transport protocols.
//====================================================================================================================

#include "sniffer.h"

// IP version 4 Ether type
static const unsigned short IPV4{0x0800};

// IP version 6 Ether type
static const unsigned short IPV6{0x86DD};

// ARP Ether type
static const unsigned short ARP{0x0806};

// Maximum packet size
static const unsigned short MAX_PACKET_SIZE{0xFFFF};

// Ethernet header offset in bytes
static const unsigned short ETH_OFFSET{14};

// ARP packet type offset
static const unsigned short ARP_PTYPE_OFFSET{2};

// ARP sender IP adress offset in bytes
static const unsigned short ARP_SIP_OFFSET{14};

// ARP target IP adress offset in bytes
static const unsigned short ARP_TIP_OFFSET{24};

// Offset of the ARP header in bytes
static const unsigned short ARP_HEADER_OFFSET{28};

// Offset of the ICMP header in bytes
static const unsigned short ICMP_HEADER_OFFSET{8};

// Offset of the IP version 6 header in bytes
static const unsigned short IPV6_HEADER_OFFSET{40};

/**
 * @struct Global structure, which holds a pointer to a pcap interface connection
 **/ 
struct
{
    pcap_t *connection;
} Memory_management = {.connection = nullptr};

// ========================================= inline functions =========================================

extern inline void print_usage_message(bool err_output);

extern inline void parse_mac_address(const u_char *data, char *mac_addr);

extern inline void parse_ethernet_header(const u_char *data, char *dst_mac_addr, char *src_mac_addr, 
                                    unsigned short &network_header_type);

extern inline void parse_time(const struct pcap_pkthdr *header, char *time_str);

extern inline void parse_extension_headers(const u_char *data, unsigned char &header_type, unsigned short &offset, 
                                           bpf_u_int32 max_len, std::stringstream &stream);

extern inline void parse_tcp_udp(const u_char *data, unsigned short &src_port, unsigned short &dst_port);

// ======================================= non inline functions =======================================

void free_resources()
{
    if (Memory_management.connection != nullptr)
    {
        pcap_close(Memory_management.connection);
        Memory_management.connection = nullptr;
    }
}

void sig_int_handler(int sig)
{
    (void) sig; // dummy required by signal function
    exit(0);
}

pcap_t *get_connection()
{
    return Memory_management.connection;
}

void parse_arguments(int argc, char **argv, parsed_args_t &data)
{
    bool tcp{false}, udp{false}, arp{false}, icmp{false}, interface_in{false}, port{false}, hostv4{false}, hostv6{false}, n{false};
    char *hostv4_ptr{nullptr}, *hostv6_ptr{nullptr};
    char num_text[64]{0, };
    long converter{0};
    unsigned short port_number{0};
    char *endptr{nullptr};
    int c{-1};
    char tmp_filter[512]{0, };

    // acceptable long options
    static struct option long_options[] =
    {
        {"tcp",       0, NULL, 't'},
        {"udp",       0, NULL, 'u'},
        {"arp",       0, NULL, 'a'},
        {"icmp",      0, NULL, 'x'},
        {"interface", 2, NULL, 'i'},
        {"help",      0, NULL, 'h'},
        {"mac",       0, NULL, 'm'},
        {"type",      0, NULL, 'y'},
        {"hostv4",    1, NULL, '4'},
        {"hostv6",    1, NULL, '6'},
        {NULL,        0, NULL,  0 }
    };

    // set up the packet filter
    data.filter[0] = '(';
    data.filter[1] = '(';
    data.filter[2] = '\0';

    // set default number of packets to be reciedved
    data.number_of_packets = 1;

    while ((c = getopt_long(argc, argv, "hi::p:tun:", long_options, NULL)) != -1)
    {
        switch (c)
        {
            case 'h':
                print_usage_message(false);
                exit(0);
                break;

            case 'i':
                if (optarg != nullptr)
                {
                    if (data.interface != nullptr)
                    {
                        std::cerr << "Warning: -i or --interface option specified more than once, last will be used." << std::endl;
                    }
                    data.interface = optarg;
                }
                else
                {
                    if (optind < argc && argv[optind][0] != '-')
                    {
                        data.interface = argv[optind];
                        optind++;
                    }
                    else
                    {
                        print_all_interfaces();
                        exit(0); // success
                    }
                }
                interface_in = true; // signalize, that interface was specified
                break;

            case 'p':
                converter = strtol(optarg, &endptr, 10);
                if (converter < 0L || converter > 0xFFFFL)
                {
                    std::cerr << "Error: Port number out of range. Acceptable values are between 0 and 65535." << std::endl;
                    exit(1);
                }
                else if (endptr != nullptr && *endptr != '\0')
                {
                    std::cerr << "Error: -p option must be followed by a number between 0 and 65535." << std::endl;
                    exit(1); // failure
                }

                if (port)
                {
                    std::cerr << "Warning: Port number entered more than once, last one will be used." << std::endl;
                }
                port = true; // signalize that port was specified
                port_number = (unsigned short)converter;
                break;

            case 't':
                tcp = true; // make sure TCP constraint will be added
                break;
            
            case 'u':
                udp = true; // make sure UDP constraint will be added
                break;

            case 'a':
                arp = true; // make sure ARP constraint will be added
                break;
            
            case 'x':
                icmp = true; // make sure ICMP constraint will be added
                break;
            
            case 'n':
                converter = strtol(optarg, &endptr, 10);
                if (converter < -1L || converter > (long) INT_MAX)
                {
                    std::cerr << "Error: Packet number out of range. Acceptable values are between -1 and 2147483647." << std::endl;
                    exit(1);
                }
                else if (endptr != nullptr && *endptr != '\0')
                {
                    std::cerr << "Error: -p option must be followed by a number between -1 and 2147483647." << std::endl;
                    exit(1); // failure
                }
                if (n)
                {
                    std::cerr << "Warning: Number of scanned packets specified more than once, last one will be used." << std::endl;
                }
                n = true;
                data.number_of_packets = (int)converter;
                break;
            
            case 'm':
                data.flags[0] = 1;
                break;
            
            case 'y':
                data.flags[1] = 1;
                break;
            
            case '4':
                hostv4_ptr = optarg;
                hostv4 = true;
                break;
            
            case '6':
                hostv6_ptr = optarg;
                hostv6 = true;
                break;

            // unknown options
            case '?':
            case ':':
                print_usage_message(true);
                exit(1); // failure
                break;

            default:
                print_usage_message(true);
                exit(1); // failure
                break;
        }
    }

    if (!interface_in)
    {
        // interface was not specified
        print_all_interfaces();
        exit(0); // sucess
    }

    sprintf(num_text, "%d) or ", port_number);
    if (arp || icmp || tcp || udp)
    {
        if (port)
        {
            if (arp)
            {
                strcat(data.filter, "arp or ");
            }
            if (icmp)
            {
                strcat(data.filter, "ip protochain \\icmp or ip6 protochain \\icmp or icmp6 or ");
            }
            if (tcp)
            {
                strcat(data.filter, "((ip protochain \\tcp or ip6 protochain \\tcp) and port ");
                strcat(data.filter, num_text);
            }
            if (udp)
            {
                strcat(data.filter, "((ip protochain \\udp or ip6 protochain \\udp) and port ");
                strcat(data.filter, num_text);
            }
            data.filter[strlen(data.filter) - 4] = ')';
            data.filter[strlen(data.filter) - 3] = '\0';
        }
        else
        {
            if (arp)
            {
                strcat(data.filter, "arp or ");
            }
            if (icmp)
            {
                strcat(data.filter, "ip protochain \\icmp or ip6 protochain \\icmp or icmp6 or ");
            }
            if (tcp)
            {
                strcat(data.filter, "ip protochain \\tcp or ip6 protochain \\tcp or ");
            }
            if (udp)
            {
                strcat(data.filter, "ip protochain \\udp or ip6 protochain \\udp or ");
            }
            data.filter[strlen(data.filter) - 4] = ')';
            data.filter[strlen(data.filter) - 3] = '\0';
        }
    }
    else
    {
        if (port)
        {
            strcat(data.filter, /*"arp or ip protochain \\icmp or ip6 protochain \\icmp or icmp6 or "*/
                                "((ip protochain \\tcp or ip6 protochain \\tcp) and port ");
            strcat(data.filter, num_text);
            strcat(data.filter, "((ip protochain \\udp or ip6 protochain \\udp) and port ");
            strcat(data.filter, num_text);
            data.filter[strlen(data.filter) - 4] = ')';
            data.filter[strlen(data.filter) - 3] = '\0';
        }
        else
        {
            strcat(data.filter, "arp or ip protochain \\udp or ip protochain \\tcp or ip protochain \\icmp or "
                                "ip6 protochain \\udp or ip6 protochain \\tcp or ip6 protochain \\icmp or icmp6)");
        }
    }

    if (!hostv4 && !hostv6)
    {
        // complete the filter and return
        strcat(data.filter, ")");
        return;
    }

    strcpy(tmp_filter, data.filter);

    if (hostv4)
    {
        // add IPv4 address to the filter if specified
        strcat(data.filter, " and ip host ");
        strcat(data.filter, hostv4_ptr);
        strcat(data.filter, ")");
    }

    if (hostv6)
    {
        // add IPv6 address to the filter if specified, make sure it will work also with IPv4 address and port
        if (hostv4)
        {
            
            strcat(tmp_filter, " and ip6 host ");
            strcat(tmp_filter, hostv6_ptr);
            strcat(data.filter, " or ");
            strcat(data.filter, tmp_filter);
            strcat(data.filter, ")");
        }
        else
        {

            strcat(data.filter, " and ip6 host ");
            strcat(data.filter, hostv6_ptr);
            strcat(data.filter, ")");
        }
    }
}

void print_packet(const u_char *data, bpf_u_int32 lenght)
{
    std::ios old_cout_settings(nullptr);
    // save the current cout settings, cout will be corrupted by the std::hex output
    old_cout_settings.copyfmt(std::cout);

    for (bpf_u_int32 i = 0; i < lenght; )
    {
        // convert bytes to hex with 4 places
        std::cout << "0x" << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        i += 0x10;
        for (bpf_u_int32 j = i - 0x10; j < i - 0x8; j++)
        {
            if (j >= lenght)
            {
                // padding of the last line
                std::cout << "   ";
            }
            else
            {
                // convert bytes to hex with 2 places
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) data[j] << " ";
            }
        }

        std::cout << " ";
        
        for (bpf_u_int32 j = i - 0x8; j < i; j++)
        {
            if (j >= lenght)
            {
                // padding of the last line
                std::cout << "   ";
            }
            else
            {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) data[j] << " ";
            }
        }

        std::cout << " ";

        for (bpf_u_int32 j = i - 0x10; j < i && j < lenght; j++)
        {
            // check printable characters, unprinteable replace with '.'
            char print{isprint((int) data[j]) ? (char) data[j] : '.'};
            std::cout << print;
        }

        std::cout << std::endl;
    }

    // restore the original cout settings
    std::cout.copyfmt(old_cout_settings);
    std::cout << std::endl;
}

void packet_parser(u_char *user, const struct pcap_pkthdr *header, const u_char *data)
{
    if (header == nullptr || data == nullptr || header->caplen != header->len || header->caplen < 14)
    {
        std::cerr << "Error: Invalid packet recieved." << std::endl;
        return;
    }

    char dst_mac_addr[32]{0, };
    char src_mac_addr[32]{0, };
    char time_str[64]{0, };
    bool print_mac{(bool) user[0]}, print_proto{(bool) user[1]};
    
    // create parsing structure for the network layer and set the offest of the layer 
    newtwork_layer_t newtwork_layer{.offset = ETH_OFFSET, 0, };

    parse_time(header, time_str);

    parse_ethernet_header(data, dst_mac_addr, src_mac_addr, newtwork_layer.header_type);

    if (print_mac)
    {
        // print MAC adresses if specifed by the command line arguments
        std::cout << "source MAC adress: " << src_mac_addr << " > destination MAC adress: " << dst_mac_addr << std::endl;
    }

    // stream for colletcing information about the parsed packet
    std::stringstream stream;
    stream << "ETHERNET, ";

    if (parse_network_layer(newtwork_layer, data, header->caplen, stream))
    {
        return; // error while parsing the network layer
    }

    parse_extension_headers(data, newtwork_layer.transport_header_type, newtwork_layer.offset, header->caplen, stream);

    // create parsing structure for the transport layer and copy the necessary information from the network layer structure
    transport_layer_t transport_layer{.header_type = newtwork_layer.transport_header_type, .offset = newtwork_layer.offset, 0, };

    if (parse_transport_layer(transport_layer, data, header->caplen, stream))
    {
        return; // error while parsing the transport layer
    }

    if (print_proto)
    {
        // print the packet layer types if specified by the command line arguments
        std::cout << stream.str() << std::endl;
    }
    else
    {
        // clear the collected information if not
        stream.clear();
    }

    if (transport_layer.print_ports)
    {
        // the packet is UDP or TCP and ports were retireved
        std::cout << time_str << " " << newtwork_layer.src_ip_addr << " : " << transport_layer.src_port << " > " 
                  << newtwork_layer.dst_ip_addr << " : " << transport_layer.dst_port << ", length " 
                  << header->caplen << std::endl << std::flush;
    }
    else
    {
        // ports could not be retireved
        std::cout << time_str << " " << newtwork_layer.src_ip_addr << " > " << newtwork_layer.dst_ip_addr 
                  << ", length " << header->caplen << std::endl << std::flush;
    }
    std::cout << std::endl;

    print_packet(data, header->caplen);
}

void create_pcap_connection(const char *interface, const char *filter)
{
    char err_msg[PCAP_ERRBUF_SIZE];

    Memory_management.connection = pcap_open_live(interface, MAX_PACKET_SIZE, 1, 250, err_msg);
    if (Memory_management.connection == nullptr)
    {
        std::cerr << "Error at pcap_open_live: " << err_msg << std::endl;
        exit(1); // failure
    }

    bpf_u_int32 netp, maskp;
    if (pcap_lookupnet(interface, &netp, &maskp, err_msg))
    {
        std::cerr << "Error at pcap_lookupnet: " << err_msg << std::endl;
        exit(1); // failure
    }

    struct bpf_program fp;
    if (pcap_compile(Memory_management.connection, &fp, filter, 0, maskp))
    {
        std::cerr << "Error at pcap_compile: " << pcap_geterr(Memory_management.connection) << std::endl;
        exit(1); // failure
    }

    // trying to suppress Warning message from pcap_setfilter, by redirecting stderr to /dev/null
    // the warning message is: "Warning: Kernel filter failed: Invalid argument"; which appears when
    // the filter cointains 'protochain' keyword, as the Kernel rejects parsing an unspecified number
    // of IPv6 extension header files.
    FILE *tmp = stderr;
    stderr = fopen("/dev/null", "r"); // redirect stderr
    if (stderr == nullptr)
    {
        stderr = tmp; // if redirection fails, use the stderr
    }

    if (pcap_setfilter(Memory_management.connection, &fp))
    {
        std::cerr << "Error at pcap_setfiler: " << pcap_geterr(Memory_management.connection) << std::endl;
        pcap_freecode(&fp);
        exit(1); // failure
    }
    pcap_freecode(&fp);

    if (stderr != tmp) // if redirection succeded, close /dev/null
    {
        fclose(stderr);
    }
    stderr = tmp; // repair stderr

    // check that the link layer is ethernet
    int data_link_layer_type = pcap_datalink(Memory_management.connection);
    if (data_link_layer_type == PCAP_ERROR_NOT_ACTIVATED)
    {
        std::cerr << "Error at pcap_datalink: " << pcap_geterr(Memory_management.connection) << std::endl;
        exit(1); // failure
    }
    else if (data_link_layer_type != DLT_EN10MB)
    {
        std::cerr << "Unsuported data link layer." << std::endl;
        exit(1); // failure
    }
}

void print_all_interfaces()
{
    char err_msg[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = nullptr;

    // retireve interfaces
    if (pcap_findalldevs(&devs, err_msg) == -1)
    {
        std::cerr << "Error at pcap_findalldevs: " << err_msg << std::endl;
        exit(1); // failure
    }

    // print interfaces recieved in a queue
    pcap_if_t *tmp = devs;
    while(tmp != nullptr)
    {
        std::cout << tmp->name << std::endl;
        tmp = tmp->next;
    }

    pcap_freealldevs(devs);
}

bool parse_network_layer(newtwork_layer_t &layer, const u_char *data, bpf_u_int32 max_len, std::stringstream &stream)
{
    if (layer.header_type == IPV4)
    {
        if (layer.offset + 20 >= max_len)
        {
            std::cerr << "Error: Malformed packet occured, incorrect length." << std::endl;
            return true; // failure
        }

        stream << "IPv4, ";
        struct ip *ipv4_header = (struct ip *) (data + layer.offset);

        // parse IPv4 adresses
        strcpy(layer.dst_ip_addr, inet_ntoa(ipv4_header->ip_dst));
        strcpy(layer.src_ip_addr, inet_ntoa(ipv4_header->ip_src));

        // retrieve the offset and the following header type, which may not be transport header
        layer.offset += ipv4_header->ip_hl << WORD_SIZE_SHIFT;
        layer.transport_header_type = ipv4_header->ip_p;
    }
    else if (layer.header_type == IPV6)
    {
        if (layer.offset + 40 >= max_len)
        {
            std::cerr << "Error: Malformed packet occured, incorrect length." << std::endl;
            return true; // failure
        }

        stream << "IPv6, ";
        struct ip6_hdr* ipv6_header = (struct ip6_hdr *) (data + layer.offset);

        // parse IPv6 adresses
        if (inet_ntop(AF_INET6, &ipv6_header->ip6_src, layer.src_ip_addr, INET6_ADDRSTRLEN) == nullptr ||
            inet_ntop(AF_INET6, &ipv6_header->ip6_dst, layer.dst_ip_addr, INET6_ADDRSTRLEN) == nullptr)
        {
            std::cerr << "Invalid IPv6 adress." << std::endl;
            return true; // failure
        }

        // add to the offset and retrieve the following header type, which may not be transport header
        layer.offset += IPV6_HEADER_OFFSET;
        layer.transport_header_type = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }
    else if (layer.header_type == ARP)
    {
        if (ETH_OFFSET + ARP_TIP_OFFSET + 3 >= max_len)
        {
            std::cerr << "Error: Malformed packet occured, incorrect length." << max_len << std::endl;
            return true; // failure
        }

        // parse IPv4 adresses
        sprintf(layer.src_ip_addr, "%d.%d.%d.%d", data[ETH_OFFSET + ARP_SIP_OFFSET], data[ETH_OFFSET + ARP_SIP_OFFSET + 1],
                                            data[ETH_OFFSET + ARP_SIP_OFFSET + 2], data[ETH_OFFSET + ARP_SIP_OFFSET + 3]);
        sprintf(layer.dst_ip_addr, "%d.%d.%d.%d", data[ETH_OFFSET + ARP_TIP_OFFSET], data[ETH_OFFSET + ARP_TIP_OFFSET + 1],
                                            data[ETH_OFFSET + ARP_TIP_OFFSET + 2], data[ETH_OFFSET + ARP_TIP_OFFSET + 3]);

        stream << "ARP";

        // no transport layer follows
        layer.transport_header_type = IPPROTO_NONE;
    }
    else
    {
        std::cerr << "Unknown network layer protocol" << std::endl;
        return true; // failure
    }

    return false; // success
}

bool parse_transport_layer(transport_layer_t &layer, const u_char *data, bpf_u_int32 max_len, std::stringstream &stream)
{
    // assume port will be retrieved
    layer.print_ports = true;

    // chose the transport layer type, add information about the parsed layer and try to parse the ports 
    switch (layer.header_type)
    {
        case IPPROTO_TCP:
            if (layer.offset + 4 >= max_len)
            {
                std::cerr << "Error: Malformed packet occured, incorrect length." << std::endl;
                return true; // failure
            }
            stream << "TCP";
            parse_tcp_udp(data + layer.offset, layer.src_port, layer.dst_port);
            break;
        
        case IPPROTO_UDP:
            if (layer.offset + 4 >= max_len)
            {
                std::cerr << "Error: Malformed packet occured, incorrect length." << std::endl;
                return true; // failure
            }
            stream << "UDP";
            parse_tcp_udp(data + layer.offset, layer.src_port, layer.dst_port);
            break;
        
        case IPPROTO_ICMP:
            stream << "ICMP";
            layer.print_ports = false;
            break;
        
        case IPPROTO_ICMPV6:
            stream << "ICMP";
            layer.print_ports = false;
            break;
        
        case IPPROTO_NONE:
        case IPPROTO_ESP:
            layer.print_ports = false;
            break;
        
        default:
            std::cerr << "Unknown transport layer protocol" << std::endl;
            return true; // failure
    }

    return false; // success
}
