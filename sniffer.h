
#ifndef __IPK_SNIFFER_H__
#define __IPK_SNIFFER_H__

//====================================================================================================================
// File:        sniffer.h
// Case:        VUT, FIT, IPK, project 2
// Date:        24. 4. 2021
// Author:      David Mihola
// Contact:     xmihol00@stud.fit.vutbr.cz
// Compiled:    gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
// Description: IP version 4, IP version 6 and ARP packet sniffer, supporting TCP, UDP and ICMP transport protocols.
//====================================================================================================================

#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>

#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/time.h>

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <csignal>

// MAC address offset in bytes
const unsigned short MAC_ADDR_OFFSET{6};

// size of a byte (8 bits)
const unsigned short BYTE_SIZE{8};

// Shifts bits by a word size (multiplication by 4) - 32 bits
const unsigned short WORD_SIZE_SHIFT{2};

// base offset on an IPv6 extension header
const unsigned short BASE_IPV6_EXT_HEADER_OFFSET{8};

// multiplies the size of extension header options by 8 using shifting
const unsigned short OPT_SIZE_SHIFT{3};

/**
 * @struct Conatains an information about parsed command line arguments.
 **/ 
typedef struct
{
    int number_of_packets;
    char *interface;
    char filter[1024];
    u_char flags[4];
} parsed_args_t;

/**
 * @struct Conatains some information about a network layer.
 **/
typedef struct
{
    unsigned short header_type;
    unsigned short offset;
    unsigned char transport_header_type;
    char src_ip_addr[64];
    char dst_ip_addr[64];
} newtwork_layer_t;

/**
 * @struct Conatains some information about a transport layer.
 **/
typedef struct
{
    unsigned char header_type;
    unsigned short offset;
    unsigned short src_port;
    unsigned short dst_port;
    bool print_ports;
} transport_layer_t;

// ======================================= non inline functions =======================================

/**
 * @brief Frees allocated resources by pcap_open_live().
 **/
void free_resources();

/**
 * @brief Handles the SIGINT signal (ctr + c)
 * @param sig The signal number
 **/
void sig_int_handler(int sig);

/**
 * @brief Retrieves a current pcap_open_live() connection.
 * @return The pcap connection.
 **/
pcap_t *get_connection();

/**
 * @brief Parses the command line arguments and stores the result in a arguments structure.
 * @param argc Number of command lines armunets.
 * @param argv Command line argumets.
 * @param data The structure, to which the parsed arguments are laoded.
 **/
void parse_arguments(int argc, char **argv, parsed_args_t &data);

/**
 * @brief Pritns a packet in a appropriate format.
 * @param data The bytes representation of the packet.
 * @param lenght The lenght of the packet.
 **/
void print_packet(const u_char *data, bpf_u_int32 lenght);

/**
 * @brief pcap_handler function, which parses a recieved packet.
 *        See https://linux.die.net/man/3/pcap_loop for further documentation.
 * @param user Array of size 2, where user[0] represents boolean flag if MAC adresses should be printed,
 *                                    user[1] represents boolean flag if packet OSI types should be printed.
 * @param header The header of recieved packet.
 * @param data The recieved packet data of a lenght specified in the header.
 **/
void packet_parser(u_char *user, const struct pcap_pkthdr *header, const u_char *data);

/**
 * @brief Opens a live pcap connection with a mask and a filter.
 * @param interface The name of an interface on which packtes will be scanned.
 * @param filter The packet filter applied to the live pcap connection.
 **/
void create_pcap_connection(const char *interface, const char *filter);

/**
 * @brief Parses the network layer of a packet from byte representation..
 * @param layer The structure which holds the current data offset and network layer header type, 
 *              the rest of the structure data is to be filled with the parsed data.
 * @param data The packet byte data.
 * @param max_len The maximum lenght of curretntly parsed packet.
 * @param stream The stream, to which information about parsed network layer is printed.
 **/
bool parse_network_layer(newtwork_layer_t &layer, const u_char *data, bpf_u_int32 max_len, std::stringstream &stream);

/**
 * @brief Parses the transport layer of a packet from byte representation.
 * @param layer The structure which holds the current data offset and transport layer header type,
 *              the rest of the structure data is to be filled with the parsed data.
 * @param data The packet byte data.
 * @param stream The stream, to which information about parsed transport layer is printed.
 **/
bool parse_transport_layer(transport_layer_t &layer, const u_char *data, bpf_u_int32 max_len, std::stringstream &stream);

/**
 * @brief Pritns all available interfaces, which can be tracked on the system.
 **/
void print_all_interfaces();

// ========================================= inline functions =========================================

/**
 * @brief Pritns the usage message including all option possibilites.
 * @param err_output Specifeis if the output of the function is on STDERR (true) or STDOUT (false).
 **/
inline void print_usage_message(bool err_output)
{
    // sets the output stream either to STDOUT or to STDERR
    std::ostream &stream = err_output ? std::cerr : std::cout;

    stream << "Usage: [options ...]" << std::endl;
    stream << std::endl;
    stream << "Options:" << std::endl;
    stream << "-h, --help \t\t\t\t Prints a usage message to STDOUT." << std::endl; 
    stream << "-i, --interface <optional string>\t Option can be either followed by a name of an interface on which packets are scanned," << std::endl; 
    stream << "\t\t\t\t\t or all available interfaces are printed, if the option parameter is not specified" << std::endl;
    stream << "\t\t\t\t\t or the option is missing entirely." << std::endl;
    stream << "-p <unsigned short>\t\t\t A port number on which the traffic is going to be scanned." << std::endl;
    stream << "-t, --tcp \t\t\t\t Only TCP and other specified packets are going to be scanned." << std::endl;
    stream << "-u, --udp \t\t\t\t Only UDP and other specified packets are going to be scanned." << std::endl;
    stream << "--arp \t\t\t\t\t Only ARP frame packets are going to be scanned." << std::endl;
    stream << "--icmp \t\t\t\t\t Only ICMP, ICMPv6 and other specified packets are going to be scanned." << std::endl;
    stream << "-n <int> \t\t\t\t The number of packets to be scanned, 1 if not specified." << std::endl;
    stream << "--mac \t\t\t\t\t Prints the source and destination MAC addresses of each packet." << std::endl;
    stream << "--type \t\t\t\t\t Prints the types of headers of layers of the OSI model including extension headers." << std::endl;
    stream << "--hostv4 \t\t\t\t Scans only packets with either destination or source IPv4 address specified in the argument." << std::endl;
    stream << "--hostv6 \t\t\t\t Scans only packets with either destination or source IPv6 address specified in the argument." << std::endl;
}

/**
 * @brief Parses the MAC adress from bytes to text representation (i.e. AA:BB:CC:DD:EE:FF).
 * @param data Byte array representing the MAC adress.
 * @param mac_addr The converted address will be copied to the variable. The allocated space must
 *                 be no smaller than 16 bytes.
 **/
inline void parse_mac_address(const u_char *data, char *mac_addr)
{
    sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", data[0], data[1], data[2], data[3], data[4], data[5]);
}

/**
 * @brief Parses the Ethernet header.
 * @param data The byte data of the header.
 * @param dst_mac_addr The destination MAC address will be loaded to the variable. The allocated space
 *                     must be no smaller than 16 bytes.
 * @param src_mac_addr The source MAC address will be loaded to the variable. The allocated space must
 *                     be no smaller than 16 bytes.
 * @param network_header_type The type of the followig network header will be loaded to the variable.
 **/
inline void parse_ethernet_header(const u_char *data, char *dst_mac_addr, char *src_mac_addr, unsigned short &network_header_type)
{
    // parse the type of the network layer header
    network_header_type = (short) ((data[12] << BYTE_SIZE) | data[13]);

    // parse the destination MAC address
    parse_mac_address(data, dst_mac_addr);

    // parse the source MAC address
    parse_mac_address(data + MAC_ADDR_OFFSET, src_mac_addr);
}

/**
 * @brief Parses the recieve time of a packet.
 * @param header The header of the recieved packet.
 * @param time_str The parsed time according to the RFC3339 standard will be copied to the variable.
 *                 The allocated space must be no smaller than 64 bytes.
 **/
inline void parse_time(const struct pcap_pkthdr *header, char *time_str)
{
    char tmp_time[32]{0, };
    char time_zone[32]{0, };

    // retrieve the time of packet arrival
    struct tm *time = localtime(&header->ts.tv_sec);
    strftime(tmp_time, 64, "%FT%T.", time);
    strftime(time_zone, 16, "%z", time);

    // correct the time zone to a format according the RFC3339 standard
    time_zone[5] = time_zone[4];
    time_zone[4] = time_zone[3];
    time_zone[3] = ':';

    // convert micro seconds to milliseconds
    unsigned short milli_s = header->ts.tv_usec / 1000;
    
    // put the obtaint strings to one string
    std::ostringstream stream;
    stream << tmp_time << std::setw(3) << std::setfill('0') << milli_s << time_zone;
    strcpy(time_str, stream.str().c_str());
}

/**
 * @brief Parses the extension headers of IPv4 and IPv6 packets from byte represenation.
 * @param data The packet byte data.
 * @param header_type The type of next header in the packet, which may not be an extesion header type.
 * @param offset The offset from the start of a packet specified by data parameter.
 * @param max_len The maximum lenght of curretntly parsed packet.
 * @param stream The stream, to which information about the parsed extension headers is printed.
 **/
inline void parse_extension_headers(const u_char *data, unsigned char &header_type, unsigned short &offset, 
                                    bpf_u_int32 max_len, std::stringstream &stream)
{
    bool transport_header{false};
    do
    {
        if (offset + 1 >= max_len && header_type == IPPROTO_HOPOPTS 
                                  && header_type == IPPROTO_DSTOPTS 
                                  && header_type == IPPROTO_ROUTING
                                  && header_type == IPPROTO_AH
                                  && header_type == IPPROTO_ESP)
        {
            std::cerr << "Error: Malformed packet occured, incorrect length." << std::endl;
            return;
        }

        switch (header_type)
        {
            case IPPROTO_HOPOPTS:
                stream << "Hop-By-Hop Options, ";
                header_type = data[offset];
                offset += (data[offset + 1] << OPT_SIZE_SHIFT) + BASE_IPV6_EXT_HEADER_OFFSET;
                break;
            
            case IPPROTO_DSTOPTS:
                stream << "Destination Options, ";
                header_type = data[offset];
                offset += (data[offset + 1] << OPT_SIZE_SHIFT) + BASE_IPV6_EXT_HEADER_OFFSET;
                break;
            
            case IPPROTO_ROUTING:
                stream << "Routing Header, ";
                header_type = data[offset];
                offset += (data[offset + 1] << OPT_SIZE_SHIFT) + BASE_IPV6_EXT_HEADER_OFFSET;
                break;

            case IPPROTO_FRAGMENT:
                stream << "Fragment Header, ";
                header_type = data[offset];
                offset += BASE_IPV6_EXT_HEADER_OFFSET;
                break;

            case IPPROTO_AH:
                stream << "Authentication Header, ";
                header_type = data[offset];
                offset += (data[offset + 1] << WORD_SIZE_SHIFT) + BASE_IPV6_EXT_HEADER_OFFSET;
                break;
            
            case IPPROTO_ESP:
                stream << "Encapsulation Security Payload Header";
                transport_header = true;
                return;

            case IPPROTO_NONE:
            default:
                transport_header = true;
                return;            
        }
    } 
    while (!transport_header); //until transport header is reached, or the tranport layer cannot be parsed.
}

/**
 * @brief Parses the tcp and udp headers and retrievs the source and destination ports.
 * @param data The byte representation of tcp or udp header.
 * @param src_port The source port number will be loaded to the variable.
 * @param dst_port The destination port number will be loaded to the variable.
 **/
inline void parse_tcp_udp(const u_char *data, unsigned short &src_port, unsigned short &dst_port)
{
    src_port = (unsigned short) ((data[0] << BYTE_SIZE) | data[1]);
    dst_port = (unsigned short) ((data[2] << BYTE_SIZE) | data[3]);
}

#endif // __IPK_SNIFFER_H__
