
#include "pcap.h"
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#define SNAP_LEN 1518
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
#define IPHDRLEN 16

// for ip hash functiom
#define HASH_MASK ((1 << 20) - 1)
struct sniff_ip
{
    unsigned char ip_vhl;          /* version << 4 | header length >> 2 */
    unsigned char ip_tos;          /* type of service */
    unsigned short ip_len;         /* total length */
    unsigned short ip_id;          /* identification */
    unsigned short ip_off;         /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    unsigned char ip_ttl;          /* time to live */
    unsigned char ip_p;            /* protocol */
    unsigned short ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
struct sniff_ethernet
{
    unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    unsigned short ether_type;                 /* IP? ARP? RARP? etc */
};
struct sniff_udp
{
    unsigned short udp_srcport;
    unsigned short udp_destport;
    unsigned short udp_len;
    unsigned short udp_sum;
};
struct transaction
{
    int transaction_id;
    double start_time;
    double first_time_packet_recived;
    double last_time_packet_recived;
    int num_packets;
    unsigned long total_transaction_bandwidth;
    int min_packet_size_inbound;
    int max_packet_size_inbound;
    int num_outbound_packets_in_range;
    int num_inbound_packets_in_range;
    double max_diff_time_inbound;
    double min_diff_time_inbound;
    double RTT;
    double inbound_packet_time_diff;
    double square_inbound_packet_time_diff;
};
struct Node
{
    int data;
    struct Node *next;
    struct Node *prev;
};
struct connection
{
    int connection_id;
    int num_connections;
    int num_transactions;
    struct transaction transaction;
    double close_transaction_time;
    double last_time_packet_recived;
    double first_time_packet_recived;
    double req_time;
    unsigned long total_bandwidth;
    char buffer[1100000];
    char server_ip[16];
    char client_ip[16];
    int server_port;
    int client_port;
    unsigned char ip_protocol;
    int video_connection;
    int state;
    double duration_of_the_TDRs;
    double time_between_two_consecutive_TDRs;
    struct Node *node;
};

struct config_data
{
    int Request_packet_threshold;
    int Minimum_video_connection_size;
    int inbound_packets_in_range_min;
    int inbound_packets_in_range_max;
    int outbound_packets_in_range_min;
    int outbound_packets_in_range_max;
    int max_diff_time_inbound_threshold;
    int Number_of_videos_to_output_statistics_per_video;
    int Max_number_of_connections;
    int Max_number_of_transaction_per_video;
    int video_connection_timeout;
    int YouTube_port;
    int YouTube_protocol;
};
