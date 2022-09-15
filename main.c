#include "pcap.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hashTable.h"
#include "packet-structs.h"
#include <time.h>
#include "netinet/in.h"
#include "netinet/ip.h"
#include "string.h"
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/ethernet.h>
#include <json-c/json.h>
#include <sys/time.h>
#include <math.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#define ETHERNET_TYPE_IPv4 0x0800
#define ETHERNET_TYPE_IPv6 0x86DD
#define SNAP_LEN 1518
#define IP_VERSION 4
#define YOUTUBE_PORT 443
#define UDP_PROTOCOL 17
// typedef enum
// {
//     TRUE,
//     FALSE
// } boolean;

// macro to find size_ip
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
ht *hash_table;      // hash table to save all the 5 truple key and thems place in the connection arr;
int num_connections; // count the number of the connections - use for the array
int num = 0;
int connection_id;              // which number is the current connection
struct connection *connections; // array of connections
// file to save the output
FILE *fpt;
FILE *video;
// json objects
struct config_data *config;
int timeount;
int video_connection = 0;
int transaction_id = 0;
double duration_of_the_video = 0;
unsigned long size_of_the_videos = 0;
int number_of_TDRs_per_video = 0;
double time_between_two_consecutive_TDRs = 0;
double duration_of_the_TDRs_per_video = 0;
double packet_time;
struct Node *list;
struct Node *head;
struct Node *tail;
struct Node *lastUsed;
char *connection_key;
char *key;
int tailChanged = FALSE; // flag to check if we have "empty" node is the list
int count = 0;
void init_connection(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, char *connection_key, int index_in_array);
void update_connection(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, char *connection_key, int index_in_array);
void close_connection(int index_in_array);
void close_transaction(double packet_time, int index_in_array)
{
    // duration_of_the_TDRs satatistic
    connections[index_in_array].duration_of_the_TDRs += connections[index_in_array].transaction.last_time_packet_recived - connections[index_in_array].transaction.start_time;

    // if the transaction is only a req from the client to the server we need to nullify sum statistic
    if (connections[index_in_array].transaction.total_transaction_bandwidth == 0)
    {
        connections[index_in_array].transaction.min_diff_time_inbound = 0;
        connections[index_in_array].transaction.min_packet_size_inbound = 0;
    }
    // add the last total_transaction_bandwidth to the total_bandwidth
    connections[index_in_array].total_bandwidth += connections[index_in_array].transaction.total_transaction_bandwidth;

    // write into the connection buffer the last transactin data
    char buffer[200];
    sprintf(&buffer, "%d, %s, %s, %8d, %8d, %8u, %10d,    %lf, %4d, %4d, %10u, %10d,    %8lf, %8lf, %8lf, %lf\n\0", connections[index_in_array].connection_id, connections[index_in_array].server_ip, connections[index_in_array].client_ip, connections[index_in_array].server_port, connections[index_in_array].client_port, connections[index_in_array].ip_protocol, connections[index_in_array].transaction.transaction_id, connections[index_in_array].transaction.start_time, connections[index_in_array].transaction.num_inbound_packets_in_range, connections[index_in_array].transaction.num_outbound_packets_in_range, connections[index_in_array].transaction.max_packet_size_inbound, connections[index_in_array].transaction.min_packet_size_inbound, connections[index_in_array].transaction.max_diff_time_inbound, connections[index_in_array].transaction.min_diff_time_inbound, connections[index_in_array].transaction.square_inbound_packet_time_diff, connections[index_in_array].transaction.RTT);
    strcat(connections[index_in_array].buffer, buffer);
}
void open_transaction(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, char *connection_key, const int index_in_array)
{

    // chack if the sum transaction of the current connection is  less then the Max_number_of_transaction_per_video
    if (connections[index_in_array].num_transactions == config->Max_number_of_transaction_per_video)
    {
        //  then we need to close the connection and update its;
        close_connection(index_in_array);
        update_connection(packet_time, ip, udp, connection_key, index_in_array);
        return;
    }
    // first we need to close the last transaction, only if this transaction isnt the first transaction
    if (connections[index_in_array].num_transactions != 0)
    {
        close_transaction(packet_time, index_in_array);
    }
    else
    {
        connections[index_in_array].req_time = packet_time;
    }
    if (connections[index_in_array].transaction.num_packets == 0)
    {
        connections[index_in_array].transaction.first_time_packet_recived = packet_time;
    }
    connections[index_in_array].time_between_two_consecutive_TDRs += packet_time - connections[index_in_array].req_time;

    // init the current transaction data
    connections[index_in_array].transaction.total_transaction_bandwidth = 0;
    connections[index_in_array].num_transactions++;
    connections[index_in_array].transaction.transaction_id = transaction_id;
    connections[index_in_array].transaction.start_time = packet_time;
    connections[index_in_array].transaction.max_packet_size_inbound = 0;
    connections[index_in_array].transaction.min_packet_size_inbound = INT_MAX;
    connections[index_in_array].transaction.num_inbound_packets_in_range = 0;
    connections[index_in_array].transaction.num_outbound_packets_in_range = 0;
    connections[index_in_array].transaction.max_diff_time_inbound = 0;
    connections[index_in_array].transaction.min_diff_time_inbound = INT_MAX;
    connections[index_in_array].transaction.num_packets = 0;
    connections[index_in_array].req_time = packet_time;
    connections[index_in_array].transaction.inbound_packet_time_diff = 0;
    connections[index_in_array].transaction.square_inbound_packet_time_diff = 0;
    connections[index_in_array].duration_of_the_TDRs = 0;
    connections[index_in_array].transaction.last_time_packet_recived = packet_time;
    transaction_id++;
}
void server_to_client(double packet_time, const struct sniff_udp *udp, int index_in_array)
{
    connections[index_in_array].transaction.last_time_packet_recived = packet_time;
    // if it not in the range its not valid
    if (ntohs(udp->udp_len) < config->inbound_packets_in_range_min)
    {
        return;
    }
    if (connections[index_in_array].transaction.num_packets == 0)
    {
        connections[index_in_array].transaction.first_time_packet_recived = packet_time;
    }
    // total_transaction_bandwidth
    connections[index_in_array].transaction.total_transaction_bandwidth += ntohs(udp->udp_len);
    // RTT statistics
    if (connections[index_in_array].transaction.num_packets == 0)
    {
        connections[index_in_array].transaction.RTT = packet_time - connections[index_in_array].req_time;
    }
    ++connections[index_in_array].transaction.num_packets;
    // inbound_packet_time_diff statistic
    double diff = packet_time - connections[index_in_array].last_time_packet_recived;
    if (diff < 0)
        diff = 0;
    // SumSquareInboundPacketTimeDiff statistic
    connections[index_in_array].transaction.square_inbound_packet_time_diff += diff * diff;
    // num_inbound_packets_in_range statistics
    if (ntohs(udp->udp_len) < config->inbound_packets_in_range_max)
    {
        ++connections[index_in_array].transaction.num_inbound_packets_in_range;
    }
    // max_diff_time_inbound statistics
    if (diff > connections[index_in_array].transaction.max_diff_time_inbound)
    {
        connections[index_in_array].transaction.max_diff_time_inbound = diff;
    }
    // min_diff_time_inbound statistics
    if (diff < connections[index_in_array].transaction.min_diff_time_inbound)
    {

        connections[index_in_array].transaction.min_diff_time_inbound = diff;
    }

    // max len statistics
    if (ntohs(udp->udp_len) > connections[index_in_array].transaction.max_packet_size_inbound)
    {

        connections[index_in_array].transaction.max_packet_size_inbound = ntohs(udp->udp_len);
    }
    // min len statistics
    if (ntohs(udp->udp_len) < connections[index_in_array].transaction.min_packet_size_inbound)
    {
        connections[index_in_array].transaction.min_packet_size_inbound = ntohs(udp->udp_len);
    }
    // save the last time packet recived in this transaction
    connections[index_in_array].last_time_packet_recived = packet_time;
}

void client_to_server(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, char *connection_key, int index_in_array)
{

    // save the last time packet recived
    connections[index_in_array].last_time_packet_recived = packet_time;

    // if the packet size is between outbound_packets_in_range_max and outbound_packets_in_range_min we need it for statistic but its not valid
    if (ntohs(udp->udp_len) < config->outbound_packets_in_range_max && ntohs(udp->udp_len) > config->outbound_packets_in_range_min)
    {
        ++connections[index_in_array].transaction.num_outbound_packets_in_range;
        connections[index_in_array].transaction.last_time_packet_recived = packet_time;

        return;
    }

    open_transaction(packet_time, ip, udp, connection_key, index_in_array);
}

void close_connection(int index_in_array)
{
    // set the connection state to false
    connections[index_in_array].state = FALSE;
    // first close connection
    close_transaction(packet_time, index_in_array);
    // check if the connection is video connection
    if ((connections[index_in_array].video_connection == 1 || connections[index_in_array].total_bandwidth > (unsigned long)config->Minimum_video_connection_size))
    {
        duration_of_the_video += connections[index_in_array].last_time_packet_recived - connections[index_in_array].first_time_packet_recived;
        size_of_the_videos += connections[index_in_array].total_bandwidth;
        number_of_TDRs_per_video += connections[index_in_array].num_transactions;
        duration_of_the_TDRs_per_video += connections[index_in_array].duration_of_the_TDRs;
        time_between_two_consecutive_TDRs += connections[index_in_array].time_between_two_consecutive_TDRs / connections[index_in_array].num_transactions;
        fprintf(fpt, &connections[index_in_array].buffer);
        video_connection++;
    }

    strcpy(connections[index_in_array].buffer, "");
    connections[index_in_array].total_bandwidth = 0;
    connections[index_in_array].transaction.total_transaction_bandwidth = 0;
}
void update_connection(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, char *connection_key, int index_in_array)
{
    connection_id++;
    connections[index_in_array].num_connections++;
    // update the key of the connection
    connections[index_in_array].connection_id = connection_id;
    // update the last_time_packet_recived to this packet time
    connections[index_in_array].last_time_packet_recived = packet_time;
    // reset the total bandwith
    connections[index_in_array].total_bandwidth = 0;
    connections[index_in_array].transaction.total_transaction_bandwidth = 0;
    // rest the data of  the transaction of this connection
    connections[index_in_array].num_transactions = 0;

    connections[index_in_array].state = TRUE;

    if (connections[index_in_array].num_transactions == 0)
    {
        connections[index_in_array].first_time_packet_recived = packet_time;
    }
    // printf("%u   %u\n", connections[num_connections].client_ip, connections[index_in_array].server_ip);
    open_transaction(packet_time, ip, udp, connection_key, index_in_array);
}
void init_connection(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, char *connection_key, int index_in_array)
{

    ht_set(hash_table, connection_key, (index_in_array));

    connections[index_in_array].num_connections = 0;
    // init the 5 tuple for this connection
    strcpy(connections[index_in_array].client_ip, inet_ntoa(ip->ip_src));
    strcpy(connections[index_in_array].server_ip, inet_ntoa(ip->ip_dst));
    connections[index_in_array].client_port = ntohs(udp->udp_srcport);
    connections[index_in_array].server_port = ntohs(udp->udp_destport);
    connections[index_in_array].ip_protocol = ip->ip_p;
    update_connection(packet_time, ip, udp, connection_key, index_in_array);
}
void after_last(int index_in_array)
{

    struct Node *current_node = connections[index_in_array].node;

    if (current_node->prev == NULL)
    {
        head = head->next;
    }
    else
    {
        current_node->prev->next = current_node->next;
    }
    if (current_node->next != NULL)
        current_node->next->prev = current_node->prev;
    if (lastUsed->next != NULL)
    {
        current_node->next = lastUsed->next;
        current_node->next->prev = current_node;
    }
    lastUsed->next = current_node;
    current_node->prev = lastUsed;
    lastUsed = lastUsed->next;

    if (tailChanged == FALSE)
    {

        tail = lastUsed;
    }
}
void after_tail(int index_in_array)
{
    tailChanged = TRUE;

    struct Node *current_node = connections[index_in_array].node;
    if (current_node->prev == NULL)
    {
        head = head->next;
    }
    else
    {
        current_node->prev->next = current_node->next;
    }
    if (current_node->next != NULL)
        current_node->next->prev = current_node->prev;
    if (tail == NULL)
    {
        tail = current_node;
    }
    else
    {
        tail->next = current_node;
        current_node->prev = tail;
        tail = tail->next;
        current_node->next = NULL;
    }
}
void have_connection(double packet_time, const struct sniff_ip *ip, const struct sniff_udp *udp, int index_in_array, char *connection_key, int client_server)
{

    // if timeout we need to close the current coonection and open a new one, in case that the packet is from the client and biger then 700
    if (packet_time - connections[index_in_array].last_time_packet_recived > (double)config->video_connection_timeout)
    {
        // if the connection is open - close it
        if (connections[index_in_array].state == TRUE)
        {
            close_connection(index_in_array);
        }

        // if the packet wont cause to open transaction, "throw" it
        if (client_server == FALSE || ntohs(udp->udp_len) < config->Request_packet_threshold)
        {
            after_tail(index_in_array);

            return;
        }
        timeount++;
        update_connection(packet_time, ip, udp, connection_key, index_in_array);
        after_last(index_in_array);

        return;
    }
    if (connections[index_in_array].node->next != NULL)
    {
        after_last(index_in_array);
    }

    if (client_server == TRUE)
    {

        client_to_server(packet_time, ip, udp, connection_key, index_in_array);
    }
    else
    {

        server_to_client(packet_time, udp, index_in_array);
    }
}
// check if there is some connection with the 5 tuple
void check_connection(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{

    const struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET); // ip layer
    int size_ip = IP_HL(ip) * 4;
    const struct sniff_udp *udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip); // udp layer
    uint32_t clinet_ip;
    uint32_t server_ip;
    int ip_ptotocol = (int)ip->ip_p;

    int client_to_server; // if the packet is from the client to the server =1
    unsigned short udp_clinet_port;
    unsigned short udp_server_port;
    unsigned short eth_type;
    struct sniff_ethernet *ethernet = (struct sniff_ethernet *)(packet);
    eth_type = ntohs(ethernet->ether_type);

    if (((ntohs(udp->udp_srcport) != config->YouTube_port && ntohs(udp->udp_destport) != config->YouTube_port) || (int)ip->ip_p != config->YouTube_protocol || eth_type != ETHERNET_TYPE_IPv4))
    {
        // if the packet isnt valid
        return;
    }
    // check  which "direction" it  is client and which it is server
    if (ntohs(udp->udp_destport) == config->YouTube_port)
    {

        udp_clinet_port = ntohs(udp->udp_srcport);
        udp_server_port = ntohs(udp->udp_destport);
        clinet_ip = ip->ip_src.s_addr;
        server_ip = ip->ip_dst.s_addr;
        client_to_server = TRUE;
    }
    else
    {

        server_ip = ip->ip_src.s_addr;
        clinet_ip = ip->ip_dst.s_addr;
        udp_clinet_port = ntohs(udp->udp_destport);
        udp_server_port = ntohs(udp->udp_srcport);
        client_to_server = FALSE;
    }

    snprintf(connection_key, connection_key, "%u%u%d%d%d", server_ip, clinet_ip, (int)udp_clinet_port, (int)udp_server_port, (int)ip->ip_p);

    // check if there is a connection;
    int index_in_array = 0;
    status isExist = ht_get(hash_table, connection_key, &index_in_array);

    // status isExist = ht_get(hash_table, (char *)&connection_key, &index_in_array);
    // save the time packet
    packet_time = header->ts.tv_sec + header->ts.tv_usec / 1000000.00000000;

    if (isExist == EXIST)
    {
        // if there is a connection, send to a function to add this packet to a transaction;
        have_connection(packet_time, ip, udp, index_in_array, connection_key, client_to_server);
        // have_connection(packet_time, ip, udp, index_in_array, (char *)&connection_key, client_to_server);
    }
    else
    {

        // a new connection wont create with server to client packet, therefore we will check only the len of the udp
        if (client_to_server == FALSE || ntohs(udp->udp_len) < config->Request_packet_threshold)
        { // if  the len is less then 700 or this is not a req we wont open a new connection
            return;
        }
        num++;

        if (num_connections >= config->Max_number_of_connections - 1 && tail->next == NULL)
        {
            if (packet_time - connections[head->data].last_time_packet_recived > (double)config->video_connection_timeout)
            {

                ++num_connections;
                index_in_array = head->data;
                if (connections[index_in_array].total_bandwidth >= (unsigned long)config->Minimum_video_connection_size)
                {
                    printf("%u\n", connections[index_in_array].total_bandwidth);
                    sleep(1);
                    count++;
                }
                close_connection(index_in_array);

                snprintf(key, key, "%u%u%d%d%d", connections[index_in_array].server_ip, connections[index_in_array].client_ip, connections[index_in_array].client_port, connections[index_in_array].server_port, connections[index_in_array].ip_protocol);
                ht_delete(hash_table, key);

                struct Node *current_node = head;
                if (current_node->next == NULL)
                {
                    return;
                }
                head = head->next;
                head->prev = NULL;
                if (lastUsed->next != NULL)
                {
                    current_node->next = lastUsed->next;
                    current_node->next->prev = current_node;
                }
                lastUsed->next = current_node;
                current_node->prev = lastUsed;
                lastUsed = lastUsed->next;
                if (tailChanged == FALSE)
                {

                    tail = lastUsed;
                }
            }
            else
            {
                printf("ERROR!\n The max number of connections is  %d", config->Max_number_of_connections);
                return;
            }
        }
        else
        {
            ++num_connections;

            if (num_connections >= config->Max_number_of_connections)
            {
                index_in_array = lastUsed->next->data;
                lastUsed = lastUsed->next;
            }
            else
            {

                index_in_array = num_connections;
                list[num_connections].data = num_connections;

                if (num_connections == 1)
                {
                    list[num_connections].next = NULL;
                    list[num_connections].prev = NULL;
                    lastUsed = head;
                    tail = lastUsed;
                }
                else
                {
                    list[num_connections].next = NULL;
                    list[num_connections].prev = lastUsed;
                    lastUsed->next = &list[num_connections];
                    lastUsed = lastUsed->next;
                }
                connections[index_in_array].node = &list[num_connections];
            }
        }
        if (tailChanged == FALSE)
        {
            tail = lastUsed;
        }

        // if there is not connection and the packet is from the client ,we need to open a new connection;
        init_connection(packet_time, ip, udp, connection_key, index_in_array);
    }
}

void init_config_object()
{
    config = (struct config_data *)malloc(sizeof(struct config_data));
    json_object *root = json_object_from_file("config.json");
    config->Request_packet_threshold = (json_object_get_int(json_object_object_get(root, "Request_packet_threshold")));
    config->Minimum_video_connection_size = json_object_get_int(json_object_object_get(root, "Minimum_video_connection_size"));
    config->inbound_packets_in_range_min = json_object_get_int(json_object_object_get(root, "inbound_packets_in_range_min"));
    config->inbound_packets_in_range_max = json_object_get_int(json_object_object_get(root, "inbound_packets_in_range_max"));
    config->outbound_packets_in_range_min = json_object_get_int(json_object_object_get(root, "outbound_packets_in_range_min"));
    config->outbound_packets_in_range_max = json_object_get_int(json_object_object_get(root, "outbound_packets_in_range_max"));
    config->max_diff_time_inbound_threshold = json_object_get_int(json_object_object_get(root, "max_diff_time_inbound_threshold"));
    config->Number_of_videos_to_output_statistics_per_video = json_object_get_int(json_object_object_get(root, "Number_of_videos_to_output_statistics_per_video"));
    config->Max_number_of_connections = json_object_get_int(json_object_object_get(root, "Max_number_of_connections"));
    config->Max_number_of_transaction_per_video = json_object_get_int(json_object_object_get(root, "Max_number_of_transaction_per_video"));
    config->video_connection_timeout = json_object_get_int(json_object_object_get(root, "video_connection_timeout"));
    config->YouTube_port = json_object_get_int(json_object_object_get(root, "YouTube_port"));
    config->YouTube_protocol = json_object_get_int(json_object_object_get(root, "YouTube_protocol"));
}

int main()
{
    // pcap_if_t *alldevs;            /* devices list*/
    char *dev = NULL;              /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    // bpf_u_int32 mask = 0;          /* subnet mask */
    bpf_u_int32 net = 0;
    pcap_t *handle; /* packet capture handle */
    struct bpf_program fp;
    num_connections = 0;

    handle = pcap_open_offline("youtube.pcap", errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    // creat the hash table
    hash_table = ht_create();
    if (hash_table == NULL)
    {
        printf("ERRORE!\n unable to create hash_table\n");
    }
    // open csv file
    fpt = fopen("output.csv", "w+");
    video = fopen("video.csv", "w+");
    if (fpt == NULL)
    {
        printf("ERRORE!\n unable to open the csv file\n");
    }
    fprintf(fpt, "Con_id,Server_ip,   Client_ip,  Server_port,Client_port,Ip_protocol,Trans_id, Start_time,Num_in,Num_out,Max_in_size,Min_in_size, Max_diff, Min_diff, sum_square, RTT\n");

    init_config_object();
    // malloc the connections array
    key = (char *)malloc(sizeof(char) * 30);

    connection_key = (char *)malloc(sizeof(char) * 30);
    connections = (struct connection *)malloc(sizeof(struct connection) * config->Max_number_of_connections);
    list = (struct Node *)malloc(sizeof(struct Node) * config->Max_number_of_connections);
    list[0].data = 1;
    head = &list[0];
    tail = head;
    connection_id = 0;
    pcap_loop(handle, 0, check_connection, NULL);
    pcap_close(handle);
    for (int i = 1; i < config->Max_number_of_connections; i++)
    {
        if (connections[i].state == TRUE)

            close_connection(i);
    }
    fprintf(video, "num video connection %d\n", video_connection);
    fprintf(video, "Average duration of the videos %lf\n", duration_of_the_video / video_connection);
    fprintf(video, "Average size of the videos %lf\n", (double)size_of_the_videos / video_connection);
    fprintf(video, "Average number of TDRs per video %d\n", number_of_TDRs_per_video / video_connection);
    fprintf(video, "Average size of the TDRs per video %lf\n", (double)size_of_the_videos / number_of_TDRs_per_video);
    fprintf(video, "Average duration of the TDRs per video %lf\n", duration_of_the_TDRs_per_video / number_of_TDRs_per_video);
    fprintf(video, "Average time between two consecutive TDRs %lf\n", (double)time_between_two_consecutive_TDRs / number_of_TDRs_per_video);
    ht_destroy(hash_table);
    fclose(fpt);
    free(connections);
}