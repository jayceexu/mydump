#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"
#include "proto.h"

// Filtering rules for '-g', to fetch 'GET' or 'POST' content packets
static const char * http_filter = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 or "
        "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420";
static bool http_filter_set = false;

 // maximum numbers of packets
static int cnt = 1024*1024; 

static char * device = NULL;
static char * filename = NULL;
static char search_str[SEARCH_STRING_LEN];

extern char * optarg;
void pcap_callback(u_char * user,
                   const struct pcap_pkthdr *h, const u_char *bytes);

int main(int argc, char *argv[])
{
    bool filter_set = false;
    memset(search_str, 0, SEARCH_STRING_LEN);

    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[SEARCH_STRING_LEN];
    int op = 0;
    size_t len;
    while ((op = getopt(argc, argv, "i:r:s:g")) != -1) {
        switch (op) {
        case 'i':
            device = optarg;
            printf ("[DEBUG] read from device: %s\n", device);
            break;

        case 'r':
            filename = optarg;
            printf ("[DEBUG] read from pcap file: %s\n", filename);            
            break;

        case 's':
            len = strlen(optarg);
            if (len >= SEARCH_STRING_LEN) {
                printf ("The search string is too long, exceeds max 128\n");
                return -1;
            }
            memcpy(search_str, optarg, len);
            printf ("[DEBUG] The search string is \"%s\"\n", search_str);
            break;

        case 'g':
            // Hardcode the filter rules
            memcpy(filter_exp, http_filter, SEARCH_STRING_LEN);
            filter_set = true;
            http_filter_set = true;
            break;

        default:
            printf ("Parameter error!\n"
                    "mydump [-i interface] [-r file] [-s string] [-g] expression\n");
            return -1;            
        }

    }
    int expr_idx = optind;
    // '-g' has a higher priority than [expression]
    if (expr_idx < argc && !filter_set) {   
        len = strlen(argv[expr_idx]);
        if (len >= SEARCH_STRING_LEN) {
            printf ("The search string is too long, exceeds max 128\n");
            return -1;
        }
        memcpy(filter_exp, argv[expr_idx], SEARCH_STRING_LEN);
        printf ("[DEBUG] Filter expression: %s\n", filter_exp);
        filter_set = true;
    }

    pcap_t * pf;
    if (filename != NULL) {
        pf = pcap_open_offline(filename, errbuf);
        if (NULL == pf) {
            perror("Fail to pcap_open_offline: %m");
            return -1;
        }
        int dl = pcap_datalink(pf);
        const char * dl_name = pcap_datalink_val_to_name(dl);
        if (dl_name == NULL) {
            fprintf(stderr, "reading from file %s, link-type %u\n",
                    filename, dl);
        } else {
            fprintf(stderr,
                    "reading from file %s, link-type %s (%s)\n",
                    filename, dl_name,
                    pcap_datalink_val_to_description(dl));
        }
    } else {
        if (device == NULL) {
            device = pcap_lookupdev(errbuf);
            if (device == NULL)
                printf("error %s\n", errbuf);
        }
        printf ("[DEBUG] listening device: %s\n", device);
        pf = pcap_create(device, errbuf);
        if (NULL == pf) {
            perror("Fail to pcap_create: %m");
        }
        int r = pcap_set_promisc(pf, 1);
        if (r != 0)
            printf("%s: pcap_set_snaplen failed: %s",
                   device, pcap_statustostr(r));
     
        int ret = pcap_activate(pf);
        if (ret != 0) {
            pcap_perror(pf, "pcap_activate failed ");
        }
    }

    struct bpf_program fp;
    if (filter_set) {
        if (pcap_compile(pf, &fp, filter_exp, 0, 0) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n",
                    filter_exp, pcap_geterr(pf));
        }
        
        if (pcap_setfilter(pf, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter_exp, pcap_geterr(pf));
        }     
    }
    pcap_loop(pf, cnt, pcap_callback, NULL);
    pcap_freecode(&fp);
    pcap_close(pf);
    return 0;
}


void print_payload(char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;/* number of bytes per line */
    int line_len;
    int offset = 0;
    const u_char *ch = payload;

    if (len <= 0)
        return;

    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    while(true) {
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch, line_len, offset);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_width;

        if (len_rem <= line_width) {
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    printf ("\n");
    return;
}


void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{

        const struct ip_header *ip;
        const struct tcp_header *tcp;

        char proto[1024];
        char *payload;                    /* Packet payload */
        int size_ip;
        int size_user_header;   /* TCP/UDP/ICMP header size */

        int size_payload;
        ip = (struct ip_header*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

        switch(ip->ip_p) {
        case IPPROTO_TCP:
            tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
            size_user_header = TH_OFF(tcp)*4;
            if (size_user_header < 20) {
                printf("[DEBUG] Invalid TCP header length: %u bytes\n",
                       size_user_header);
                return;
            }
            //printf(" TCP");
            memcpy(proto, " TCP", 10);
            break;

        case IPPROTO_UDP:
            size_user_header = 8;
            //printf(" UDP");
            memcpy(proto, " UDP", 10);
            break;

        case IPPROTO_ICMP:
            size_user_header = 8;
            //printf(" ICMP");
            memcpy(proto, " ICMP", 10);
            break;
        default:
            printf("[DEBUG] Other protocol we do not support yet\n");
            return;
        }



        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_user_header);
        size_payload = ntohs(ip->ip_len) - (size_ip + size_user_header);

        //printf("[DEBUG]  Payload (%d bytes):\n", size_payload);
        //printf ("[DEBUG] Search_str %s \npayload: [%s]\n", search_str, payload);
        char * str = NULL;
        
        // If '-g' is set
        if (http_filter_set) {
            ts_print(&h->ts);          /* print the timestamp of the packet */
            printf ("%s", proto);
            printf(" %s:%d -> %s:%d",
                   inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                   inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf (" len %d\n", h->len);


            char substr[SEARCH_STRING_LEN];
            print_get_post_resource(payload, substr);
            printf ("%s\n\n", substr);

        } else if (NULL == search_str ||
            (NULL != search_str && (str = strstr(payload, search_str)) != NULL)) {

            ts_print(&h->ts);          /* print the timestamp of the packet */
            printf ("%s", proto);
            printf(" %s:%d -> %s:%d",
                   inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                   inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf (" len %d\n", h->len);

            print_payload(payload, size_payload);
        }
        fflush(stdout);
}

