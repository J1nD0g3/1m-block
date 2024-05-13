#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "parse_header.h"
#include <string.h>

char *site_list_filename;
char **site_list;
int site_count = 0;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

//for quick-sort
int compare(const void *a, const void *b){
    return strcmp(*(const char **)a, *(const char**)b);
}

int binary_search(char *arr[], int size, const char *target){
    int left = 0;
    int right = size - 1;
    int mid;

    while(left <= right){
        mid = left + (right - left) / 2;
        int cmp = strcmp(arr[mid], target);

        if(cmp == 0) return 1;
        else if(cmp < 0) left = mid + 1;
        else right = mid - 1;
    }
    return 0;
}

int search_site(const char *host){
    return binary_search(site_list, site_count, host);
}

int site_filter(struct nfq_data *tb){
    int len;
    unsigned char *buf;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);

    len = nfq_get_payload(tb, &buf);

    if(ntohs(ph->hw_protocol) == 0x800){//if IPv4
        struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr*)buf;

        if(ipv4_hdr->ip_p == 6){//if TCP
            struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(buf + (ipv4_hdr->ip_hl * 4));

            int payload_len;
            payload_len = ntohs(ipv4_hdr->ip_len) - (ipv4_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);

            unsigned char *payload = malloc(sizeof(payload_len));
            memcpy(payload, buf + (ipv4_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4), payload_len);

            char *host = strstr(payload, "Host: ");
            free(payload);

            if(host != NULL){
                host += 6;
                char *newline = strchr(host, '\r');

                if(newline != NULL){
                    *newline = '\0';
                }

                int filtered = search_site(host);

                if(filtered){
                    printf("[filtered] : %s\n", host);
                    return 0;
                }
                else{
                    return 1;
                }
            }
        }
    }
    return 1;
}
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
        dump(data, ret);
    }
    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    int forward = site_filter(nfa);

    int result = forward == 1 ? nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL) : nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    return result;
}

void parse_sort_sites(){
    FILE *file = fopen(site_list_filename, "r");
    if(file == NULL){
        fprintf(stderr, "Failed to open file : %s\n", site_list_filename);
        exit(1);
    }

    int max_sites = 1000000;
    site_list = malloc(max_sites * sizeof(char *));

    char line[1024];
    char *domain;

    while(fgets(line, sizeof(line), file) != NULL){
        domain = strchr(line, ',');
        if(domain != NULL){
            domain++;
            domain[strcspn(domain, "\n")] = '/0';

            site_list[site_count] = strdup(domain);
            site_count++;
        }
    }
    fclose(file);

    qsort(site_list, site_count, sizeof(char*), compare);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if(argc == 2){
        site_list_filename = argv[1];
    }
    else{
        printf("Usage : 1m-block <site list file>\n");
        return -1;
    }

    parse_sort_sites();

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    printf("Waiting for packets...\n");

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    free(site_list);
    exit(0);
}

