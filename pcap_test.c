#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    //unsigned int ether_shost;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len;

    ep = (struct ether_header *)packet;

    packet += sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);

    iph = (struct ip *)packet;
    if (iph->ip_p == IPPROTO_TCP)
    {
       
	tcph = (struct tcp *)(packet + iph->ip_hl * 4);
        printf("TCP 패킷\n");
        printf("Src MAC    : %02X:%02X:%02X:%02X:%02X:%02X\n", ep->ether_shost[0],
			ep->ether_shost[1], ep->ether_shost[2], ep->ether_shost[3],
			ep->ether_shost[4], ep->ether_shost[5]);
        printf("Dst MAC    : %02X:%02X:%02X:%02X:%02X:%02X\n", ep->ether_dhost[0],
			ep->ether_dhost[1], ep->ether_dhost[2], ep->ether_dhost[3],
			ep->ether_dhost[4], ep->ether_dhost[5]);
        //printf("Protocol    : %d\n", iph->ip_p);        
        //printf("Type     : %04x\n", ether_type);
        //printf("Version     : %d\n", iph->ip_v);
        //printf("Header Len  : %d\n", iph->ip_hl);
        //printf("Ident       : %d\n", ntohs(iph->ip_id));
        //printf("TTL         : %d\n", iph->ip_ttl); 
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));
        printf("Src Port : %d\n" , ntohs(tcph->source));
        printf("Dst Port : %d\n" , ntohs(tcph->dest));
        
    }
    else
    {
        printf("\n\nNONE TCP 패킷\n\n");
    }
    printf("\nㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ\n");
}    

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;     

    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET : %s\n", net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MSK : %s\n", mask);
    printf("=======================\n");

    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }    

    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");    
        exit(1);
    }

    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);    
    }

    pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}
