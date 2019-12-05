#include <stdio.h>
#include <string.h>
#include <net/if.h> //struct ifreq (interface request)  linux/if.h  PF_PACKET
#include <net/ethernet.h> //ETH_P_ALL
#include <sys/ioctl.h> //SIOCGIFFLAG SIOCSIFFLAG SIOCGIFINDEX 
#include <netinet/ip.h> //struct iphdr (struct ip)
#include <netinet/if_ether.h> //struct ether_arp
#include <netinet/tcp.h> //struct tcp
#include <netinet/udp.h> //struct udp
#include <netpacket/packet.h> //struct sockaddr_ll

#include <unistd.h>
#include <inttypes.h>

/* DHCP packet */
#define EXTEND_FOR_BUGGY_SERVERS 80
#define DHCP_OPTIONS_BUFSIZE    308

/* See RFC 2131 */
struct dhcp_pkt {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr_nip;
    uint32_t gateway_nip;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie;
    uint8_t options[DHCP_OPTIONS_BUFSIZE + EXTEND_FOR_BUGGY_SERVERS];
} __attribute__((packed));

char *ip_ntoa(u_int32_t ip){
	u_char *d = (u_char *)&ip;
	static char str[15];
	sprintf(str,"%d.%d.%d.%d",d[0],d[1],d[2],d[3]);
	return str;
}

char *ip_ntoa2(u_char *d){
	static char str[15];
	sprintf(str,"%d.%d.%d.%d",d[0],d[1],d[2],d[3]);
	return str;
}

char *mac_ntoa(u_char *d){
	static char str[18];
	sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",d[0],d[1],d[2],d[3],d[4],d[5]);
	return str;
}

void printEtherHeader(u_char *buf){
	struct ether_header *eth;
	eth = (struct ether_header *)buf;
	printf("----------- ETHERNET -----------\n");
	printf("Dst MAC addr   : %17s \n",mac_ntoa(eth->ether_dhost));
	printf("Src MAC addr   : %17s \n",mac_ntoa(eth->ether_shost));
	int type = ntohs(eth->ether_type);
	printf("Ethernet Type  : 0x%04x\n",ntohs(eth->ether_type));
}

void printIPHeader(u_char *buf){
	struct iphdr *ip;
	ip= (struct iphdr *)buf;
	printf("----------- IP -----------\n");
	printf("version=%u\n",ip->version);
	printf("ihl=%u\n",ip->ihl);
	printf("tos=%x\n",ip->tos);
	printf("tot_len=%u\n",ntohs(ip->tot_len));
	printf("id=%u\n",ntohs(ip->id));
	printf("ttl=%u\n",ip->ttl);
	printf("protocol=%u\n",ip->protocol);
	printf("src addr=%s\n",ip_ntoa(ip->saddr));
	printf("dst addr=%s\n",ip_ntoa(ip->daddr));

}

void printArp(u_char *buf){
	struct ether_arp *arp;
	arp =(struct ether_arp *)buf;
	printf("----------- ARP ----------\n");
	printf("arp_hrd=%u\n",ntohs(arp->arp_hrd));
	printf("arp_pro=%u\n",ntohs(arp->arp_pro));
	printf("arp_hln=%u\n",arp->arp_hln);
	printf("arp_pln=%u\n",arp->arp_pln);
	printf("arp_op=%u\n",ntohs(arp->arp_op));
	printf("arp_sha=%s\n",mac_ntoa(arp->arp_sha));
	printf("arp_spa=%s\n",ip_ntoa2(arp->arp_spa));
	printf("arp_tha=%s\n",mac_ntoa(arp->arp_tha));
	printf("arp_tpa=%s\n",ip_ntoa2(arp->arp_tpa));
	//	printf("arp_tpa=%s\n",ip_ntoa(*((u_int32_t *)arp->arp_tpa)));
}

void printTcpHeader(u_char *buf){
	struct tcphdr *ptr;
	ptr = (struct tcphdr *)buf;
	printf("----------- TCP ----------\n");
	printf("src port = %u\n",ntohs(ptr->source));
	printf("dst port = %u\n",ntohs(ptr->dest));
}

void printUdpHeader(u_char *buf){
    struct udphdr *ptr;
    ptr = (struct udphdr *)buf;
    printf("----------- UDP ----------\n");
	printf("src port = %u\n",ntohs(ptr->source));
	printf("dst port = %u\n",ntohs(ptr->dest));
}

void printDhcp(u_char *buf){
    struct dhcp_pkt *dhcp;
    dhcp = (struct dhcp_pkt *)buf;
    printf("----------- DHCP ----------\n");
    printf("opcode: %u\n",dhcp->op);
    printf("hw_type: %u\n",dhcp->htype);
    printf("hw_len: %u\n",dhcp->hlen);
    printf("gw_hops: %u\n",dhcp->hops);
    printf("tx_id: %s\n", ip_ntoa(dhcp->xid));
    printf("bp_secs; %u\n",ntohs(dhcp->secs));
    printf("bp_flags; %u\n",ntohs(dhcp->flags));
    printf("CIaddr; %s\n", ip_ntoa(dhcp->ciaddr));
    printf("YIaddr; %s\n", ip_ntoa(dhcp->yiaddr));
    printf("SIaddr; %s\n", ip_ntoa(dhcp->siaddr_nip));
    printf("GIaddr; %s\n", ip_ntoa(dhcp->gateway_nip));
    int i;
    printf("chaddr: ");
    for(i=0;i<16;i++){
        printf("%u ", dhcp->chaddr[i]);
    }
    printf("\n");
    printf("sname: ");
    for(i=0;i<64;i++){
        printf("%u ", dhcp->sname[i]);
    }
    printf("\n");
    printf("file: ");
    for(i=0;i<128;i++){
        printf("%u ", dhcp->file[i]);
    }
    printf("\n");
    printf("cookie: %d\n",dhcp->cookie);
    printf("options: ");
    for(i=0;i<sizeof(dhcp->options);i++){
        printf("%x ", dhcp->options[i]);
    }
    printf("\n");
}

void analyzePacket(u_char *buf){
	u_char *ptr;
	struct ether_header *eth;
	struct iphdr *ip;
	// printEtherHeader(buf);
	ptr = buf;
	eth = (struct ether_header *)buf;
	ptr += sizeof(struct ether_header);

	switch(ntohs(eth->ether_type)){
	case ETH_P_IP:
		// printIPHeader(ptr);
		ip = (struct iphdr *)ptr;
		if(ip->protocol==6){ // tcp
			 ptr+=((struct iphdr *)ptr)->ihl*4;
			//  printTcpHeader(ptr);
		}else if(ip->protocol == 17){ // udp
            ptr += ((struct iphdr *)ptr)->ihl * 4;
            // printUdpHeader(ptr);

            // struct udphdr *ptrUdp;
            // ptr = (struct udphdr *)buf;
            if(ntohs(((struct udphdr *)ptr)->source) == 68 && ntohs(((struct udphdr *)ptr)->dest) == 67){
                // ptr += ntohs(((struct udphdr *)ptr)->len);
                ptr += sizeof(struct udphdr);
                printf("sizeof(struct updhdr) : %ld\n", sizeof(struct udphdr));
                printf("ntohs(((struct udphdr *)ptr)->len) : %d\n", ntohs(((struct udphdr *)ptr)->len));
                // printf("hello\n");
                // dumpdhcp(ptr, 0);
                printDhcp(ptr);
            }
        }
		break;
	case ETH_P_IPV6:
		printf("IPv6 Packet\n");
		break;
	case ETH_P_ARP:
		printArp(ptr);
		break;
	default:
		printf("unknown\n");
	}
}

int main(){
	int soc;
	u_char buf[65535];
	soc = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strcpy(ifr.ifr_name, "eth1");
    if(ioctl(soc, SIOCGIFINDEX, &ifr) < 0){
        perror("ioctl");
        return -1;
    }
	
	while(1){
        memset(buf, 0, sizeof(buf));
		read(soc,buf,sizeof(buf));
		analyzePacket(buf);
	}
}