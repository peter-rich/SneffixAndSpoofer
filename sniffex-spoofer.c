//        Zhanfu Yang   yang1676@purdue.edu   sniffix-spoofer.c
//
//	  Function to spoof in ICMP and Ethernet modes
//
//        Usage :   gcc -Wall -o sniffex-spoofer sniffex-spoofer.c -lpcap
//
//	  Running:  sudo ./sniffix-spoofer
//                  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>  

#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

// Define the stuct of the ICMP
struct sniff_icmp {
	u_char type;
	u_char code;
	u_short chksum;
	u_short id;
	u_short sequence;
};

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);


void
print_app_usage(void);

/*
 * print help text
 */
void print_app_usage(void)
{

        printf("Usage: %s [interface]\n", "Sniffex_Spoofer");
        printf("\n");
        printf("Options:\n");
        printf("    interface    Listen on <interface> for packets.\n");
        printf("\n");

	return;
}


unsigned short in_cksum(unsigned short *addr, int len) {
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;
        /* Our algorithm is simple, using a 32 bit accumulator (sum), we add
        * sequential 16 bit words to it, and at the end, fold back all the
        * carry bits from the top 16 bits into the lower 16 bits.
        */
        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }
        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *) (&answer) = *(u_char *) w;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
        sum += (sum >> 16); /* add carry */
        answer = ~sum; /* truncate to 16 bits */
        return (answer);
}



// ICMP header
void ICMP_Header(struct iphdr *ip, struct icmphdr *icmp, const struct sniff_ip *dst) {
//
// Setup the Ip address:
//

	memcpy (ip, dst, htons(dst->ip_len));
	//ip->ihl         	 	= 5; // set internet header
	//ip->version          		= 4;
	ip->saddr	          	= dst->ip_dst.s_addr;
    	ip->daddr	            	= dst->ip_src.s_addr;
    	//ip->tot_len          		= sizeof(struct iphdr) + sizeof(struct icmphdr);
    	//ip->ttl                      	= 64;
    	//ip->frag_off         		= 0x0;
    	//ip->protocol         		= IPPROTO_ICMP;

// Set ICMP
	icmp->type 			= ICMP_ECHOREPLY;
	icmp->code 			= 0;
	//icmp->un.echo.id 		= dst_icmp->id;
	//icmp->un.echo.sequence 		=  dst_icmp->sequence;
	icmp->checksum			= 0;
	icmp->checksum                  = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));
}


void check_sock(int i, char * s_error){
	if (i < 0) {
		perror(s_error);
		exit(EXIT_FAILURE);
	}
}
/***************************************************************************************
Mainfunction for ICMP spoofer:

(1) create a raw socket, 
(2) set socket option, 
(3) construct the packet, and 
(4) send out the packet through the raw socket.

*/

void ICMP(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	const struct sniff_ethernet *ethernet;  /* The ethernet header */
	const struct sniff_ip *dst;              /* The IP header */
	const struct sniff_icmp *dst_icmp;

	/* define/compute ip header offset */

	dst = (struct sniff_ip*)(packet+SIZE_ETHERNET);

	int sock; 
	struct sockaddr_in connection;
	
	char buffer[1024]; // Raw packet.
	memset((void*)&buffer, 0, 1024); 
	
	/* (1) Create a raw socket. 
	 * ***  */
	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
       	check_sock(sock, "socket() error");
	 
	/* (2) Set socket option
	 * */
	connection.sin_family = AF_INET;
	connection.sin_addr.s_addr = dst->ip_src.s_addr;
	
	// (3) Construct the IP packet using
	struct iphdr *ip = (struct iphdr *) buffer;// + sizeof(struct ethhdr));
	struct icmphdr *icmp = (struct icmphdr *) (buffer  + sizeof(struct iphdr));		
	
	ICMP_Header(ip, icmp, dst);

	// (4) send out the packet
	check_sock(sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&connection, sizeof(connection)), "send() error");
	
	// Send out
	printf("Sent spoofed ICMP packet.\n");
	
}


int main(int argc, char const *argv[]) {	
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	char dev[] = "eth14";
	char filter_exp[] = "icmp and src net 192.168.15.4";		/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1;			/* number of packets to capture */

        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
                net = 0;
                mask = 0;
        }

	/* print capture info */
	printf("Device: %s\n", "eth14");
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	handle = pcap_open_live("eth14", SNAP_LEN, 1, 1000, errbuf);

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -(num_packets), ICMP, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\n\nALL complete.\n\n");

	return 0;
}
