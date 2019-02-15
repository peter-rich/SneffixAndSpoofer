//        Zhanfu Yang   yang1676@purdue.edu   spoofer.c
//
//	  Function to spoof in ICMP and Ethernet modes
//
//        Usage :   gcc -o spoofer spoofer.c
//
//	  Running:  sudo ./spoofer 1 // ICMP mode
//                  sudo ./spoofer 2 // Ethernet mode

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

/*
* in_cksum --
* Checksum routine for Internet Protocol
* family headers (C Version)
*/

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
void ICMP_Header(struct iphdr *ip, struct icmphdr *icmp) {
//
// Setup the Ip address:
//

        const char *ip_src              = "192.168.15.6"; // spoofed IP
        const char *ip_dst              = "172.69.90.11"; // Destination IP
	ip->ihl         	 	= 5; // set internet header
	ip->version          		= 4;
	ip->saddr            		= inet_addr(ip_src);
    	ip->daddr            		= inet_addr(ip_dst);
    	ip->tot_len          		= sizeof(struct iphdr) + sizeof(struct icmphdr);
    	ip->ttl                      	= 64;
    	ip->frag_off         		= 0x0;
    	ip->protocol         		= IPPROTO_ICMP;

// Set ICMP
        icmp->type 			= ICMP_ECHO; //ICMP Echo Type
	icmp->checksum 			= in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));
}

// Ethernet Header, When use the ethernet mode, we will use the setting of the ICMP
void Ethernet_Header(struct ethhdr *ethernet) {
	const unsigned char ethernet_src_addr[]	= {0x01,0x02,0x03,0x04,0x05,0x06}; // Source Mac address
	const unsigned char ethernet_dst_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff}; //Destination address
	memcpy(ethernet->h_source, ethernet_src_addr,6);
	memcpy(ethernet->h_dest, ethernet_dst_addr,6);
	ethernet->h_proto = htons(ETH_P_IP);
}

int getIndexNetwork(char* interface_name, int sock) {
	struct ifreq source_buf;
	memset(&source_buf, 0x00, sizeof(source_buf));
	strncpy(source_buf.ifr_name, interface_name, IFNAMSIZ);
	ioctl(sock, SIOCGIFINDEX, &source_buf);
	return source_buf.ifr_ifindex;
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

int ICMP(void) {
	int sock; 
	struct sockaddr_in connection;
	char packet[512]; // Raw packet.
	int optval = 1;
	memset((void*)&packet, 0, sizeof(512)); 
	/* (1) Create a raw socket. 
	 *
	 *  IPPROTO_RAW parameter inform the system that the IP is included
	 * ***  */
	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
       	check_sock(sock, "socket() error");
	 
	/* (2) Set socket option
	 * */
	connection.sin_family = AF_INET;
	
	// (3) Construct the IP packet using
	struct iphdr *ip = (struct iphdr *) packet; // Construct IP header
	struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof(struct iphdr)); // Construct ICMP header
	
	ICMP_Header(ip, icmp);


	// (4) send out the packet
	check_sock(sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(connection)), "send() error");
	
	return 1;
}

/***************************************************************************************
Mainfunction for Ethernet spoofer:

(1) create a raw socket, 
(2) set socket option, 
(3) construct the packet, and 
(4) send out the packet through the raw socket.

*/
int Ethernet(void) {

	int sock; 
	char packet[512]; // Raw packets
	// (1) Raw socket
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	check_sock(sock, "socket() error");

	char *source_name = "eth14"; // network interface of the source
	// (2) FInd out the Network adaptor
	int source_idx = getIndexNetwork(source_name,sock); //find out the network adaptor

	// (3) Construct the IP packet
	struct ethhdr *ethernet = (struct ethhdr *) packet;
	struct iphdr *ip = (struct iphdr *) (packet + sizeof(struct ethhdr));
	struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	
	Ethernet_Header(ethernet);	
	ICMP_Header(ip, icmp);

	// (4) Setting up the linklayer structure to send packets
	struct sockaddr_ll connection;
	memset((void*)&connection, 0, sizeof(connection)); // Initial the value
	connection.sll_ifindex = source_idx; // the adapter

	check_sock(sendto(sock, packet, ip->tot_len+6, 0, (struct sockaddr*)&connection, sizeof(connection)), "sendto() err");
	return 1;
}

int main(int argc, char const *argv[]) {

	int opt = atoi(argv[1]);
	int run;
	if (opt == 1) {
		run = ICMP(); //
		if (run != 1) {
			printf("ICMP failed.\n");
			exit(1);
		}
	} else {
		run = Ethernet();
		if (run != 1) {
			printf("Ethernet failed.\n");
			exit(1);
		}
	}
	printf("\n\n All Complete. \n\n");

	return 0;
}
