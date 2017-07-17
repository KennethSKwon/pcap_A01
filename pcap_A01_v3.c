#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct _eth_set{
	unsigned char dst_eth_addr[6];
	unsigned char src_eth_addr[6];
	unsigned short eth_type;
};// __attribute__((packed));     
// __attribute__((packed))  is advised by teammates

struct _ip_set{
	unsigned char ip_version:4;
	unsigned char ip_ihl:4;
	unsigned char ip_tos;
	unsigned char ip_tl[2];
	unsigned char ip_id[2];
	unsigned char ip_flag:3;
	unsigned short ip_FragmentOffset:13;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned char ip_cksum[2];
	unsigned char ip_src_addr[4];
	unsigned char ip_dst_addr[4];
};//__attribute__((packed));
//
struct _tcp_set{
	unsigned short tcp_src_port;
	unsigned short tcp_dst_port;
	unsigned char sq_num[4];
	unsigned char ack_num[4];
	unsigned char offset:4;
	unsigned char reserved:4;
	unsigned char tcp_flags;
	unsigned char window_s[2];
	unsigned char tcp_cksum[2];
	unsigned char urgent_pt[2];
};//__attribute__((packed));

int main(int argc, char *argv[]){
	printf("*START*");
	pcap_t *handle;			
	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;		
	char filter_exp[] = "port 80";	
	bpf_u_int32 mask;	
	bpf_u_int32 net;		
	struct pcap_pkthdr *header;
	int ck_packet;	
	const u_char *packet;		
	
	// ether packet 14 bye
	struct _eth_set *_eth;
	struct _ip_set *_ip;
	struct _tcp_set *_tcp;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	
//START
	while(1){
		ck_packet = pcap_next_ex(handle, &header,&packet);
		if(ck_packet==0){
			printf("ck_packet=0\n");
			continue;
		}
		else if(ck_packet==1){
			_eth=(struct _eth_set*)(packet);
			//packet=packet+14;   //if use in below 'packet+14' it means  address+14.  so did in here.
			_ip=(struct _ip_set*)(&(packet[14]));
			
			//packet=packet+20;  // same with above commend
			_tcp=(struct _tcp_set*)(&(packet[34]));

			printf("\ndst MAC : ");
			for(int i = 0; i<6; i++){	
				printf("%02x ", _eth->dst_eth_addr[i]);
			}
			
			printf("\nsrc MAC : ");
				for(int i = 0; i<6; i++){
				printf("%02x ", _eth->src_eth_addr[i]);
			}
			printf("\n");


			printf("dst IP : ");
			for(int i=0; i<4; i++){
				printf("%d ",_ip->ip_dst_addr[i]);
			}
			printf("\nsrc IP : ");
			for(int i=0; i<4; i++){
				printf("%d ", _ip->ip_src_addr[i]);
			}

			printf("\n");
			printf("dst Port : ");
			

			printf("%hu ", ntohs(_tcp->tcp_dst_port));
			printf("\nsrc Port : ");
			printf("%hu ", ntohs(_tcp->tcp_src_port));
		
		}
		else{
			printf("ck_packout wrong\n");
			break;
		}

		
		//printf("\n\n*END*\n\n");
			printf("\n\n");

			for(int i=1; i<=60; i++){
				if(i % 16 == 0)
					printf("\n");
				else
					printf("%02x ", packet[i - 1]);
			}
			printf("\n\n");

	}
	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */

	pcap_close(handle);
	return(0);
 }
		
	