#include <pcap.h>
#include <stdio.h>

#include<stdlib.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include<sys/types.h>
//#include<net/if_var.h>
#include<net/if_arp.h>



int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */

	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	u_char eth_mac[6];
	u_char ip_addr[4];
	u_char tcp_port[2];


	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	/*Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		printf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		printf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	packet = pcap_next(handle, &header);


	// From here,  main functioning
	// www.tcpdump.org/manpages/pcap.3pcap.html   refernces




	printf("Device: %s\n",dev);
	//printf("net? : %s", net);   // what's the defference above one?
	//printf("mastk : %s",mask);

	

	printf("dst MAC : ");
	for(int i=0; i<6; i++){
		eth_mac[i]=packet[i];
		printf("%02x ",eth_mac[i]);
	}
	printf("\nsrc MAC : ");
	for(int i=0; i<6; i++){
		eth_mac[i]=packet[i+6];
		printf("%02x ", eth_mac[i]);
	}

	printf("\ndst IP : ");
	for(int i=0; i<4; i++){
		ip_addr[i]=packet[i+14+16];
		printf("%d ", ip_addr[i]);
	}
	printf("\nsrc IP : ");
	for(int i=0; i<4; i++){
		ip_addr[i]=packet[i+14+12];
		printf("%d ", ip_addr[i]);
	}

	printf("\ndst Port : ");
	for(int i=0; i<2; i++){
		tcp_port[i]=packet[i+36];
		printf("%02x ", tcp_port[i]);
	}
	printf("\nsrc Port : ");
	for(int i=0; i<2; i++){
		tcp_port[i]=packet[i+34];
		printf("%02x ", tcp_port[i]);
	}
	printf("\n\n END \n\n");

	for(int i=1; i<=60; i++){
			if(i % 16 == 0)
				printf("\n");
			else
				printf("%02x ", packet[i - 1]);
	}
	printf("\n\n");
		



	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);

	/* And close the session*/
	pcap_close(handle);

	return(0);
}
