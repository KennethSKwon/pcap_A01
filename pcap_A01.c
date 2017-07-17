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


// added viariable
	char *net_addr;
	char *mask_addr;
	int ret;   // return code
	struct in_addr addr; // using sturc in witch header ?

//	struct ether_header et_addr;
/*
	typedef struct ether_header {
	        u_char  ether_dhost[6];     
		u_char  ether_shost[6];     
		u_short ether_type;         
	} ETHERHDR;
*/





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

	ret=pcap_lookupnet(dev,&net,&mask,errbuf);
	if(ret==-1){
		printf("%s\n",dev);
		exit(1);
		}
	
	addr.s_addr=net;
	net_addr=inet_ntoa(addr);
	if(net==NULL)
	{
	 perror("inet_ntoa");
	 exit(1);
	 }

	 printf("NET: %s\n",net_addr);
	 addr.s_addr=mask;
	 mask_addr=inet_ntoa(addr);
	 if(net==NULL)
	 {
	  perror("inet_ntoa");
	  exit(1);    
	  }
	         
		           printf("NET: %s\n",net_addr);

      

	printf("%s\n",handle);

	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);

	/* And close the session*/
	pcap_close(handle);

	return(0);
}
