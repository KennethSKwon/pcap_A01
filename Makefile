all:
	gcc -o pcap_A01_v1 pcap_A01_v2.c -lpcap
	gcc -o pcap_A01_v2 pcap_A01_v2.c -lpcap
	gcc -o pcap_A01_v3 pcap_A01_v3.c -lpcap
clean:
	rm pcap_A01_v1
	rm pcap_A01_v2
	rm pcap_A01_v3

