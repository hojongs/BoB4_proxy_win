#include "stdafx.h" //3,4

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define ICMPHDR_LEN 8
#define RES_MAC { 0x2c, 0x21, 0x72, 0x93, 0xdf, 0x00 }
#define MIDDLE_MAC { 0xd8, 0xfc, 0x93, 0x46, 0x58, 0x70 } //(SRC)REQ_IP/MAC -> MIDDLE_IP/MAC
#define MIDDLE_IP "192.168.32.231" //ME
#define REQ_MAC {0x00, 0x27, 0x1c, 0xcd, 0xdd, 0x04}									//(DST)MIDDLE_IP/MAC -> REQ_IP/MAC
#define REQ_IP "192.168.137.84" //BOB_MIL

#define	ETHER_ADDR_LEN		6
#define ETH_P_IP 0x0800

/*
* Structure of a 10Mb/s Ethernet header.
*/
typedef struct	ether_header {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
}ethhdr;

/*
* Structure of a 48-bit Ethernet address.
*/
struct	ether_addr {
	u_char octet[ETHER_ADDR_LEN];
};

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver : 4;        // ver (4 bits) + Internet header length (4 bits)
	u_char  ihl : 4;
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
//	ip_address  saddr;      // Source address
//	ip_address  daddr;      // Destination address
	u_long saddr;
	u_long daddr;
	u_int   op_pad;         // Option + Padding
}iphdr;

/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udphdr;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t  data_offset : 4;  // 4 bits
	uint8_t  not_used : 4;
	uint8_t  flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} tcp_header_t, tcphdr;

void req_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	pcap_t* res_handle = (pcap_t*)args;

	char*ptr = (char*)buffer;
	ethhdr*ethptr = (ethhdr*)ptr;
	iphdr*ipptr;
	tcphdr*tcpptr;
	udphdr*udpptr;
	char*data;

	if (ethptr->ether_type == htons(ETH_P_IP))
	{
		ipptr = (iphdr*)(ptr + sizeof(ethhdr));
	}
	else
	{
		//	printf("IPv6\n");
		return;
	}

	//printf("PROTO : %d\n", ipptr->proto);
	switch (ipptr->proto)
	{
	case PROTO_TCP:
		tcpptr = (tcphdr*)(ptr + sizeof(ethhdr) + ipptr->ver * 4);
		data = ptr + sizeof(ethhdr) + ipptr->ver * 4 + tcpptr->data_offset * 4;
		break;
	case PROTO_UDP:
		udpptr = (udphdr*)(ptr + sizeof(ethhdr) + ipptr->ver * 4);
		data = ptr + sizeof(ethhdr) + ipptr->ver * 4 + udpptr->len;
		break;
	case PROTO_ICMP:
		printf("len : %d bytes\n", header->len);
		data = ptr + sizeof(ethhdr) + ipptr->ver * 4 + ICMPHDR_LEN;
		break;
	default:
		printf("exception\n");
		printf("type : 0x%x\n", ipptr->proto);
	}

	//todo
	//filtering

	//printf("saddr : %u %u\n", ipptr->saddr, inet_addr(REQ_IP));
	if (ipptr->saddr == inet_addr(REQ_IP))
	{ //request packet
		u_char* temp = (u_char*)ethptr->ether_shost;
		//printf("mac before : ");
		//for (int i = 0; i<ETHER_ADDR_LEN; i++)
		//{
		//	printf("%02x", temp[i]);
		//	if (i<ETHER_ADDR_LEN - 1)
		//		printf(":");
		//}
		printf("\n");
		u_char src_mac_array[6] = MIDDLE_MAC;
		printf("src mac : ");
		for (int i = 0; i<ETHER_ADDR_LEN; i++)
		{
			*temp = src_mac_array[i]; //src change
			temp++;
			printf("%02x", temp[i]);
			if (i<ETHER_ADDR_LEN - 1)
				printf(":");
		}
		printf("\n");
		printf("dst mac : ");
		u_char dst_mac_array[6] = RES_MAC;
		for (int i = 0; i<ETHER_ADDR_LEN; i++)
		{
			*temp = dst_mac_array[i]; //dst change
			temp++;
			printf("%02x", temp[i]);
			if (i<ETHER_ADDR_LEN - 1)
				printf(":");
		}
		printf("\n");
		

		printf("0x%08x\n", ipptr->saddr);
		ipptr->saddr = inet_addr(MIDDLE_IP);
		printf("0x%08x\n", ipptr->saddr);
	}

	//return; //stop

	/* Send down the packet */
	if (pcap_sendpacket(res_handle, buffer, header->len /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(res_handle));
		return;
	}
}

void res_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){};

void* caller_thread(void *args)
{ //res_handling func caller
	struct handlezip* hdzip = (struct handlezip*)args;
	pcap_loop(hdzip->res_handle, -1, res_handling, (u_char*)hdzip->req_handle);

	return NULL;
}


int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	int j;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *alldevsp, *device;
	pcap_t *req_handle, *res_handle;

	char *devname, devs[100][100];
	int count = 1, n;

//	pthread_t thread;
	int iret;

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	j = i;
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum, sizeof(inum));

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((req_handle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
		// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//////////////////////////////////////////////////
	printf("Enter the interface number (1-%d):", j);
	scanf_s("%d", &inum, sizeof(inum));

	if (inum < 1 || inum > j)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, j = 0; j< inum - 1; d = d->next, j++);

	/* Open the device */
	if ((res_handle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
		// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	struct handlezip hdzip;
	hdzip.req_handle = req_handle;
	hdzip.res_handle = res_handle;

	//if (iret = pthread_create(&thread, NULL, caller_thread, (void*)&hdzip))
	//	perror("pthread_create");

	pcap_loop(req_handle, -1, req_handling, (u_char*)res_handle);

	return 0;
}
