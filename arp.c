#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <pcap.h>
#define REQ_CNT 20
#define Protocol_Address_Type 0x0806


void convrt_mac( const char *data, char *cvrt_str, int sz );

struct mac{
    u_int8_t dest_addr[6];
    u_int8_t src_addr[6];
    u_int16_t d_type;
};

struct arp{
        u_int16_t arp_hd_type;
        u_int16_t arp_pt_type;
        u_int8_t arp_hd_len;
        u_int8_t arp_pt_len;
        u_int16_t arp_operation;
        u_int8_t arp_sour_hd_addr[6];
        u_int8_t arp_sour_pt_addr[4];
        u_int8_t arp_target_hd_addr[6];
        u_int8_t arp_target_pt_addr[4];
};

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr *header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int status;
 int sockfd, cnt, req_cnt = REQ_CNT;
     char mac_adr[128] = {0x00,};
     struct sockaddr_in *sock;
     struct ifconf ifcnf_s;
     struct ifreq *ifr_s;
     u_char data[42]= { 0, };     
     sockfd = socket( PF_INET , SOCK_DGRAM , 0 );
     if( sockfd < 0 ) {
          perror( "socket()" );
          return -1;
     }
     memset( (void *)&ifcnf_s , 0x0 , sizeof(ifcnf_s) );
     ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
     ifcnf_s.ifc_buf = malloc(ifcnf_s.ifc_len);
     if( ioctl( sockfd, SIOCGIFCONF, (char *)&ifcnf_s ) < 0 ) {
          perror( "ioctl() - SIOCGIFCONF" );
          return -1;
     }
    
     if( ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt) ) {
          req_cnt = ifcnf_s.ifc_len;
          ifcnf_s.ifc_buf = realloc( ifcnf_s.ifc_buf, req_cnt );
     }
     ifr_s = ifcnf_s.ifc_req;
     for( cnt = 0 ; cnt < ifcnf_s.ifc_len ; cnt += sizeof(struct ifreq), ifr_s++ )
     {
          if( ioctl( sockfd, SIOCGIFFLAGS, ifr_s ) < 0 ) {
               perror( "ioctl() - SIOCGIFFLAGS" );
               return -1;
          }
         
          if( ifr_s->ifr_flags & IFF_LOOPBACK )
               continue;
          sock = (struct sockaddr_in *)&ifr_s->ifr_addr;
          printf( "\n<IP address> - %s\n" , inet_ntoa(sock->sin_addr) );
          if( ioctl( sockfd, SIOCGIFHWADDR, ifr_s ) < 0 ) {
               perror( "ioctl() - SIOCGIFHWADDR" );
               return -1;
          }
          convrt_mac( ether_ntoa((struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
          printf( "<MAC address> - %s\n" , mac_adr );
     }

     printf( "\n- code by hkpco\n" );

    /* Define the device */
    
    

    dev = pcap_lookupdev(errbuf);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    /* Grab a packet */

        struct mac * mac_addr;
	int i=0;
	

	for(i=0;i<6;i++)
        {
        mac_addr->dest_addr[i] = 0xFF;
        }

	mac_addr->src_addr[0] = 0x00;
	mac_addr->src_addr[1] = 0x0c;
	mac_addr->src_addr[2] = 0x29;
	mac_addr->src_addr[3] = 0x0a;
	mac_addr->src_addr[4] = 0xd6;
	mac_addr->src_addr[5] = 0x06;
	mac_addr->d_type = Protocol_Address_Type;

	struct arp * arp_header;
     
	char buf[6];
	char buf1[6];
	inet_ntop(AF_INET,"192.168.207.137",buf,6);
	inet_ntop(AF_INET,"192.198.207.135",buf1,6);
	arp_header->arp_hd_type = htons(0x0001);
	arp_header->arp_pt_type = Protocol_Address_Type;
	arp_header->arp_hd_len = htons(0x0006);
	arp_header->arp_pt_len = htons(0x0004);
	arp_header->arp_operation = htons(0x0001);
	arp_header->arp_sour_hd_addr[0] = 0x00;
	arp_header->arp_sour_hd_addr[1] = 0x0c;
	arp_header->arp_sour_hd_addr[2] = 0x29;
	arp_header->arp_sour_hd_addr[3] = 0x0A;
	arp_header->arp_sour_hd_addr[4] = 0xD6;
	arp_header->arp_sour_hd_addr[5] = 0x00;
	memcpy(buf,arp_header->arp_sour_pt_addr,6);
	
	
	for(i=0;i<6;i++)
	{
	arp_header->arp_target_hd_addr[i] = 0x00;
	}
	memcpy(buf1,arp_header->arp_target_pt_addr,6);
	
	mac_addr = (struct mac *)data;
	arp_header = (struct arp *)(data+14);

	printf("%s\n",data);
	pcap_sendpacket(handle,data,(sizeof(struct mac)+sizeof(arp_header)));
}

void convrt_mac( const char *data, char *cvrt_str, int sz )
{
     char buf[128] = {0x00,};
     char t_buf[8];
     char *stp = strtok( (char *)data , ":" );
     int temp=0;
     do
     {
          memset( t_buf, 0x0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );
     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}
