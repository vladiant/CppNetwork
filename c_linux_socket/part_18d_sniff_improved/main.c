#include <pcap.h>
#include <stdio.h>

/* https://cs.dartmouth.edu/~tjp/cs55/code/sniffspoof/sniff_improved.c */

/* Sniff frames using C and PCAP

    Author: Tim Pierson, Dartmouth CS55, Winter 2021
        From Du: Computer and Internet Security

    compile gcc sniff.c -o sniff -lpcap
    run: sudo ./sniff

    NOTE: Will not run without sudo (no rights to interface)!
    try opening Firefox to get traffic

*/

/* Ethernet header */
struct ethheader {
  u_char ether_dhost[6]; /* destination host address */
  u_char ether_shost[6]; /* source host address */
  u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char iph_ihl : 4,        // IP header length
      iph_ver : 4;                  // IP version
  unsigned char iph_tos;            // Type of service
  unsigned short int iph_len;       // IP Packet length (data + header)
  unsigned short int iph_ident;     // Identification
  unsigned short int iph_flag : 3,  // Fragmentation flags
      iph_offset : 13;              // Flags offset
  unsigned char iph_ttl;            // Time to Live
  unsigned char iph_protocol;       // Protocol type
  unsigned short int iph_chksum;    // IP datagram checksum
  struct in_addr iph_sourceip;      // Source IP address
  struct in_addr iph_destip;        // Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) {  // 0x0800 is IP type
    struct ipheader *ip =
        (struct ipheader *)(packet + sizeof(struct ethheader));

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));

    /* determine protocol */
    switch (ip->iph_protocol) {
      case IPPROTO_TCP:
        printf("   Protocol: TCP\n");
        return;
      case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        return;
      case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        return;
      default:
        printf("   Protocol: others\n");
        return;
    }
  }
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "udp or icmp";
  bpf_u_int32 net;
  const int MAX_SIZE = 8192;

  // Step 1: Open live pcap session on NIC with name enp4s0
  handle = pcap_open_live("enp4s0", MAX_SIZE, 1, 1000, errbuf);
  if (handle == NULL) {
    printf("Error on open\n");
    printf("errbuf %s\n", errbuf);
    return (1);
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
    printf("set filter error");
    return (1);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);  // Close the handle
  return 0;
}
