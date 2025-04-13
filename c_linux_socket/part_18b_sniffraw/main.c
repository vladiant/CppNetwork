#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

/* https://cs.dartmouth.edu/~tjp/cs55/code/sniffspoof/sniff_raw.c */

/* Receive raw frames using C

    Author: Tim Pierson, Dartmouth CS55, Winter 2021
        From Du: Computer and Internet Security

    compile gcc sniff_raw.c -o sniff_raw
    run: ./sniff_raw

    NOTE: careful, this may get overwhelmed with network traffic!

*/

int main() {
  int PACKET_LEN = 512;
  char buffer[PACKET_LEN];
  struct sockaddr saddr;
  struct packet_mreq mr;

  // Create the raw socket
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  // Turn on the promiscuous mode.
  mr.mr_type = PACKET_MR_PROMISC;
  setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

  // Getting captured packets
  while (1) {
    int data_size = recvfrom(sock, buffer, PACKET_LEN, 0, &saddr,
                             (socklen_t*)sizeof(saddr));
    if (data_size) printf("Got one packet\n");
  }

  close(sock);
  return 0;
}
