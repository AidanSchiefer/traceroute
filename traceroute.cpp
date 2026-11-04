#include "traceroute.h"

// Constant values
const int PACKET_SIZE = 64;
const int PAYLOAD_SIZE = PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct icmphdr);

// ****************************************************************************
// * Compute the Internet Checksum over an arbitrary buffer.
// * (written with the help of ChatGPT 3.5)
// ****************************************************************************
uint16_t checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(unsigned char *) buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

// Build packet helper function
void buildPacket(char buffer, struct in_addr binaryIP){
  // Zero the buffer, then fill the payload
  memset(buffer, 0, sizeof(char));

  // Cast pointers on to the buffer
  struct iphdr *ip = (struct iphdr*) sendBuf;
  struct icmphdr *icmp = (struct icmphdr*) (sendBuf + sizeof(struct iphdr));

  // Fill out the IP header
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = PACKET_SIZE;
  ip->id = 0;
  ip->frag_off = 0;
  ip->protocol = IPPROTO_ICMP;
  ip->check = 0;
  ip->saddr = 0;
  ip->daddr = binaryIP;

  // Fill out the ICMP header
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = htons(getpid() & 0xFFFF);
}

// Update packet method (called every loop iteration)
void updatePacket(){
  // Set ip->ttl

  // Set tcmp->un.echo.sequence with htons()

  // Set icmp->checksum = 0, then compute it
}

int main (int argc, char *argv[]) {
  std::string destIP;

  // ********************************************************************
  // * Process the command line arguments
  // ********************************************************************
  int opt = 0;
  while ((opt = getopt(argc,argv,"t:d:")) != -1) {

    switch (opt) {
    case 't':
      destIP = optarg;
      break;
    case 'd':
      LOG_LEVEL = atoi(optarg);;
      break;
    case ':':
    case '?':
    default:
      std::cout << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]" << std::endl;
      exit(-1);
    }
  }


  //----- Part 1: Building the packet -----
  // Validate that the destIP is not empty
  if (destIP.empty()){
    ERROR << "The destination IP is empty" << ENDL;
  }
  
  // Convert the string to a binary address
  struct in_addr ip_binary;
  if (inet_pton(AF_INET, destIP, &ip_binary) == 1){
    TRACE << "The binary address was successfully created :" << ip_binary.s_addr << ENDL;
  }
  else {
    ERROR << "Something unexpected happened in convertng the IP to a binary address" << ENDL;
  }

  // Create the sendBuf buffer
  char sendBuf[PACKET_SIZE];
  buildPacket(sendBuf, destIP);

  //----- Part 2: The two sockets (send and receive) -----


  //----- Part 3: The main loop -----


  //----- Part 4: Classifying what has been reveived -----
}
