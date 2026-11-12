#include "traceroute.h"

// Constant values
const int PACKET_SIZE = 64;
const int PAYLOAD_SIZE = PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct icmphdr);
const int FIRST_TTL = 2;
const int MAX_PACKETS = 30;
const int REPLY_TIMEOUT_SEC = 15; // Total time to wait per packet
const int SELECT_INTERVAL_SEC = 5; // How long each select() sleeps
const int RECV_BUF_SIZE = 1500;

// Enum to classify reply type
enum ReplyType {REPLY_IGNORE, REPLY_TTL_EXCEEDED, REPLY_ECHO};

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

// Classify reply helper function - to be fleshed out fully
ReplyType classifyReply(const char* recvBuf, ssize_t bytesRead, int sequence){
  // Case the ip and icmp pointers on to the buffer
  struct iphdr* ip = (struct iphdr*) recvBuf;
  struct icmphdr* icmp = (struct icmphdr*) (recvBuf + ip->ihl * 4);

  // Debug log to log what has been received
  DEBUG << "type=" << (int) icmp->type << " code=" << (int) icmp->code << ENDL;

  // Return a basic ReplyType for now
  return REPLY_IGNORE;
}

// Build packet helper function
void buildPacket(char* buffer, struct in_addr binaryIP){
  // Zero the buffer, then fill the payload
  memset(buffer, 0, PACKET_SIZE);
  memset(buffer, 'A', PAYLOAD_SIZE);

  // Cast pointers on to the buffer
  struct iphdr *ip = (struct iphdr*) buffer;
  struct icmphdr *icmp = (struct icmphdr*) (buffer + sizeof(struct iphdr));

  // Fill out the IP header
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(PACKET_SIZE);
  ip->id = 0;
  ip->frag_off = 0;
  ip->protocol = IPPROTO_ICMP;
  ip->check = 0;
  ip->saddr = 0;
  ip->daddr = binaryIP.s_addr;

  // Fill out the ICMP header
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = htons(getpid() & 0xFFFF);
}

// Update packet method (called every loop iteration)
void updatePacket(char* buffer, int ttl, int sequence){
  // Cast pointers on to the buffer
  struct iphdr *ip = (struct iphdr*) buffer;
  struct icmphdr *icmp = (struct icmphdr*) (buffer + sizeof(struct iphdr));

  // Set ip->ttl
  ip->ttl = ttl;

  // Set tcmp->un.echo.sequence with htons()
  icmp->un.echo.sequence = htons(sequence);

  // Set icmp->checksum = 0, then compute it
  icmp->checksum = 0;
  icmp->checksum = checksum(buffer, sizeof(struct icmphdr) + PAYLOAD_SIZE);
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
  if (inet_pton(AF_INET, destIP.c_str(), &ip_binary) == 1){
    TRACE << "The binary address was successfully created :" << ip_binary.s_addr << ENDL;
  }
  else {
    ERROR << "Something unexpected happened in convertng the IP to a binary address" << ENDL;
    return -1;
  }

  // Create the sendBuf buffer
  char sendBuf[PACKET_SIZE];
  buildPacket(sendBuf, ip_binary);

  //----- Part 2: The two sockets (send and receive) -----
  // Create the send socket
  int sendFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Check to ensure the socket didn't error
  if (sendFd == -1){
    // No socket was opened, log error and return
    ERROR << "Opening the send Fd failed" << ENDL;
    return -1;
  }

  // Create the receive socket
  int recvFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

  // Check to ensure the socket didn't error
  if (recvFd == -1){
    // Receive socket wasn't opened, log error, close sendFd, then return
    ERROR << "Opening the reveive Fd failed" << ENDL;
    close(sendFd);
    return -1;
  }

  // Build out the destination address
  struct sockaddr_in destAddr;
  memset(&destAddr, 0, sizeof(destAddr));
  destAddr.sin_family = AF_INET;
  destAddr.sin_addr = ip_binary;

  //----- Part 3: The main loop -----
  // Create the reveived buffer and tracking variables
  char recvBuf[RECV_BUF_SIZE];
  bool reachedDestination = false;
  int sequence = 1;

  // Send up to 30 packets and stops early if EchoReply is received
  for (int ttl = FIRST_TTL; ttl < (FIRST_TTL + MAX_PACKETS) && !reachedDestination; ttl++, sequence++){
    // Stamp this packet with the current TTL and sequence
    updatePacket(sendBuf, ttl, sequence);

    // Send the packet - test if it fails
    if (sendto(sendFd, sendBuf, PACKET_SIZE, 0, (struct sockaddr*) &destAddr, sizeof(destAddr)) == -1){
      FATAL << "Packet send failed" << ENDL;
      break; 
    }

    // Log the sent packet with DEBUG
    DEBUG << "Sent packet with TTL: " << ttl << ENDL;

    // Wait up to 15 seconds for a reply to this packet
    time_t startTime = time(NULL);
    bool gotAnswer = false;


    // Loop while the answer hasn't been received and the time is less than the timeout limit
    while (!gotAnswer && (time(NULL) - startTime) < REPLY_TIMEOUT_SEC){
      // Rebuild timeout and readFd attributes every iteration
      fd_set readFdSet;
      struct timeval timeout;
      timeout.tv_sec = SELECT_INTERVAL_SEC;
      timeout.tv_usec = 0;
      FD_ZERO(&readFdSet);
      FD_SET(recvFd, &readFdSet);

      // Int value to see if an error or timeout occurred
      int ready = select(recvFd + 1, &readFdSet, NULL, NULL, &timeout);
      if (ready < 0){
        // Error occcured, log error, cleanup, then exit
        ERROR << "Select error occured" << ENDL;
        close(sendFd);
        close(recvFd);
        exit(-1);
      }
      if (ready == 0){
        DEBUG << "Timeout: no socket activity" << ENDL;
        continue;
      }

      // If the fd is set, process the response
      if (FD_ISSET(recvFd, &readFdSet)){
        // Create the received address
        struct sockaddr_in recvAddr;
        // Get the length of the address - reset everu time
        socklen_t addrLen = sizeof(recvAddr);
        // Extract the bytes read
        ssize_t bytesRead = recvfrom(recvFd, recvBuf, RECV_BUF_SIZE, 0, (struct sockaddr*) &recvAddr, &addrLen);

        // Check if the bytes read is less then zero, log the error and close
        if (bytesRead < 0){
          ERROR << "No bytes read - exiting" << ENDL;
          close(recvFd);
          close(sendFd);
          exit(-1);
        }

        // Get the reply type
        ReplyType reply = classifyReply(recvBuf, bytesRead, sequence);

        // Convert recvAddr.sin_addr to a string
        char ipString[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &recvAddr.sin_addr, ipString, INET_ADDRSTRLEN);

        // If the reply is REPLY_TTL_EXCEEDED -> print hop, gotAnswer = true
        if (reply == REPLY_TTL_EXCEEDED){
          std::cout << "TTL " << ttl << ": " << ipString << std::endl;
          gotAnswer = true;
        }

        // If the reply is REPLY_ECHO -> print hop and final message, gotAnswer = true, reachedDestination = true
        if (reply == REPLY_ECHO){
          std::cout << "TTL " << ttl << ": " << ipString << std::endl;
          gotAnswer = true;
          reachedDestination = true;
        }

        // REPLY_IGNORE was the reply, do nothing and keep waiting
      }
    }

    // If gotAnswer is false, log no response and its ttl
    if (!gotAnswer){
      std::cout << "No response with TTL of " << ttl << std::endl;
    }
  }

  // Close the file descriptors
  close(sendFd);
  close(recvFd);

  //----- Part 4: Classifying what has been reveived -----
}
