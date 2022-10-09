#pragma once

#include <iostream>
#include <mutex>
#include <thread>
#include <fstream>              // std::ifstream
#include <unistd.h>             // close, sleep
#include <sys/socket.h>         // socket, AF_INET
#include <sys/types.h>          // some historical (BSD) implementations required 
                                //      this header file, and portable applications are 
                                //      probably wise to include it.
#include <arpa/inet.h>          // inet_ntop
#include <sys/ioctl.h>          // ioctl
#include <net/if.h>             // ifreq
#include <cstdint>              // uint8_t
#include <cstring>              // strncpy, memset
#include <pcap.h>               // pcap

#include <thread>               // std::thread

#include "mac.hpp"
#include "ip.hpp"
#include "ethhdr.hpp"
#include "arphdr.hpp"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct flagSet final {
    uint8_t mainFlag: 4,    // flag from main
            threadFlag: 4;  // flag from thread, used in Keyboard Interrupt
};
#pragma pack(pop)

#define CREATE_SOCKET_ERROR_MSG "Error: Error while create socket\n"
#define IOCTL_ERROR_MSG "Error: Error while ioctl\n"
#define SEND_PACKET_ERROR_MSG "Error: Error while send packet\n"
#define CLOSE_ERROR_MSG "Error: Error while close file descriptor\n"
#define GET_MAC_ERROR_MSG "Error: Error while get local MAC address\n"
#define SLEEP_ERROR_MSG "Error: Error while sleep\n"

#define PCAP_RECEIVE_PACKET_ERROR "Error : Error while pcap_next_ex: "

extern std::vector<volatile flagSet> endFlag;
extern std::mutex mutex4Flag;

std::map<IPv4, Mac> attackerARPTable;
std::mutex mutex4Map;

bool getMyInfo(const std::string& interface, Mac& MAC, IPv4& IP);
bool resolveMACByIP(pcap_t* pcap, 
                    Mac& MAC, const IPv4& IP, 
                    const Mac& myMAC, const IPv4& myIP);
void ARPpacketConstructor(EthArpPacket& packet, 
                          const Mac& destMAC, const Mac& sourceMAC, 
                          const Mac& sendMAC, const IPv4& sendIP,
                          const Mac& targetMAC, const IPv4& targetIP,
                          const ArpHdr::Mode ARPMode = ArpHdr::Mode::Request);

bool sendPacket(pcap_t* pcap, const EthArpPacket& packet);
bool sendPacket(pcap_t* pcap, const uint8_t* packet, const int packetLength);

bool sendARPPacketRepeatedly(pcap_t* pcap, 
                            const Mac& destMAC, const Mac& sourceMAC,
                            const Mac& sendMAC, const IPv4& sendIP, 
                            const Mac& targetMAC, const IPv4& targetIP, 
                            const ArpHdr::Mode mode, const int idx);

bool managePackets(pcap_t* pcap, const Mac& myMAC,
                   const Mac& sendMAC, const IPv4& sendIP, 
                   const Mac& targetMAC, const IPv4& targetIP, 
                   const int idx);

void printInfo(const Mac& myMAC, const IPv4& myIP, 
               const Mac& sendMAC, const IPv4& sendIP, 
               const Mac& targetMAC, const IPv4& targetIP);

bool attackARP(pcap_t* pcap, 
               const Mac& myMAC, const IPv4& myIP,
               const Mac& sendMAC, const IPv4& sendIP, 
               const Mac& targetMAC, const IPv4& targetIP,
               const int idx);
