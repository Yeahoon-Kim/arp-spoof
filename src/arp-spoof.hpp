#pragma once

#include <iostream>             // std::cout
#include <fstream>              // std::ifstream
#include <unistd.h>             // close, sleep, usleep
#include <sys/socket.h>         // socket, AF_INET
#include <sys/types.h>          // some historical (BSD) implementations required 
                                //      this header file, and portable applications are 
                                //      probably wise to include it.
#include <arpa/inet.h>          // inet_ntoa
#include <sys/ioctl.h>          // ioctl
#include <net/if.h>             // ifreq
#include <cstdint>              // uint8_t
#include <cstring>              // strncpy, memset
#include <pcap.h>               // pcap

#include <mutex>                // std::mutex
#include <thread>               // std::thread
#include <condition_variable>   // std::condition_variable
#include <chrono>               // std::chrono, std::chrono_literals

#include <csignal>              // signal

#include "mac.hpp"
#include "ip.hpp"
#include "ethhdr.hpp"
#include "arphdr.hpp"
#include "ipv4hdr.hpp"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct attackInfo final {
    Mac sendMAC, targetMAC;
    IPv4 sendIP, targetIP;
};

#define CREATE_SOCKET_ERROR_MSG "Error: Error while create socket\n"
#define IOCTL_ERROR_MSG "Error: Error while ioctl\n"
#define SEND_PACKET_ERROR_MSG "Error: Error while send packet\n"
#define CLOSE_ERROR_MSG "Error: Error while close file descriptor\n"
#define GET_MAC_ERROR_MSG "Error: Error while get local MAC address\n"
#define SLEEP_ERROR_MSG "Error: Error while sleep\n"

#define PCAP_RECEIVE_PACKET_ERROR "Error : Error while pcap_next_ex: "

using namespace std::chrono_literals;

extern volatile bool isEnd;
extern std::mutex mPcap, mRequest, mNonPeriod;
extern std::condition_variable cvRequest, cvPeriod;

bool getMyInfo(const std::string& interface, Mac& MAC, IPv4& IP);
bool resolveMACByIP(pcap_t* pcap, Mac& MAC, const IPv4& IP, const Mac& myMAC, const IPv4& myIP);
bool sendPacket(pcap_t* pcap, const EthArpPacket& packet);
bool sendPacket(pcap_t* pcap, const uint8_t* packet, const int packetLength);

bool sendARPRequest(pcap_t* pcap, const Mac& myMAC, const IPv4& myIP, const IPv4& IP);

void ARPPacketInit(EthArpPacket& packet);
void ARPPacketSetting(EthArpPacket& packet, 
                      const Mac& destMAC, const Mac& sourceMAC,     // for Ethernet
                      const Mac& sendMAC, const IPv4& sendIP,       // for ARP
                      const Mac& targetMAC, const IPv4& targetIP);

bool periodAttack(pcap_t* pcap, const Mac& myMAC, const std::vector<attackInfo>& victims);
bool managePackets(pcap_t* pcap, const Mac& myMAC, const std::vector<attackInfo>& victims);

void printInfo(const Mac& myMAC, const IPv4& myIP, 
               const Mac& sendMAC, const IPv4& sendIP, 
               const Mac& targetMAC, const IPv4& targetIP);