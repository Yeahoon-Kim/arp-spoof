# arp-spoof
## Objective
## Component
## Requirements
* Get MAC address from both sender and target using ARP request
* Infect ARP table of both sender and target
    * Periodically : Send fake ARP reply packet periodically
    * Nonperiodically : Send fake ARP reply when receive ARP request
        * When sender sends broadcast Request ARP packet
        * When target sends broadcast Request ARP packet
        * When sender sends unique Request ARP packet(No problem)
        * When target sends unique Request ARP packet(Need to infect both!)
* Send ARP recover packets when program exits
    * When user use signal(SIGINT and SIGTERM)
* Use thread and mutex for attacking each pairs of sender and target
* Do not attack CAM table of L2 switch
* Divide jumbo packet by unit of 1500 bytes and send to relay packet
