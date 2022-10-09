#pragma once

#include <arpa/inet.h>
#include "mac.hpp"

#pragma pack(push, 1)
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	// Type(type_)
	enum Mode : uint16_t {
		Ipv4 = 0x0800,
		Arp = 0x0806,
		Ipv6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)
