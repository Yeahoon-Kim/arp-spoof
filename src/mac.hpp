#pragma once

#include <iostream>
#include <iomanip>	// std::setw, std::setfill
#include <sstream>
#include <cstdint>
#include <cstring>	// memcpy, memcmp
#include <string>

// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
class Mac final {
public:
	static constexpr int SIZE = 6;

	// constructor
	Mac() = default;
	Mac(const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); }
	Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
	Mac(const std::string& r);

	// assign operator
	Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); return *this; }

	// casting operator
	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; }
	bool operator <  (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) <  0; }
	bool operator >  (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) >  0; }
	bool operator <= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) <= 0; }
	bool operator >= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) >= 0; }
	bool operator == (const uint8_t* r) const { return memcmp(mac_, r, SIZE) == 0; }

	void clear() { *this = nullMac(); }

	bool isNull() const { return *this == nullMac(); }

	// FF:FF:FF:FF:FF:FF
	bool isBroadcast() const { return *this == broadcastMac(); }

	bool isMulticast() const { // 01:00:5E:0*
		return mac_[0] == 0x01 and mac_[1] == 0x00 and mac_[2] == 0x5E and (mac_[3] & 0x80) == 0x00;
	}

	static Mac randomMac();
	static Mac& nullMac();
	static Mac& broadcastMac();

protected:
	uint8_t mac_[SIZE];
};

namespace std {
	template<>
	struct hash<Mac> {
		size_t operator() (const Mac& r) const {
			return std::_Hash_impl::hash(&r, Mac::SIZE);
		}
	};
}
