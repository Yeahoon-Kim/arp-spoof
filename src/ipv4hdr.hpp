#pragma once

#include <cstdint>
#include "ip.hpp"

struct IPv4Hdr final {
uint8_t ip_hl:4,            /* header length */
            ip_v:4;         /* version */
    u_int8_t ip_tos;        /* type of service */

    u_int16_t ip_len;       /* total length */
    u_int16_t ip_id;        /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;        /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_int16_t ip_sum;       /* checksum */
    IPv4 ip_src, ip_dst;    /* source and dest address */
};