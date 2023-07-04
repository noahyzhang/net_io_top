/**
 * @file ipv4_address.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_IPV4_ADDRESS_H_
#define SRC_IPV4_ADDRESS_H_

#include <stdint.h>
#include <netinet/in.h>
#include <stdio.h>
#include "ip_address.h"

namespace net_io_top {

class IPv4Address : public IPAddress {
public:
    explicit IPv4Address(struct in_addr addr) : addr_(addr) {}
    IPv4Address(const IPv4Address& addr) { addr_ = addr.addr_; }

public:
    virtual int get_type() const { return 4; }
    virtual bool operator==(const IPAddress& addr) const {
        if (addr.get_type() != get_type()) {
            return false;
        }
        const IPv4Address* ipv4_addr = dynamic_cast<const IPv4Address*>(&addr);
        if (ipv4_addr == nullptr) {
            return false;
        }
        return ipv4_addr->addr_.s_addr == addr_.s_addr;
    }
    virtual char* ptr() const {
        static char ascii[16];
        uint32_t i_addr = ntohl(addr_.s_addr);
        int oc1 = (i_addr & 0xFF000000) / 16777216;
        int oc2 = (i_addr & 0x00FF0000) / 65536;
        int oc3 = (i_addr & 0x0000FF00) / 256;
        int oc4 = (i_addr & 0x000000FF);
        snprintf(ascii, (sizeof(ascii) - 1), "%d.%d.%d.%d", oc1, oc2, oc3, oc4);
        return ascii;
    }

    virtual uint32_t hash() const {
        return addr_.s_addr;
    }

    virtual IPAddress* clone() const {
        return new IPv4Address(addr_);
    }

private:
    struct in_addr addr_;
};

}  // namespace net_io_top

#endif  // SRC_IPV4_ADDRESS_H_
