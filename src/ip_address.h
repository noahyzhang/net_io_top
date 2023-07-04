/**
 * @file ip_address.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_IP_ADDRESS_H_
#define SRC_IP_ADDRESS_H_

#include <stdint.h>

namespace net_io_top {

class IPAddress {
public:
    IPAddress() = default;
    virtual ~IPAddress() = default;

public:
    virtual int get_type() const = 0;
    virtual bool operator==(const IPAddress&) const = 0;
    virtual bool operator!=(const IPAddress& addr) const { return !operator==(addr); }
    virtual char* ptr() const = 0;
    virtual uint32_t hash() const = 0;
    virtual IPAddress* clone() const = 0;
};

}  // namespace net_io_top

#endif  // SRC_IP_ADDRESS_H_
