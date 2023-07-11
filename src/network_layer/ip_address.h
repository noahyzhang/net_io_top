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

#ifndef SRC_NETWORK_LAYER_IP_ADDRESS_H_
#define SRC_NETWORK_LAYER_IP_ADDRESS_H_

#include <stdint.h>

namespace net_io_top {

/**
 * @brief IP 地址类
 * 作为基类，可以由 IPv4、IPv6 等类继承
 */
class IPAddress {
public:
    IPAddress() = default;
    virtual ~IPAddress() = default;
    IPAddress(const IPAddress&) = default;
    IPAddress& operator=(const IPAddress&) = default;
    IPAddress(IPAddress&&) = default;
    IPAddress& operator=(IPAddress&&) = default;

public:
    virtual int get_type() const = 0;
    virtual bool operator==(const IPAddress&) const = 0;
    virtual bool operator!=(const IPAddress& addr) const { return !operator==(addr); }
    virtual char* ptr() const = 0;
    virtual uint32_t hash() const = 0;
    virtual IPAddress* clone() const = 0;
};

}  // namespace net_io_top

#endif  // SRC_NETWORK_LAYER_IP_ADDRESS_H_
