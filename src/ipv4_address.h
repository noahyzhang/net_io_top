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

/**
 * @brief IPv4 地址
 * 继承自 IPAddress 类
 */
class IPv4Address : public IPAddress {
public:
    explicit IPv4Address(struct in_addr addr) : addr_(addr) {}
    IPv4Address(const IPv4Address& addr) = default;
    IPv4Address& operator=(const IPv4Address& addr) = default;
    IPv4Address(IPv4Address&& addr) = default;
    IPv4Address& operator=(IPv4Address&& addr) = default;

public:
    /**
     * @brief 获取 IP 协议的类型
     * 
     * @return int 
     */
    int get_type() const override {
        return 4;
    }

    /**
     * @brief 判断相等
     * 
     * @param addr 
     * @return true 
     * @return false 
     */
    bool operator==(const IPAddress& addr) const override {
        if (addr.get_type() != get_type()) {
            return false;
        }
        const IPv4Address* ipv4_addr = dynamic_cast<const IPv4Address*>(&addr);
        if (ipv4_addr == nullptr) {
            return false;
        }
        return ipv4_addr->addr_.s_addr == addr_.s_addr;
    }

    /**
     * @brief 返回可视化的 IP 地址
     * 
     * @return char* 
     */
    char* ptr() const override {
        static char ascii[16];
        uint32_t i_addr = ntohl(addr_.s_addr);
        int oc1 = (i_addr & 0xFF000000) / 16777216;
        int oc2 = (i_addr & 0x00FF0000) / 65536;
        int oc3 = (i_addr & 0x0000FF00) / 256;
        int oc4 = (i_addr & 0x000000FF);
        snprintf(ascii, (sizeof(ascii) - 1), "%d.%d.%d.%d", oc1, oc2, oc3, oc4);
        return ascii;
    }

    /**
     * @brief 获取 hash 值
     * 
     * @return uint32_t 
     */
    uint32_t hash() const override {
        return addr_.s_addr;
    }

    /**
     * @brief 拷贝
     * 
     * @return IPAddress* 
     */
    IPAddress* clone() const override {
        return new IPv4Address(addr_);
    }

private:
    // IP 地址
    struct in_addr addr_;
};

}  // namespace net_io_top

#endif  // SRC_IPV4_ADDRESS_H_
