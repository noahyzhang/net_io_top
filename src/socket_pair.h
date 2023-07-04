/**
 * @file socket_pair.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_SOCKET_PAIR_H_
#define SRC_SOCKET_PAIR_H_

#include "ip_address.h"

namespace net_io_top {

class SocketPair {
public:
    SocketPair(const IPAddress& addrA, uint16_t portA, const IPAddress& addrB, uint16_t portB)
        : portA_(portA), portB_(portB) {
        p_ip_addrA_ = addrA.clone();
        p_ip_addrB_ = addrB.clone();
    }
    SocketPair(const SocketPair& other)
        : portA_(other.portA_), portB_(other.portB_) {
        p_ip_addrA_ = other.p_ip_addrA_->clone();
        p_ip_addrB_ = other.p_ip_addrB_->clone();
    }

    ~SocketPair() {
        delete p_ip_addrA_;
        delete p_ip_addrB_;
    }

public:
    bool operator==(const SocketPair& other) const {
        if ((*(other.p_ip_addrA_) == *(p_ip_addrA_))
            && (*(other.p_ip_addrB_) == *(p_ip_addrB_))
            && (other.portA_ == portA_)
            && (other.portB_ == portB_)) {
            return true;
        } else if ((*(other.p_ip_addrA_) == *(p_ip_addrB_))
            && (*(other.p_ip_addrB_) == *(p_ip_addrA_))
            && (other.portA_ == portB_)
            && (other.portB_ == portA_)) {
            return true;
        } else {
            return false;
        }
    }
    bool operator!=(const SocketPair& other) const { !(other == *this); }
    const IPAddress& get_addrA() const { return *p_ip_addrA_; }
    const IPAddress& get_addrB() const { return *p_ip_addrB_; }
    uint16_t get_portA() const { return portA_; }
    uint16_t get_portB() const { return portB_; }
    uint32_t hash() const {
        uint32_t hash = 0;
        hash = p_ip_addrA_->hash() % portB_;
        hash += p_ip_addrB_->hash() % portA_;
        return hash;
    }

private:
    IPAddress* p_ip_addrA_;
    IPAddress* p_ip_addrB_;
    uint16_t portA_;
    uint16_t portB_;
};


}  // namespace net_io_top

#endif  // SRC_SOCKET_PAIR_H_
