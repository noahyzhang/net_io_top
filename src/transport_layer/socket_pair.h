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

#include "network_layer/ip_address.h"

namespace net_io_top {

/**
 * @brief 发送端和接收端的套接字(五元组)
 * 
 */
class SocketPair {
public:
    SocketPair(
        TransportLayerProtocol protocol,
        const IPAddress& addrA, uint16_t portA,
        const IPAddress& addrB, uint16_t portB)
        : protocol_(protocol), portA_(portA), portB_(portB) {
        p_ip_addrA_ = addrA.clone();
        p_ip_addrB_ = addrB.clone();
    }

    SocketPair(const SocketPair& other)
        : protocol_(other.protocol_), portA_(other.portA_), portB_(other.portB_) {
        p_ip_addrA_ = other.p_ip_addrA_->clone();
        p_ip_addrB_ = other.p_ip_addrB_->clone();
    }

    SocketPair& operator=(const SocketPair& other) {
        protocol_ = other.protocol_;
        portA_ = other.portA_;
        portB_ = other.portB_;
        p_ip_addrA_ = other.p_ip_addrA_->clone();
        p_ip_addrB_ = other.p_ip_addrB_->clone();
        return *this;
    }

    SocketPair(SocketPair&& other)
        : protocol_(other.protocol_), portA_(other.portA_), portB_(other.portB_) {
        other.portA_ = other.portB_ = 0;
        p_ip_addrA_ = other.p_ip_addrA_;
        p_ip_addrB_ = other.p_ip_addrB_;
        other.p_ip_addrA_ = other.p_ip_addrB_ = nullptr;
    }

    SocketPair& operator=(SocketPair&& other) {
        protocol_ = other.protocol_;
        portA_ = other.portA_;
        portB_ = other.portB_;
        other.portA_ = other.portB_ = 0;
        p_ip_addrA_ = other.p_ip_addrA_;
        p_ip_addrB_ = other.p_ip_addrB_;
        other.p_ip_addrA_ = other.p_ip_addrB_ = nullptr;
        return *this;
    }

    ~SocketPair() {
        portA_ = portB_ = 0;
        delete p_ip_addrA_;
        delete p_ip_addrB_;
    }

public:
    /**
     * @brief 比较函数，用于哈希表
     * 
     * @param other 
     * @return true 
     * @return false 
     */
    bool operator==(const SocketPair& other) const {
        if (protocol_ != other.protocol_) {
            return false;
        }
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
    inline TransportLayerProtocol get_protocol() const { return protocol_; }
    inline const IPAddress& get_addrA() const { return *p_ip_addrA_; }
    inline const IPAddress& get_addrB() const { return *p_ip_addrB_; }
    inline uint16_t get_portA() const { return portA_; }
    inline uint16_t get_portB() const { return portB_; }
    uint32_t hash() const {
        uint32_t hash = 0;
        hash = p_ip_addrA_->hash() % portB_;
        hash += p_ip_addrB_->hash() % portA_;
        return hash;
    }

private:
    TransportLayerProtocol protocol_;
    // IP 地址
    IPAddress* p_ip_addrA_{nullptr};
    IPAddress* p_ip_addrB_{nullptr};
    // 端口
    uint16_t portA_{0};
    uint16_t portB_{0};
};

}  // namespace net_io_top

#endif  // SRC_SOCKET_PAIR_H_
