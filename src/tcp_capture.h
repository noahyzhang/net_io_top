/**
 * @file tcp_capture.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TCP_CAPTURE_H_
#define SRC_TCP_CAPTURE_H_

#include "tcp_packet.h"

namespace net_io_top {

class TcpCapture {
public:
    TcpCapture(TcpPacket* tcp_packet, struct timeval ts)
        : packet_(tcp_packet), ts_(ts) {}

    ~TcpCapture() {
        if (packet_ != nullptr) {
            delete packet_;
        }
    }

    TcpCapture(const TcpCapture& other) {
        packet_ = new TcpPacket(*other.packet_);
        ts_ = other.ts_;
    }

public:
    TcpPacket& get_packet() const { return *packet_; }
    struct timeval get_timestamp() const { return ts_; }

private:
    TcpPacket* packet_;
    struct timeval ts_;
};

}  // namespace net_io_top

#endif  // SRC_TCP_CAPTURE_H_
