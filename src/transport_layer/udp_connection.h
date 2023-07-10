/**
 * @file udp_connection.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_UDP_CONNECTION_H_
#define SRC_TRANSPORT_LAYER_UDP_CONNECTION_H_

#include <stdint.h>
#include "transport_layer/connection.h"

namespace net_io_top {

class UdpConnection : public Connection {
public:

public:
    TransportLayerProtocol get_protocol() override { return TransportLayerProtocol::UDP; }
    uint64_t get_all_packet_count() { return packet_count_; }
    uint64_t get_all_packet_bytes() { return packet_bytes_; }
    uint64_t get_last_period_packet_count() { return last_period_packet_count_; }
    uint64_t get_last_period_packet_bytes() { return last_period_packet_bytes_; }

public:
    int accept_packet()

private:
    uint64_t packet_count_;
    uint64_t packet_bytes_;

    uint64_t last_period_packet_count_;
    uint64_t last_period_packet_bytes_;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_UDP_CONNECTION_H_
