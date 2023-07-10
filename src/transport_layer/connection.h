/**
 * @file connection.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_CONNECTION_H_
#define SRC_TRANSPORT_LAYER_CONNECTION_H_

#include <stdint.h>

namespace net_io_top {

enum TransportLayerProtocol {
    TRANSPORT_LAYER_PROTOCOL_TCP = 0,
    TRANSPORT_LAYER_PROTOCOL_UDP
};

/**
 * @brief 连接类
 * 作为基类，可以由 TCP、UDP 等类继承
 */
class Connection {
public:
    Connection() = default;
    virtual ~Connection() = default;
    Connection(const Connection&) = default;
    Connection& operator=(const Connection&) = default;
    Connection(Connection&&) = default;
    Connection& operator=(Connection&&) = default;

public:
    virtual TransportLayerProtocol get_protocol() = 0;
    virtual uint64_t get_all_packet_count() = 0;
    virtual uint64_t get_all_packet_bytes() = 0;
    virtual uint64_t get_last_period_packet_count() = 0;
    virtual uint64_t get_last_period_packet_bytes() = 0;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_CONNECTION_H_
