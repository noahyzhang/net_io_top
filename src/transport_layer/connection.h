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
    virtual TransportLayerProtocol get_protocol() const = 0;
    virtual const IPAddress& get_src_addr() const = 0;
    virtual const IPAddress& get_dst_addr() const = 0;
    virtual uint16_t get_src_port() const = 0;
    virtual uint16_t get_dst_port() const = 0;

    virtual uint64_t get_forward_packet_count() const = 0;
    virtual uint64_t get_forward_packet_bytes() const = 0;
    virtual uint64_t get_backward_packet_count() const = 0;
    virtual uint64_t get_backward_packet_bytes() const = 0;

    virtual uint64_t get_cur_period_forward_packet_count() const = 0;
    virtual uint64_t get_cur_period_forward_packet_bytes() const = 0;
    virtual uint64_t get_cur_period_backward_packet_count() const = 0;
    virtual uint64_t get_cur_period_backward_packet_bytes() const = 0;

    virtual uint64_t exchange_cur_period_forward_packet_count(uint64_t val) = 0;
    virtual uint64_t exchange_cur_period_forward_packet_bytes(uint64_t val) = 0;
    virtual uint64_t exchange_cur_period_backward_packet_count(uint64_t val) = 0;
    virtual uint64_t exchange_cur_period_backward_packet_bytes(uint64_t val) = 0;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_CONNECTION_H_
