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
#include "network_layer/ip_address.h"
#include "common/common.h"

namespace net_io_top {

/**
 * 注意，连接类(Connection) 由 TcpConnect、UdpConnect 继承
 * 实现多态，支持多种不同的协议
 * 但当前的代码我们会发现 TcpConnect、UdpConnect 的实现重复性很强
 * 解释下原因：我们后面要对连接失效，待删除的情况进行区分，而不同协议的场景不同
 * 因此当前从架构上来说，是可以理解的，此时 架构可扩展性+代码优雅性 > 性能
 */

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

    virtual uint64_t get_all_packet_count() const = 0;
    virtual uint64_t get_all_packet_bytes() const = 0;

    virtual uint64_t get_forward_packet_count() const = 0;
    virtual uint64_t get_forward_packet_bytes() const = 0;
    virtual uint64_t get_backward_packet_count() const = 0;
    virtual uint64_t get_backward_packet_bytes() const = 0;

    virtual time_t get_idle_time_s() const = 0;

    virtual void re_calc_period_value() = 0;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_CONNECTION_H_
