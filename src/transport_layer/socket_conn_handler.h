/**
 * @file tc_container.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-30
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_TRANSPORT_LAYER_SOCKET_CONN_HANDLER_H_
#define SRC_TRANSPORT_LAYER_SOCKET_CONN_HANDLER_H_

#include <functional>
#include <unordered_map>
#include <vector>
#include "transport_layer/tcp_connection.h"
#include "transport_layer/udp_connection.h"
#include "transport_layer/connection.h"
#include "transport_layer/tcp_packet.h"
#include "transport_layer/udp_packet.h"
#include "network_layer/ipv4_packet.h"

namespace net_io_top {

/**
 * @brief 设置哈希表的哈希函数
 * 
 */
class ConnHashFunc {
public:
    uint32_t operator()(const SocketPair& sp) const {
        return sp.hash();
    }
};

/**
 * @brief socket 连接的处理
 * 
 */
class SocketConnHandler {
public:
    SocketConnHandler();
    ~SocketConnHandler();
    SocketConnHandler(const SocketConnHandler&) = delete;
    SocketConnHandler& operator=(const SocketConnHandler&) = delete;
    SocketConnHandler(SocketConnHandler&&) = delete;
    SocketConnHandler& operator=(SocketConnHandler&&) = delete;

public:
    /**
     * @brief 处理数据包，提取连接信息
     * 
     * @param t_cap 
     * @return int 
     */
    // int process_packet(const TcpCapture& t_cap);
    int process_packet(const IPv4Packet& ip_packet);

    /**
     * @brief 获取已经排序的的 socket 连接信息
     * 
     * @return std::vector<Connection*> 
     */
    std::vector<Connection*> get_sorted_conns();

private:
    int process_tcp_packet(const TcpPacket& tcp_packet);
    int process_udp_packet(const UdpPacket& udp_packet);


private:
    /**
     * @brief 移除过期的 socket 连接
     * 
     */
    void remove_overdue_conn();

private:
    // socket 连接的哈希表
    // std::unordered_map<SocketPair, TcpConnection*, ConnHashFunc> conn_hash_;
    std::unordered_map<SocketPair, Connection*, ConnHashFunc> conn_hash_;
    // 用于哈希表的安全竞争
    pthread_mutex_t conn_hash_lock_;
};

}  // namespace net_io_top

#endif  // SRC_TRANSPORT_LAYER_SOCKET_CONN_HANDLER_H_
