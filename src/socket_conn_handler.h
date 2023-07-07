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

#ifndef SRC_SOCKET_CONN_HANDLER_H_
#define SRC_SOCKET_CONN_HANDLER_H_

#include <functional>
#include <unordered_map>
#include <vector>
#include "tcp_connection.h"
#include "tcp_capture.h"

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
    int process_packet(const TcpCapture& t_cap);

    /**
     * @brief 获取已经排序的的 socket 连接信息
     * 
     * @return std::vector<TcpConnection*> 
     */
    std::vector<TcpConnection*> get_sorted_conns();

private:
    /**
     * @brief 移除过期的 socket 连接
     * 
     */
    void remove_overdue_conn();

private:
    // socket 连接的哈希表
    std::unordered_map<SocketPair, TcpConnection*, ConnHashFunc> conn_hash_;
    // 用于哈希表的安全竞争
    pthread_mutex_t conn_hash_lock_;
};

}  // namespace net_io_top

#endif  // SRC_SOCKET_CONN_HANDLER_H_
