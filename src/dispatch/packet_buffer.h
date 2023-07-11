/**
 * @file packet_buffer.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_DISPATCH_PACKET_BUFFER_H_
#define SRC_DISPATCH_PACKET_BUFFER_H_

#include <pthread.h>
#include <queue>
#include "transport_layer/socket_conn_handler.h"

namespace net_io_top {

/**
 * @brief 数据包的缓冲区
 * 
 */
class PacketBuffer {
public:
    PacketBuffer();
    ~PacketBuffer();
    PacketBuffer(const PacketBuffer&) = delete;
    PacketBuffer& operator=(const PacketBuffer&) = delete;
    PacketBuffer(PacketBuffer&&) = delete;
    PacketBuffer& operator=(PacketBuffer&&) = delete;

public:
    /**
     * @brief 初始化
     * 
     * @param conn_handler 
     * @return int 
     */
    int init(SocketConnHandler* conn_handler);

    /**
     * @brief 添加数据包到缓冲区
     * 
     */
    void push_packet(struct IpPacketWrap*);

    /**
     * @brief 处理数据包
     * 
     */
    void maint_thread_run();

private:
    int check_ip_packet(struct IpPacketWrap*);

public:
    /**
     * @brief 线程的回调函数
     * 
     * @return void* 
     */
    static void* pb_maint_thread_func(void*);

private:
    // 内部线程
    pthread_t maint_thread_tid_{0};
    // 线程是否初始化
    bool pthread_initted_{false};
    // 使用两个队列作为缓冲区，避免读写竞争
    // 一个专门写入的队列，一个专门读取的队列
    // 同时使用锁和条件变量来做同步
    uint64_t packet_count_{0};
    pthread_mutex_t inq_lock_;
    pthread_cond_t inq_flag_;
    std::queue<struct IpPacketWrap*> queue1_;
    std::queue<struct IpPacketWrap*> queue2_;
    std::queue<struct IpPacketWrap*>* in_queue_{nullptr};
    std::queue<struct IpPacketWrap*>* out_queue_{nullptr};
    // 处理数据包的对象
    SocketConnHandler* conn_handler_{nullptr};
};

}  // namespace net_io_top

#endif  // SRC_DISPATCH_PACKET_BUFFER_H_
