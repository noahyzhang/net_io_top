/**
 * @file sniffer.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_SNIFFER_H_
#define SRC_SNIFFER_H_

#include <string>
#include "packet_buffer.h"
#include "pcap/pcap.h"

namespace net_io_top {

/**
 * @brief 嗅探器
 * 通过 pcap 库监听某个网卡
 * 并且收集此网卡的数据包
 * 
 */
class Sniffer {
public:
    Sniffer();
    ~Sniffer();
    Sniffer(const Sniffer&) = delete;
    Sniffer& operator=(const Sniffer&) = delete;
    Sniffer(Sniffer&&) = delete;
    Sniffer& operator=(Sniffer&&) = delete;

public:
    /**
     * @brief 初始化
     * 
     * @param interface 
     * @param exp 
     * @return int 
     */
    int init(PacketBuffer* packet_buffer, const std::string& interface, const std::string& exp);

    /**
     * @brief 收集数据包
     * 
     */
    void collect_packet();

private:
    /**
     * @brief 处理数据包
     * 
     * @param header 
     * @param packet 
     */
    void process_packet(const pcap_pkthdr* header, const u_char* packet);

    /**
     * @brief 解析 pcap 包并返回
     *        返回值是从堆上空间，一定要记得 free
     * @param p 
     * @param dlt 
     * @param pcap 
     * @return std::shared_ptr<PacketData> 
     */
    PacketData* get_packet_data(const u_char* p, int dlt, const pcap_pkthdr* pcap);

    /**
     * @brief 检测数据包是否合法
     * 
     * @param packet 
     * @return true 
     * @return false 
     */
    bool check_packet_data(struct PacketData* packet);

private:
    /**
     * @brief 处理数据包（用于 pcap_loop 的回调）
     * 
     */
    static void handle_packet(u_char*, const pcap_pkthdr*, const u_char*);

    /**
     * @brief 线程回调函数
     * 
     * @return void* 
     */
    static void* sniffer_thread_func(void*);

private:
    // 新线程，用于收集网卡数据包
    pthread_t sniffer_tid_{0};
    // pcap 库的描述符
    pcap_t* pcap_handler_{nullptr};
    // 链路层的类型
    int pcap_dlt_{0};
    // 存储数据包的缓冲区
    PacketBuffer* packet_buffer_{nullptr};
    // 同步的处理数据包
    pthread_mutex_t pb_mutex_;
    // pcap 库是否已经初始化
    bool pcap_initted_{false};
    // 线程是否初始化
    bool pthread_initted_{false};
};

}  // namespace net_io_top

#endif  // SRC_SNIFFER_H_
