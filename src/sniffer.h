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

class Sniffer {
public:
    Sniffer();
    ~Sniffer();

public:
    int init(const std::string& interface, const std::string& exp);

    void run();
    void process_packet(const pcap_pkthdr* header, const u_char* packet);

private:
    pthread_t sniffer_tid_{0};
    pcap_t* pcap_handler_{nullptr};

    PacketBuffer* pb_{nullptr};
    pthread_mutex_t pb_mutex_;

    bool pcap_initted_{false};
    bool pthread_initted_{false};
    int dlt_{0};
};

void handle_packet(u_char*, const pcap_pkthdr*, const u_char*);

void* sniffer_thread_func(void*);

}  // namespace net_io_top

#endif  // SRC_SNIFFER_H_
