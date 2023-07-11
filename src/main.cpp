#include <iostream>
#include "transport_layer/socket_conn_handler.h"
#include "dispatch/packet_buffer.h"
#include "dispatch/sniffer.h"
#include "common/config.h"


using net_io_top::SocketConnHandler;
using net_io_top::PacketBuffer;
using net_io_top::Sniffer;
using net_io_top::Config;

int main() {
    SocketConnHandler* conn_handler = new SocketConnHandler();
    PacketBuffer* packet_buffer = new PacketBuffer();
    if (packet_buffer->init(conn_handler) < 0) {
        delete conn_handler;
        std::cout << "init packet buffer failed" << std::endl;
        return 0;
    }
    Sniffer* sniffer = new Sniffer();
    sniffer->init(packet_buffer, Config::get_instance().get_interface(), Config::get_instance().get_filter_exp());

    // for (;;) {}
    // // 上一周期的数据包数量
    // uint64_t last_period_packet_count_{0};
    // // 上一周期的 TCP 报文总字节数(不包括 TCP 头)
    // uint64_t last_period_tcp_payload_bytes_{0};
    // // 上一周期的数据包总字节数(从 IP 头算起)
    // uint64_t last_period_all_bytes_{0};


    for (;;) {
        auto sorted_conns = conn_handler->get_sorted_conns();
        for (const auto& conn : sorted_conns) {
            std::cout << "conn: " << conn->get_src_addr().ptr() << ":" << conn->get_src_port() << ", "
                << conn->get_dst_addr().ptr() << ":" << conn->get_dst_port()
                << ", packet count: " << conn->get_all_packet_count()
                << ", packet bytes: " << conn->get_all_packet_bytes()
                // << ", packet count: " << conn->get_packet_count()
                // << ", all_tcp_payload_bytes: " << conn->get_all_tcp_payload_bytes()
                // << ", period packet count: " << conn->get_last_period_packet_count()
                // << ", period tcp_payload_bytes: " << conn->get_last_period_tcp_payload_bytes()
                // << ", period all_bytes: " << conn->get_last_period_all_bytes()
                << std::endl;
        }
        std::cout << std::endl << std::endl;
        sleep(1);
    }
    return 0;
}
