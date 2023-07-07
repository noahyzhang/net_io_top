#include <iostream>
#include "socket_conn_handler.h"
#include "packet_buffer.h"
#include "sniffer.h"
#include "config.h"


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

    for (;;) {}

    // for (;;) {
    //     auto sorted_conns = conn_handler->get_sorted_conns();
    //     for (const auto& conn : sorted_conns) {
    //         std::cout << "conn: " << conn->get_src_addr().ptr() << ":" << conn->get_src_port() << ", "
    //             << conn->get_dst_addr().ptr() << ":" << conn->get_dst_port() << std::endl;
    //     }
    // }
    return 0;
}
