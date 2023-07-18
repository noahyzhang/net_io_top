#include <iostream>
#include "transport_layer/socket_conn_handler.h"
#include "dispatch/packet_buffer.h"
#include "dispatch/sniffer.h"
#include "common/config.h"
#include "common/common.h"
#include "common/process_socket_info.h"


using net_io_top::SocketConnHandler;
using net_io_top::PacketBuffer;
using net_io_top::Sniffer;
using net_io_top::Config;
using net_io_top::TransportLayerProtocol;
using net_io_top::ProcessSocketInfo;

int main() {
    SocketConnHandler* conn_handler = new SocketConnHandler();
    PacketBuffer* packet_buffer = new PacketBuffer();
    if (packet_buffer->init(conn_handler) < 0) {
        delete conn_handler;
        std::cout << "init packet buffer failed" << std::endl;
        return 0;
    }
    Config::get_instance().set_pcap_interface("wlo1");
    Sniffer* sniffer = new Sniffer();
    sniffer->init(packet_buffer, Config::get_instance().get_interface(), Config::get_instance().get_filter_exp());
    ProcessSocketInfo process_socket_info;

    for (;;) {
        auto sorted_conns = conn_handler->get_sorted_conns();
        process_socket_info.refresh_process_socket_info();
        for (const auto& conn : sorted_conns) {
            int pid = process_socket_info.get_pid_from_socket(conn);
            std::string protocol = (conn.protocol == TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_TCP)
                 ? "TCP" : "UDP";
            if (conn.forward_packet_count > 0) {
                std::cout << "PID: " << pid << " " << protocol
                    << " conn: " << conn.src_addr << ":" << conn.src_port << ", "
                    << conn.dst_addr << ":" << conn.dst_port
                    << ", packet count: " << conn.forward_packet_count
                    << ", packet bytes: " << conn.forward_packet_bytes
                    << std::endl;
            }
            if (conn.backward_packet_count > 0) {
                std::cout << "PID: " << pid << " " << protocol
                    << " conn: " << conn.dst_addr << ":" << conn.dst_port << ", "
                    << conn.src_addr << ":" << conn.src_port
                    << ", packet count: " << conn.backward_packet_count
                    << ", packet bytes: " << conn.backward_packet_bytes
                    << std::endl;
            }
        }
        std::cout << std::endl << std::endl;
        sleep(1);
    }
    return 0;
}
