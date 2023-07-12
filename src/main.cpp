#include <iostream>
#include "transport_layer/socket_conn_handler.h"
#include "dispatch/packet_buffer.h"
#include "dispatch/sniffer.h"
#include "common/config.h"
#include "common/common.h"


using net_io_top::SocketConnHandler;
using net_io_top::PacketBuffer;
using net_io_top::Sniffer;
using net_io_top::Config;
using net_io_top::TransportLayerProtocol;

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

    for (;;) {
        auto sorted_conns = conn_handler->get_sorted_conns();
        for (const auto& conn : sorted_conns) {
            std::string protocol = (conn->get_protocol() == TransportLayerProtocol::TRANSPORT_LAYER_PROTOCOL_TCP)
                 ? "TCP" : "UDP";
            if (conn->get_forward_packet_count() > 0) {
                std::cout << protocol << " conn: " << conn->get_src_addr().ptr() << ":" << conn->get_src_port() << ", "
                    << conn->get_dst_addr().ptr() << ":" << conn->get_dst_port()
                    << ", packet count: " << conn->get_forward_packet_count()
                    << ", packet bytes: " << conn->get_forward_packet_bytes()
                    << std::endl;
            }
            if (conn->get_backward_packet_count() > 0) {
                std::cout << protocol << " conn: " << conn->get_dst_addr().ptr() << ":" << conn->get_dst_port() << ", "
                    << conn->get_src_addr().ptr() << ":" << conn->get_src_port()
                    << ", packet count: " << conn->get_backward_packet_count()
                    << ", packet bytes: " << conn->get_backward_packet_bytes()
                    << std::endl;
            }
        }
        std::cout << std::endl << std::endl;
        sleep(1);
    }
    return 0;
}
