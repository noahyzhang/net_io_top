/**
 * @file config.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-07-04
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_COMMON_CONFIG_H_
#define SRC_COMMON_CONFIG_H_

#include <stdint.h>
#include <string>

namespace net_io_top {

/**
 * @brief 配置类
 * 
 */
class Config {
public:
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    Config(Config&&) = delete;
    Config& operator=(Config&&) = delete;

    static Config& get_instance() {
        static Config instance;
        return instance;
    }

private:
    Config() = default;

public:
    void set_conn_closed_timeout_s(uint64_t time_s) { conn_closed_timeout_s_ = time_s; }
    void set_pcap_interface(const std::string& inter) { pcap_interface_ = inter; }
    void set_pcap_filter_exp(const std::string& filter) { pcap_filter_exp_ = filter; }

    uint64_t get_conn_closed_timeout_s() const { return conn_closed_timeout_s_; }
    const std::string& get_interface() const { return pcap_interface_; }
    const std::string& get_filter_exp() const { return pcap_filter_exp_; }

private:
    // 移除已关闭连接的超时时间（单位为秒）
    uint64_t conn_closed_timeout_s_{10};
    // 网卡
    std::string pcap_interface_{"wlo1"};
    // 过滤表达式
    std::string pcap_filter_exp_;
};

}  // namespace net_io_top

#endif  // SRC_COMMON_CONFIG_H_
