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

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdint.h>
#include <string>

namespace net_io_top {

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
    uint64_t get_conn_closed_timeout_s() const { return conn_closed_timeout_s_; }
    const std::string& get_interface() const { return interface_; }
    const std::string& get_filter_exp() const { return filter_exp_; }

private:
    // 移除已关闭连接的超时时间（单位为秒）
    uint64_t conn_closed_timeout_s_{10};
    // 网卡
    std::string interface_{"wlo1"};
    // 过滤表达式
    std::string filter_exp_;
};

}  // namespace net_io_top

#endif  // SRC_CONFIG_H_
