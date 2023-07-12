/**
 * @file log.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2023-06-29
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#ifndef SRC_COMMON_LOG_H_
#define SRC_COMMON_LOG_H_

#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <utility>

namespace net_io_top {

enum LogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
};

void init_logger(const std::string& filename);
void set_log_level(LogLevel log_level);
std::string get_log_level_str(LogLevel log_level);

class Logger {
public:
    Logger() = default;
    ~Logger() {
        get_stream() << std::endl << std::flush;
    }
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

public:
    static std::ostream& start(
        LogLevel log_level, const std::string& filename,
        const std::string& func, const int line) {
        time_t tm;
        time(&tm);
        char time_str[128];
        strftime(time_str, sizeof(time_str), "[%Y-%m-%d %X]", localtime(&tm));
        return get_stream() << time_str << " [" << get_log_level_str(log_level) << "] "
            << filename << " " << func << ":" << line << " ";
    }

    static std::ostream& get_stream() {
        return file_.is_open() ? file_ : std::cout;
    }

private:
    friend void init_logger(const std::string& filename);
    friend void set_log_level(LogLevel log_level);

private:
    static LogLevel log_level_;
    static std::ofstream file_;
};

#define LOG(log_level) Logger().start(log_level, __FILE__, __FUNCTION__, __LINE__)

}  // namespace net_io_top

#endif  // SRC_COMMON_LOG_H_
