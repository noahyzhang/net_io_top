#include "common/log.h"

namespace net_io_top {

std::ofstream Logger::file_;
LogLevel Logger::log_level_ = LogLevel::DEBUG;

void init_logger(const std::string& filename) {
    Logger::file_.open(filename, std::ofstream::app);
}

void set_log_level(LogLevel log_level) {
    Logger::log_level_ = log_level;
}

std::string get_log_level_str(LogLevel log_level) {
    switch (log_level) {
    case DEBUG:
        return "DEBUG";
    case INFO:
        return "INFO";
    case WARN:
        return "WARN";
    case ERROR:
        return "ERROR";
    }
    return "INVALID_LOG_LEVEL";
}

}  // namespace net_io_top
