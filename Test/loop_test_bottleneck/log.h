// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

#define LOG_LEVEL 1

// 打开日志文件的全局对象
extern std::ofstream logFile;

// 获取当前时间并格式化为字符串

inline std::string getCurrentTimeAsString()
{
    // 获取当前时间点
    auto now = std::chrono::system_clock::now();
    // 转换为时间结构体
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm *now_tm = std::localtime(&now_time);

    // 格式化时间为字符串
    std::ostringstream oss;
    oss << std::put_time(now_tm, "%Y-%m-%d_%H-%M-%S");
    return oss.str();
}

// 初始化日志文件的函数
inline void initLogFile()
{
    // 获取当前时间作为文件名
    std::string fileName = getCurrentTimeAsString() + ".log";
    logFile.open(fileName, std::ios::out | std::ios::app);
    if (!logFile.is_open())
    {
        std::cerr << "[ERROR] Failed to open log file: " << fileName << std::endl;
    }
}

// 关闭日志文件的函数
inline void closeLogFile()
{
    if (logFile.is_open())
    {
        logFile.close();
    }
}

// 定义日志宏
#define LOG_INFO(x)                                     \
    do                                                  \
    {                                                   \
        if ((LOG_LEVEL) <= 3)                           \
        {                                               \
            std::cout << "[INFO] " << x << std::endl;   \
            if (logFile.is_open())                      \
            {                                           \
                logFile << "[INFO] " << x << std::endl; \
            }                                           \
        }                                               \
    } while (0)

#define LOG_DEBUG(x)                                     \
    do                                                   \
    {                                                    \
        if ((LOG_LEVEL) <= 2)                            \
        {                                                \
            std::cout << "[DEBUG] " << x << std::endl;   \
            if (logFile.is_open())                       \
            {                                            \
                logFile << "[DEBUG] " << x << std::endl; \
            }                                            \
        }                                                \
    } while (0)

#define LOG_TRACE(x)                                     \
    do                                                   \
    {                                                    \
        if ((LOG_LEVEL) <= 1)                            \
        {                                                \
            std::cout << "[TRACE] " << x << std::endl;   \
            if (logFile.is_open())                       \
            {                                            \
                logFile << "[TRACE] " << x << std::endl; \
            }                                            \
        }                                                \
    } while (0)

#define LOG_ERROR(x)                                 \
    do                                               \
    {                                                \
        std::cerr << "[ERROR] " << x << std::endl;   \
        if (logFile.is_open())                       \
        {                                            \
            logFile << "[ERROR] " << x << std::endl; \
        }                                            \
    } while (0)

#endif /* LOG_H */