//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#pragma once

#include "nts.hpp"

#include <memory>
#include <vector>

#include <spdlog/fwd.h>

enum class Severity
{
    DEBUG,
    INFO,
    WARN,
    ERR,
    FATAL
};

class Logger
{
  private:
    spdlog::logger *logger;

  public:
    Logger(const std::string &name, const std::vector<std::shared_ptr<spdlog::sinks::sink>> &sinks);
    virtual ~Logger();

  private:
    void logImpl(Severity severity, const std::string &msg);

  public:
    template <typename... Args>
    inline void debug(const std::string &fmt, Args &&...args)
    {
        log(Severity::DEBUG, fmt.c_str(), args...);
    }

    inline void debug(const std::string &fmt)
    {
        log(Severity::DEBUG, "%s", fmt.c_str());
    }

    template <typename... Args>
    inline void info(const std::string &fmt, Args &&...args)
    {
        log(Severity::INFO, fmt.c_str(), args...);
    }

    inline void info(const std::string &fmt)
    {
        log(Severity::INFO, "%s", fmt.c_str());
    }

    template <typename... Args>
    inline void warn(const std::string &fmt, Args &&...args)
    {
        log(Severity::WARN, fmt.c_str(), args...);
    }

    inline void warn(const std::string &fmt)
    {
        log(Severity::WARN, "%s", fmt.c_str());
    }

    template <typename... Args>
    inline void err(const std::string &fmt, Args &&...args)
    {
        log(Severity::ERR, fmt.c_str(), args...);
    }

    inline void err(const std::string &fmt)
    {
        log(Severity::ERR, "%s", fmt.c_str());
    }

    template <typename... Args>
    inline void fatal(const std::string &fmt, Args &&...args)
    {
        log(Severity::FATAL, fmt.c_str(), args...);
    }

    inline void fatal(const std::string &fmt)
    {
        log(Severity::FATAL, "%s", fmt.c_str());
    }

    template <typename... Args>
    inline void log(Severity severity, const char * fmt, Args &&...args)
    {
        int size = snprintf(nullptr, 0, fmt, args...);
        std::string res;
        res.resize(size);
        snprintf(&res[0], size + 1, fmt, args...);
        logImpl(severity, res);
    }

    void flush();

    /* Specific logs */
    void unhandledNts(const NtsMessage& msg);
};

class LogBase
{
  private:
    // std::shared_ptr<spdlog::sinks::sink> fileSink;
    std::shared_ptr<spdlog::sinks::sink> consoleSink;

  public:
    explicit LogBase(const std::string &filename);
    virtual ~LogBase();

    Logger *makeLogger(const std::string &loggerName, bool useConsole = true);
    std::unique_ptr<Logger> makeUniqueLogger(const std::string &loggerName, bool useConsole = true);
    std::shared_ptr<Logger> makeSharedLogger(const std::string &loggerName, bool useConsole = true);
};
