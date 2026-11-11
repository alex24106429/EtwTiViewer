/*
 * Headless.cpp — automation-friendly capture using EtwConsumer.
 */

#include "Headless.h"
#include "EtwConsumer.h"
#include "EventBuffer.h"
#include "SecurityTrace.h"

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

namespace {

std::string Narrow(const std::wstring& in)
{
    if (in.empty())
        return {};

    int needed = WideCharToMultiByte(CP_UTF8, 0, in.c_str(),
                                     static_cast<int>(in.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};

    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, in.c_str(),
                        static_cast<int>(in.size()),
                        out.data(), needed, nullptr, nullptr);
    return out;
}

std::string JsonEscape(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
            {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04X",
                         static_cast<unsigned char>(c));
                out += buf;
            }
            else
            {
                out += c;
            }
        }
    }
    return out;
}

std::string FormatTimestamp(const FILETIME& ft)
{
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&ft, &st);
    char buf[24];
    snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

void WriteEventLine(std::ofstream& log, const TiEvent& ev)
{
    if (!log.is_open())
        return;

    log << "{\"ts\":\"" << FormatTimestamp(ev.timestamp) << "\""
        << ",\"id\":" << ev.eventId
        << ",\"name\":\"" << JsonEscape(ev.name) << "\""
        << ",\"pid\":" << ev.pid
        << ",\"tid\":" << ev.tid
        << ",\"keyword\":\"0x" << std::hex << ev.keyword << std::dec << "\""
        << ",\"fields\":{";

    for (size_t i = 0; i < ev.fields.size(); ++i)
    {
        if (i > 0)
            log << ",";
        log << "\"" << JsonEscape(ev.fields[i].first) << "\":\""
            << JsonEscape(ev.fields[i].second) << "\"";
    }

    log << "}}\n";
}

} // namespace

int RunHeadless(const HeadlessOptions& options)
{
    if (!options.sessionName.empty())
    {
        SetEnvironmentVariableW(L"ETWTI_TRACE_NAME",
                                options.sessionName.c_str());
    }

    std::ofstream log;
    if (!options.logPath.empty())
    {
        log.open(options.logPath, std::ios::out | std::ios::trunc);
        if (!log.is_open())
        {
            fwprintf(stderr, L"[headless] cannot open log file: %ls\n",
                     options.logPath.c_str());
            return 3;
        }
    }

    EtwConsumer consumer;

    std::atomic<uint64_t> events{0};
    std::atomic<bool>     stopRequested{false};

    uint64_t total     = 0;
    int      cyclesRun = 0;

    for (int cycle = 0; cycle < options.cycles; ++cycle)
    {
        stopRequested.store(false, std::memory_order_relaxed);

        std::string error = consumer.Start(
            options.keywordMask,
            [&](TiEvent&& ev)
            {
                const uint64_t n =
                    events.fetch_add(1, std::memory_order_relaxed) + 1;

                WriteEventLine(log, ev);

                if (log.is_open() && (n % 500) == 0)
                    log.flush();

                if (n <= 10)
                {
                    fwprintf(stderr,
                             L"[headless] event %llu: %hs pid=%lu tid=%lu\n",
                             static_cast<unsigned long long>(n),
                             ev.name.c_str(),
                             static_cast<unsigned long>(ev.pid),
                             static_cast<unsigned long>(ev.tid));
                }

                if (options.maxEvents != 0 && n >= options.maxEvents)
                    stopRequested.store(true, std::memory_order_relaxed);
            });

        const SecurityTrace::SessionInfo& session = consumer.Session();

        if (!error.empty())
        {
            fwprintf(stderr, L"[headless] attach failed:\n%hs\n", error.c_str());

            if (log.is_open())
            {
                log << "{\"attach\":false,\"error\":\"" << JsonEscape(error)
                    << "\"}\n";
                log.close();
            }
            SecurityTrace::Cleanup();
            return 2;
        }

        fwprintf(stderr,
                 L"[headless] attached: session=%ls loggerId=%lu "
                 L"providerMask=0x%016llX protected=%ls\n",
                 session.name.c_str(),
                 static_cast<unsigned long>(session.loggerId),
                 static_cast<unsigned long long>(session.providerMask),
                 session.protectedSession ? L"yes" : L"no");

        if (log.is_open())
        {
            std::ostringstream attach;
            attach << "{\"attach\":true,\"session\":\""
                   << JsonEscape(Narrow(session.name))
                   << "\",\"loggerId\":" << session.loggerId
                   << ",\"providerMask\":\"0x" << std::hex << session.providerMask
                   << std::dec << "\",\"protected\":"
                   << (session.protectedSession ? "true" : "false") << "}\n";
            log << attach.str();
            log.flush();
        }

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(options.seconds);

        while (!stopRequested.load(std::memory_order_relaxed) &&
               std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        consumer.Stop();

        total     = events.load(std::memory_order_relaxed);
        cyclesRun = cycle + 1;

        if (stopRequested.load(std::memory_order_relaxed))
            break;
    }

    if (log.is_open())
    {
        std::ostringstream summary;
        summary << "{\"summary\":true,\"events\":" << total
                << ",\"cycles\":" << cyclesRun
                << ",\"durationSec\":" << options.seconds
                << ",\"keywordMask\":\"0x" << std::hex << options.keywordMask
                << std::dec << "\"}\n";
        log << summary.str();
        log.flush();
        log.close();
    }

    fwprintf(stderr, L"[headless] done: events=%llu\n",
             static_cast<unsigned long long>(total));

    SecurityTrace::Cleanup();
    return 0;
}
