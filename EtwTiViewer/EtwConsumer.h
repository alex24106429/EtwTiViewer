#pragma once
/*
 * EtwConsumer.h — Real-time consumer for the Microsoft-Windows-Threat-Intelligence
 * provider ({F4E1897C-BB5D-5668-F1D8-040F4D8DD344}) via a SecurityTrace AutoLogger.
 *
 * The upstream viewer created its own trace session with StartTraceW() and then
 * called EnableTraceEx2(), which the kernel denies unless the calling process is
 * PS_PROTECTED_ANTIMALWARE_LIGHT (0x31).  That is why the original tool needed a
 * kernel debugger to patch EPROCESS->Protection.
 *
 * This version instead attaches to a *pre-existing* AutoLogger session that the
 * kernel created at boot (see SecurityTrace.h).  The provider enablement happened
 * in kernel context, so no PPL is required; the only obstacle is the internal
 * ControlTraceW(QUERY) performed by sechost, which SecurityTrace detours in user
 * mode.  No driver and no kernel patch are involved.
 *
 * USAGE
 * =====
 *   EtwConsumer c;
 *   std::string err = c.Start(keywordMask, &evBuf);
 *   if (!err.empty()) { /* display error * / }
 *   // ... later ...
 *   c.Stop();
 */

#include <Windows.h>
#include <evntrace.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>

#include "EventBuffer.h"
#include "SecurityTrace.h"

class EtwConsumer {
public:
    EtwConsumer()  = default;
    ~EtwConsumer() { Stop(); }

    /*
     * Start — attach to the AutoLogger session, install the ControlTraceW
     * detour (once per process), open a trace handle and spawn a background
     * thread running ProcessTrace().
     *
     * keywordMask is a *client-side* filter: the kernel-side provider mask was
     * fixed when the AutoLogger was created at boot.  Unchecking keywords in
     * the UI therefore hides matching events; changing the registry mask
     * requires a reboot.
     *
     * Returns an empty string on success, or an actionable error message.
     */
    std::string Start(ULONGLONG keywordMask, std::function<void(TiEvent&&)> onEvent);

    /*
     * Stop — closes the trace handle (which unblocks ProcessTrace) and joins
     * the background thread.  The AutoLogger session is deliberately left
     * running so the viewer can re-attach without a reboot.
     */
    void Stop();

    bool IsRunning() const { return m_running.load(std::memory_order_relaxed); }

    const std::string& LastError() const { return m_lastError; }

    const SecurityTrace::SessionInfo& Session() const { return m_sessionInfo; }
    uint64_t EventCount() const { return m_eventCount.load(std::memory_order_relaxed); }

    static const wchar_t kDefaultSessionName[];

private:
    static void WINAPI StaticCallback(PEVENT_RECORD er);
    void OnEvent(PEVENT_RECORD er);
    static EtwConsumer* s_instance;

    TRACEHANDLE                    m_trace = INVALID_PROCESSTRACE_HANDLE;
    EVENT_TRACE_LOGFILEW           m_logFile = {};
    std::thread                    m_thread;
    std::atomic<bool>              m_running{false};
    std::atomic<uint64_t>          m_eventCount{0};
    std::function<void(TiEvent&&)> m_onEvent;
    std::string                    m_lastError;
    SecurityTrace::SessionInfo     m_sessionInfo;
    ULONGLONG                      m_keywordMask = 0;
};
