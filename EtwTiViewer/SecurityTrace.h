#pragma once
/*
 * SecurityTrace.h — consume a SecurityTrace-protected AutoLogger session
 * without Antimalware-PPL.
 *
 * HOW IT WORKS
 * ============
 * A session that consumes the Microsoft-Windows-Threat-Intelligence provider
 * is marked "SecurityTrace" by the kernel, so ControlTraceW(QUERY) on it is
 * denied to anything that is not PS_PROTECTED_ANTIMALWARE_LIGHT.
 *
 * An AutoLogger session, however, is started by the kernel at boot with no
 * caller identity, so the provider enablement never hits the PPL check.
 * OpenTraceW()/ProcessTrace() still work — except that sechost internally
 * issues a ControlTraceW(QUERY) on the session, which is denied.
 *
 * We therefore patch sechost!ControlTraceW in *our own process* so that a
 * QUERY for the AutoLogger session is answered from a fabricated
 * EVENT_TRACE_PROPERTIES structure built from the AutoLogger registry key.
 * The fabricated buffer must be byte-compatible with a real query result,
 * including LoggerNameOffset/LogFileNameOffset, otherwise OpenTraceW returns
 * a valid handle that is bound to nothing and ProcessTrace blocks forever.
 *
 * This module is a direct port of the ThreatIntelligenceConsumer POC
 * (Connor McGarr / Origin).  See REPORT.md for the investigation that
 * established these details.
 */

#include <Windows.h>
#include <evntrace.h>
#include <string>
#include <cstdint>

namespace SecurityTrace {

/* Size used by sechost!EtwpQueryRealTimeTraceProperties. */
constexpr ULONG   kTracePropsSize     = 0x1078;

constexpr wchar_t kDefaultSessionName[] = L"0MyThreatIntelTrace";

constexpr wchar_t kAutoLoggerRoot[] =
    L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";

/* Microsoft-Windows-Threat-Intelligence */
extern const GUID kThreatIntelligenceGuid;

struct SessionInfo {
    std::wstring name;
    ULONG        loggerId        = 0;
    ULONGLONG    providerMask    = 0;    /* MatchAnyKeyword from the registry */
    ULONG        logFileMode     = 0;
    ULONG        bufferSize      = 0;    /* kernel buffer size, KiB */
    ULONG        flushTimer      = 0;
    ULONG        clockType       = 0;
    ULONG        maximumBuffers  = 0;
    ULONG        minimumBuffers  = 0;
    GUID         sessionGuid     = {};
    bool         providerEnabled = false;
    bool         realTime        = false;
    bool         protectedSession = false;
};

/*
 * Reads HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<name>, validates
 * that the Threat-Intelligence provider is enabled, builds the fabricated
 * EVENT_TRACE_PROPERTIES buffer and resolves the logger ID.
 *
 * Must be called BEFORE InstallHook(): the logger-ID heuristic needs an
 * unpatched ControlTraceW.
 *
 * Results are cached; calling Prepare() again with the same name is cheap and
 * does not re-run the heuristic while the detour is installed.
 */
bool Prepare(const std::wstring& sessionName, SessionInfo& info, std::string& error);

/*
 * Installs the sechost!ControlTraceW detour (idempotent).  Only QUERY calls
 * that refer to our session are answered from the fabricated properties; every
 * other call is forwarded to the original function via the trampoline.
 */
bool InstallHook(std::string& error);

bool HookInstalled();

/* Remove the detour and release all resources.  Safe to call repeatedly. */
void Cleanup();

} // namespace SecurityTrace
