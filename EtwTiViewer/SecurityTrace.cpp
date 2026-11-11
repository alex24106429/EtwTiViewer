/*
 * SecurityTrace.cpp — AutoLogger attach + sechost!ControlTraceW detour.
 *
 * Derived from the ThreatIntelligenceConsumer POC (Connor McGarr / Origin).
 * See REPORT.md for the full investigation of why the fabricated
 * EVENT_TRACE_PROPERTIES must carry LoggerNameOffset/LogFileNameOffset and the
 * session name, and why OpenTraceW otherwise silently attaches to nothing.
 */

#include "SecurityTrace.h"

#include <combaseapi.h>
#include <winternl.h>

#include <cstdio>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Globals shared with the detour
// ---------------------------------------------------------------------------

extern "C" {
    PEVENT_TRACE_PROPERTIES k_TraceProperties = nullptr;
}

using SecurityTrace::SessionInfo;

namespace {

constexpr SIZE_T kHookSize = 14;   // FF 25 00000000 + 8-byte absolute target

using ControlTraceW_t = ULONG (WINAPI*)(
    TRACEHANDLE             TraceHandle,
    LPCWSTR                 InstanceName,
    PEVENT_TRACE_PROPERTIES Properties,
    ULONG                   ControlCode);

ControlTraceW_t g_originalControlTraceW = nullptr;

bool         g_hookInstalled = false;
PVOID        g_trampoline    = nullptr;
BYTE         g_originalBytes[kHookSize] = {};
std::wstring g_hookedSessionName;
ULONG        g_hookedLoggerId = 0;

// Cached Prepare() result.  Cached because once the detour is installed the
// logger-ID heuristic would be answered by the detour itself.
bool        g_prepared = false;
SessionInfo g_info;

// ---------------------------------------------------------------------------
// Small registry helpers
// ---------------------------------------------------------------------------

bool ReadDword(HKEY key, LPCWSTR valueName, DWORD& out)
{
    DWORD size = sizeof(DWORD);
    return RegGetValueW(key, nullptr, valueName, RRF_RT_REG_DWORD,
                        nullptr, &out, &size) == ERROR_SUCCESS;
}

bool ReadString(HKEY key, LPCWSTR valueName, std::wstring& out)
{
    DWORD size = 0;
    if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_SZ,
                     nullptr, nullptr, &size) != ERROR_SUCCESS ||
        size < sizeof(WCHAR))
    {
        return false;
    }

    std::vector<WCHAR> buffer(size / sizeof(WCHAR) + 1, L'\0');
    if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_SZ,
                     nullptr, buffer.data(), &size) != ERROR_SUCCESS)
    {
        return false;
    }

    out.assign(buffer.data());
    return true;
}

bool ReadKeywordMask(HKEY key, LPCWSTR valueName, ULONGLONG& out)
{
    // MatchAnyKeyword is stored as REG_BINARY(8) by the classic AutoLogger
    // tooling, but accept QWORD/DWORD forms too.
    BYTE binary[8] = {};
    DWORD size = sizeof(binary);
    if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_BINARY,
                     nullptr, binary, &size) == ERROR_SUCCESS &&
        size == sizeof(binary))
    {
        ULONGLONG v = 0;
        for (int i = 7; i >= 0; --i)
            v = (v << 8) | binary[i];
        out = v;
        return true;
    }

    ULONGLONG qword = 0;
    size = sizeof(qword);
    if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_QWORD,
                     nullptr, &qword, &size) == ERROR_SUCCESS)
    {
        out = qword;
        return true;
    }

    DWORD dword = 0;
    size = sizeof(dword);
    if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_DWORD,
                     nullptr, &dword, &size) == ERROR_SUCCESS)
    {
        out = dword;
        return true;
    }

    return false;
}

std::string FormatError(const char* what, LSTATUS status)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%s (win32 error %ld)", what, (long)status);
    return buf;
}

// ---------------------------------------------------------------------------
// Logger-ID resolution
// ---------------------------------------------------------------------------

ULONG ResolveLoggerId(const std::wstring& name, DWORD startFlag,
                      bool& isProtected, std::string& error)
{
    isProtected = false;

    // Explicit override for hosts where the heuristic picks the wrong session.
    WCHAR envId[32] = {};
    DWORD envLen = GetEnvironmentVariableW(L"ETWTI_LOGGER_ID", envId, 32);
    if (envLen > 0 && envLen < 32)
    {
        WCHAR* end = nullptr;
        unsigned long forced = wcstoul(envId, &end, 0);
        if (forced >= 2 && forced < 0x1000)
            return static_cast<ULONG>(forced);
    }

    std::vector<BYTE> buffer(SecurityTrace::kTracePropsSize, 0);
    auto* probe = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
    probe->Wnode.BufferSize = SecurityTrace::kTracePropsSize;
    probe->Wnode.Flags      = WNODE_FLAG_TRACED_GUID;

    //
    // If the session is not SecurityTrace-protected we can simply read the
    // kernel-populated HistoricalContext (logger ID) from a normal query.
    //
    ULONG status = ControlTraceW(0, name.c_str(), probe, EVENT_TRACE_CONTROL_QUERY);
    if (status == ERROR_SUCCESS)
    {
        ULONG id = static_cast<ULONG>(probe->Wnode.HistoricalContext);
        if (id >= 2 && id < 0x1000)
            return id;

        error = "ControlTraceW(QUERY) succeeded but returned an invalid logger "
                "ID. Set ETWTI_LOGGER_ID=<n> (see REPORT.md).";
        return 0;
    }
    else if (status != ERROR_ACCESS_DENIED)
    {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "AutoLogger session '%ls' is not running (ControlTraceW query "
                 "returned %lu).%s",
                 name.c_str(), status,
                 startFlag == 1
                     ? " The registry entry exists with Start=1; reboot so the "
                       "kernel starts it at boot."
                     : " The registry entry has Start=0. Run install_autologger.ps1 "
                       "and reboot.");
        error = msg;
        return 0;
    }

    //
    // Access denied => the session is protected.  AutoLogger sessions are
    // created alphabetically, and our default name starts with '0', so the
    // first protected session at ID >= 4 is ours.  This matches the POC.
    //
    isProtected = true;

    for (ULONG id = 4; id < 0x50; ++id)
    {
        ZeroMemory(buffer.data(), buffer.size());
        probe->Wnode.BufferSize = SecurityTrace::kTracePropsSize;
        probe->Wnode.Flags      = WNODE_FLAG_TRACED_GUID;

        ULONG rc = ControlTraceW(static_cast<TRACEHANDLE>(id), nullptr, probe,
                                 EVENT_TRACE_CONTROL_QUERY);
        if (rc == ERROR_ACCESS_DENIED)
            return id;
    }

    error = "The AutoLogger session is protected, but no protected logger ID "
            "could be found. Set ETWTI_LOGGER_ID=<n> (the ID can be read from "
            "a kernel debugger, see REPORT.md).";
    return 0;
}

// ---------------------------------------------------------------------------
// Fabricated EVENT_TRACE_PROPERTIES
// ---------------------------------------------------------------------------

PEVENT_TRACE_PROPERTIES BuildProperties(const std::wstring& name,
                                        const SessionInfo& info,
                                        std::string& error)
{
    const ULONG nameBytes = static_cast<ULONG>((name.size() + 1) * sizeof(WCHAR));
    if (nameBytes > SecurityTrace::kTracePropsSize -
                    sizeof(EVENT_TRACE_PROPERTIES) - sizeof(WCHAR))
    {
        error = "AutoLogger session name is too long.";
        return nullptr;
    }

    auto* props = static_cast<PEVENT_TRACE_PROPERTIES>(
        malloc(SecurityTrace::kTracePropsSize));
    if (!props)
    {
        error = "Out of memory allocating EVENT_TRACE_PROPERTIES.";
        return nullptr;
    }

    ZeroMemory(props, SecurityTrace::kTracePropsSize);

    props->Wnode.BufferSize         = SecurityTrace::kTracePropsSize;
    props->Wnode.Flags              = WNODE_FLAG_TRACED_GUID;
    props->Wnode.HistoricalContext  = info.loggerId;

    //
    // sechost (EtwpCopyPropertiesToInfo) derives the session-name length from
    // (LogFileNameOffset - LoggerNameOffset), so the name must sit directly
    // after the struct and LogFileNameOffset must point past the name.
    // Leaving LogFileNameOffset at zero makes OpenTraceW() succeed against a
    // garbage name and ProcessTrace() then blocks forever.
    //
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset = props->LoggerNameOffset + nameBytes;

    RtlCopyMemory(reinterpret_cast<PUCHAR>(props) + props->LoggerNameOffset,
                  name.c_str(), nameBytes);

    //
    // Registry-backed session settings.  Everything not set here is an
    // output-only field that the kernel fills during a real query.
    //
    props->BufferSize       = info.bufferSize;
    props->Wnode.ClientContext = info.clockType;
    props->FlushTimer       = info.flushTimer;
    props->LogFileMode      = info.logFileMode;
    props->MaximumBuffers   = info.maximumBuffers;
    props->MinimumBuffers   = info.minimumBuffers;
    props->Wnode.Guid       = info.sessionGuid;

    return props;
}

} // namespace

// ---------------------------------------------------------------------------
// Detour
// ---------------------------------------------------------------------------

namespace {

bool IsOurQuery(TRACEHANDLE traceHandle, LPCWSTR instanceName)
{
    if (instanceName != nullptr && instanceName[0] != L'\0' &&
        !g_hookedSessionName.empty())
    {
        return _wcsicmp(instanceName, g_hookedSessionName.c_str()) == 0;
    }

    return g_hookedLoggerId != 0 &&
           static_cast<ULONG>(traceHandle) == g_hookedLoggerId;
}

} // namespace

//
// The detour target.  A normal C++ function is sufficient: the 14-byte patch
// jumps here with the original x64 arguments still in RCX/RDX/R8/R9, and the
// return address is on the stack exactly as for a normal call.
//
extern "C" __declspec(noinline)
ULONG WINAPI MyControlTraceW(TRACEHANDLE             TraceHandle,
                             LPCWSTR                 InstanceName,
                             PEVENT_TRACE_PROPERTIES Properties,
                             ULONG                   ControlCode)
{
    if (ControlCode == EVENT_TRACE_CONTROL_QUERY &&
        k_TraceProperties != nullptr &&
        Properties != nullptr &&
        IsOurQuery(TraceHandle, InstanceName))
    {
        const ULONG callerSize = Properties->Wnode.BufferSize;
        if (callerSize < sizeof(EVENT_TRACE_PROPERTIES))
            return ERROR_INVALID_PARAMETER;

        const ULONG copySize = callerSize < SecurityTrace::kTracePropsSize
                                   ? callerSize
                                   : SecurityTrace::kTracePropsSize;
        RtlCopyMemory(Properties, k_TraceProperties, copySize);
        return ERROR_SUCCESS;
    }

    return g_originalControlTraceW(TraceHandle, InstanceName, Properties,
                                   ControlCode);
}

namespace {

bool CreateTrampoline(ULONG_PTR target)
{
    const SIZE_T trampolineSize = kHookSize * 2;
    g_trampoline = VirtualAlloc(nullptr, trampolineSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!g_trampoline)
        return false;

    auto* code = static_cast<BYTE*>(g_trampoline);

    // Original 14 bytes, then an absolute jump back to target + 14.
    RtlCopyMemory(code, g_originalBytes, kHookSize);
    code[kHookSize + 0] = 0xFF;
    code[kHookSize + 1] = 0x25;
    *reinterpret_cast<ULONG*>(&code[kHookSize + 2]) = 0;
    *reinterpret_cast<ULONG_PTR*>(&code[kHookSize + 6]) = target + kHookSize;

    FlushInstructionCache(GetCurrentProcess(), g_trampoline, trampolineSize);
    return true;
}

bool InstallDetour(std::string& error)
{
    HMODULE sechost = GetModuleHandleW(L"sechost.dll");
    if (!sechost)
        sechost = LoadLibraryW(L"sechost.dll");
    if (!sechost)
    {
        error = FormatError("Unable to load sechost.dll", GetLastError());
        return false;
    }

    ULONG_PTR target = reinterpret_cast<ULONG_PTR>(
        GetProcAddress(sechost, "ControlTraceW"));
    if (target == 0)
    {
        error = FormatError("Unable to resolve sechost!ControlTraceW", GetLastError());
        return false;
    }

    RtlCopyMemory(g_originalBytes, reinterpret_cast<PVOID>(target), kHookSize);

    if (!CreateTrampoline(target))
    {
        error = FormatError("Unable to allocate hook trampoline", GetLastError());
        return false;
    }

    g_originalControlTraceW =
        reinterpret_cast<ControlTraceW_t>(g_trampoline);

    BYTE patch[kHookSize] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *reinterpret_cast<ULONG_PTR*>(&patch[6]) =
        reinterpret_cast<ULONG_PTR>(&MyControlTraceW);

    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<PVOID>(target), kHookSize,
                        PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        error = FormatError("VirtualProtect(ControlTraceW) failed", GetLastError());
        return false;
    }

    RtlCopyMemory(reinterpret_cast<PVOID>(target), patch, kHookSize);

    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<PVOID>(target), kHookSize, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<PVOID>(target),
                          kHookSize);

    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

namespace SecurityTrace {

const GUID kThreatIntelligenceGuid = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

bool Prepare(const std::wstring& sessionName, SessionInfo& info,
             std::string& error)
{
    error.clear();

    if (g_prepared && g_info.name == sessionName)
    {
        info = g_info;
        return true;
    }

    if (sizeof(EVENT_TRACE_PROPERTIES) != 0x78)
    {
        error = "Unexpected sizeof(EVENT_TRACE_PROPERTIES); this build of the "
                "SDK is not compatible with the sechost projection.";
        return false;
    }

    HKEY root = nullptr;
    HKEY key  = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kAutoLoggerRoot, 0,
                                   KEY_READ, &root);
    if (status != ERROR_SUCCESS)
    {
        error = FormatError("Unable to open the AutoLogger registry root "
                            "(run EtwTiViewer as Administrator)", status);
        return false;
    }

    status = RegOpenKeyExW(root, sessionName.c_str(), 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS)
    {
        RegCloseKey(root);

        if (status == ERROR_FILE_NOT_FOUND)
        {
            char msg[640];
            snprintf(msg, sizeof(msg),
                     "AutoLogger session '%ls' is not registered.\n"
                     "Run EtwTiViewer\\install_autologger.ps1 from an elevated "
                     "prompt, then reboot so the kernel starts the session at "
                     "boot.",
                     sessionName.c_str());
            error = msg;
        }
        else
        {
            error = FormatError("Unable to open the AutoLogger session key",
                                status);
        }
        return false;
    }

    SessionInfo parsed;
    parsed.name = sessionName;

    DWORD startFlag = 0;
    DWORD clockType = 0;
    DWORD maximumBuffers = 0;
    DWORD minimumBuffers = 0;
    std::wstring sessionGuidString;

    if (!ReadDword(key, L"Start", startFlag) ||
        !ReadDword(key, L"BufferSize", parsed.bufferSize) ||
        !ReadDword(key, L"ClockType", clockType) ||
        !ReadDword(key, L"FlushTimer", parsed.flushTimer) ||
        !ReadDword(key, L"LogFileMode", parsed.logFileMode) ||
        !ReadDword(key, L"MaximumBuffers", maximumBuffers) ||
        !ReadDword(key, L"MinimumBuffers", minimumBuffers) ||
        !ReadString(key, L"GUID", sessionGuidString))
    {
        RegCloseKey(key);
        RegCloseKey(root);
        error = "The AutoLogger registry key is missing required values "
                "(Start/BufferSize/ClockType/FlushTimer/LogFileMode/"
                "MaximumBuffers/MinimumBuffers/GUID). Re-run "
                "install_autologger.ps1.";
        return false;
    }

    parsed.clockType      = static_cast<ULONG>(clockType);
    parsed.maximumBuffers = static_cast<ULONG>(maximumBuffers);
    parsed.minimumBuffers = static_cast<ULONG>(minimumBuffers);
    parsed.realTime = (parsed.logFileMode & EVENT_TRACE_REAL_TIME_MODE) != 0;

    if (CLSIDFromString(sessionGuidString.c_str(),
                        reinterpret_cast<LPCLSID>(&parsed.sessionGuid)) != S_OK)
    {
        RegCloseKey(key);
        RegCloseKey(root);
        error = "The AutoLogger GUID value is not a valid GUID string.";
        return false;
    }

    //
    // Validate the Threat-Intelligence provider subkey.
    //
    const std::wstring providerKeyName =
        L"{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}";
    HKEY providerKey = nullptr;
    status = RegOpenKeyExW(key, providerKeyName.c_str(), 0, KEY_READ,
                           &providerKey);
    if (status == ERROR_SUCCESS)
    {
        DWORD enabled = 0;
        parsed.providerEnabled = ReadDword(providerKey, L"Enabled", enabled) &&
                                 enabled != 0;

        ULONGLONG mask = 0;
        if (ReadKeywordMask(providerKey, L"MatchAnyKeyword", mask))
            parsed.providerMask = mask;

        RegCloseKey(providerKey);
    }

    RegCloseKey(key);
    RegCloseKey(root);

    if (!parsed.providerEnabled)
    {
        char msg[640];
        snprintf(msg, sizeof(msg),
                 "AutoLogger session '%ls' does not enable "
                 "Microsoft-Windows-Threat-Intelligence (provider subkey "
                 "%ls must exist with Enabled=1). Re-run "
                 "install_autologger.ps1.",
                 sessionName.c_str(), providerKeyName.c_str());
        error = msg;
        return false;
    }

    if (!parsed.realTime)
    {
        error = "The AutoLogger session is not configured for real-time "
                "consumption (LogFileMode must include "
                "EVENT_TRACE_REAL_TIME_MODE = 0x100). Re-run "
                "install_autologger.ps1.";
        return false;
    }

    //
    // Resolve the logger ID before installing the detour.
    //
    bool isProtected = false;
    ULONG loggerId = ResolveLoggerId(sessionName, startFlag, isProtected, error);
    if (loggerId == 0)
        return false;

    parsed.loggerId         = loggerId;
    parsed.protectedSession = isProtected;

    PEVENT_TRACE_PROPERTIES props = BuildProperties(sessionName, parsed, error);
    if (!props)
        return false;

    if (k_TraceProperties != nullptr)
        free(k_TraceProperties);

    k_TraceProperties = props;
    g_hookedSessionName = sessionName;
    g_hookedLoggerId    = loggerId;

    g_info     = parsed;
    g_prepared = true;

    info = parsed;
    return true;
}

bool InstallHook(std::string& error)
{
    error.clear();

    if (g_hookInstalled)
        return true;

    if (!g_prepared)
    {
        error = "SecurityTrace::InstallHook called before Prepare().";
        return false;
    }

    if (!InstallDetour(error))
        return false;

    g_hookInstalled = true;
    return true;
}

bool HookInstalled()
{
    return g_hookInstalled;
}

void Cleanup()
{
    if (g_hookInstalled)
    {
        HMODULE sechost = GetModuleHandleW(L"sechost.dll");
        if (sechost)
        {
            ULONG_PTR target = reinterpret_cast<ULONG_PTR>(
                GetProcAddress(sechost, "ControlTraceW"));
            if (target != 0)
            {
                DWORD oldProtect = 0;
                if (VirtualProtect(reinterpret_cast<PVOID>(target), kHookSize,
                                   PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    RtlCopyMemory(reinterpret_cast<PVOID>(target),
                                  g_originalBytes, kHookSize);
                    DWORD ignored = 0;
                    VirtualProtect(reinterpret_cast<PVOID>(target), kHookSize,
                                   oldProtect, &ignored);
                    FlushInstructionCache(GetCurrentProcess(),
                                          reinterpret_cast<PVOID>(target),
                                          kHookSize);
                }
            }
        }

        g_hookInstalled = false;
    }

    if (g_trampoline != nullptr)
    {
        VirtualFree(g_trampoline, 0, MEM_RELEASE);
        g_trampoline = nullptr;
    }

    g_originalControlTraceW = nullptr;

    if (k_TraceProperties != nullptr)
    {
        free(k_TraceProperties);
        k_TraceProperties = nullptr;
    }

    g_hookedSessionName.clear();
    g_hookedLoggerId = 0;
    g_prepared       = false;
}

} // namespace SecurityTrace
