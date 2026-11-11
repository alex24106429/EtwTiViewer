/*
 * ProcessInfo.cpp — best-effort process metadata for the selected event.
 *
 * Everything here is queried on demand.  The renderer calls QueryProcessInfo()
 * only when the user selects a different event (and for that event's calling
 * and target PIDs), so the cost never scales with the event rate.
 */

#include "ProcessInfo.h"

#include <tlhelp32.h>
#include <sddl.h>

#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>

/* -------------------------------------------------------------------------
 * Minimal ntdll definitions
 * ------------------------------------------------------------------------- */

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

struct ProcBasicInformation {
    LONG        ExitStatus;
    PVOID       PebBaseAddress;
    ULONG_PTR   AffinityMask;
    LONG        BasePriority;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   InheritedFromUniqueProcessId;
};

struct ProcUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

static_assert(sizeof(ProcBasicInformation) == 48,
              "unexpected PROCESS_BASIC_INFORMATION layout");
static_assert(sizeof(ProcUnicodeString) == 16,
              "unexpected UNICODE_STRING layout");

static constexpr ULONG kProcessBasicInformation       = 0;
static constexpr ULONG kProcessCommandLineInformation = 60;

static NtQueryInformationProcessFn NtQueryProc() {
    static NtQueryInformationProcessFn fn = []() -> NtQueryInformationProcessFn {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return nullptr;
        return reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
    }();
    return fn;
}

/* -------------------------------------------------------------------------
 * String helpers
 * ------------------------------------------------------------------------- */

static std::string WideToUtf8(const std::wstring& in) {
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

static std::string BaseName(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

static std::string Win32ErrorText(DWORD error) {
    LPWSTR message = nullptr;
    DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0,
        reinterpret_cast<LPWSTR>(&message), 0, nullptr);

    std::string text;
    if (length != 0 && message != nullptr) {
        std::wstring wide(message, length);
        LocalFree(message);
        while (!wide.empty() &&
               (wide.back() == L'\r' || wide.back() == L'\n' ||
                wide.back() == L' '  || wide.back() == L'\t')) {
            wide.pop_back();
        }
        text = WideToUtf8(wide);
    }

    if (text.empty()) {
        char buf[32];
        snprintf(buf, sizeof(buf), "error %lu", static_cast<unsigned long>(error));
        return buf;
    }

    char suffix[32];
    snprintf(suffix, sizeof(suffix), " (error %lu)",
             static_cast<unsigned long>(error));
    return text + suffix;
}

/* -------------------------------------------------------------------------
 * Access / snapshots
 * ------------------------------------------------------------------------- */

static void EnableDebugPrivilegeOnce() {
    static bool attempted = false;
    if (attempted)
        return;
    attempted = true;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token)) {
        return;
    }

    LUID luid = {};
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }

    CloseHandle(token);
}

static HANDLE OpenProcessForQuery(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h && GetLastError() == ERROR_ACCESS_DENIED)
        h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    return h;
}

static bool FindProcessEntry(DWORD pid, PROCESSENTRY32W& out) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    out = {};
    out.dwSize = sizeof(out);

    bool found = false;
    if (Process32FirstW(snapshot, &out)) {
        do {
            if (out.th32ProcessID == pid) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &out));
    }

    CloseHandle(snapshot);
    return found;
}

/* -------------------------------------------------------------------------
 * Individual pieces of process information
 * ------------------------------------------------------------------------- */

static bool QueryImagePath(HANDLE process,
                           std::string& imagePath,
                           std::string& imageName) {
    std::vector<WCHAR> buffer(32768);
    DWORD length = static_cast<DWORD>(buffer.size());

    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &length) ||
        length == 0) {
        return false;
    }

    imagePath = WideToUtf8(std::wstring(buffer.data(), length));
    imageName = BaseName(imagePath);
    return !imagePath.empty();
}

static std::string QueryCommandLine(HANDLE process) {
    NtQueryInformationProcessFn query = NtQueryProc();
    if (!query)
        return {};

    /* Windows maximum command line is 32767 UTF-16 characters. */
    std::vector<BYTE> buffer(128 * 1024);
    ULONG returnLength = 0;

    NTSTATUS status = query(process,
                            kProcessCommandLineInformation,
                            buffer.data(),
                            static_cast<ULONG>(buffer.size()),
                            &returnLength);
    if (status < 0)
        return {};

    auto* command = reinterpret_cast<ProcUnicodeString*>(buffer.data());
    if (command->Buffer == nullptr || command->Length < sizeof(WCHAR))
        return {};

    /* The Buffer pointer is expected to point inside our output buffer. */
    const BYTE* begin = buffer.data();
    const BYTE* end   = begin + buffer.size();
    const BYTE* text  = reinterpret_cast<const BYTE*>(command->Buffer);
    if (text < begin || text >= end ||
        command->Length > static_cast<ULONG>(end - text)) {
        return {};
    }

    return WideToUtf8(std::wstring(command->Buffer,
                                   command->Length / sizeof(WCHAR)));
}

static DWORD QueryParentPid(HANDLE process) {
    NtQueryInformationProcessFn query = NtQueryProc();
    if (!query)
        return 0;

    ProcBasicInformation basic = {};
    ULONG returnLength = 0;
    NTSTATUS status = query(process,
                            kProcessBasicInformation,
                            &basic,
                            sizeof(basic),
                            &returnLength);
    if (status < 0)
        return 0;

    return static_cast<DWORD>(basic.InheritedFromUniqueProcessId);
}

static std::string AccountNameFromSid(PSID sid) {
    WCHAR name[256]   = {};
    WCHAR domain[256] = {};
    DWORD nameLength   = ARRAYSIZE(name);
    DWORD domainLength = ARRAYSIZE(domain);
    SID_NAME_USE use = SidTypeUnknown;

    if (LookupAccountSidW(nullptr, sid, name, &nameLength,
                          domain, &domainLength, &use)) {
        std::wstring full;
        if (domainLength != 0) {
            full.assign(domain, domainLength);
            full += L'\\';
        }
        full.append(name, nameLength);
        return WideToUtf8(full);
    }

    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        std::string out = WideToUtf8(sidString);
        LocalFree(sidString);
        return out;
    }

    return {};
}

static std::string IntegrityName(DWORD rid) {
    switch (rid) {
        case SECURITY_MANDATORY_UNTRUSTED_RID:          return "Untrusted";
        case SECURITY_MANDATORY_LOW_RID:                return "Low";
        case SECURITY_MANDATORY_MEDIUM_RID:             return "Medium";
        case SECURITY_MANDATORY_MEDIUM_PLUS_RID:        return "Medium+";
        case SECURITY_MANDATORY_HIGH_RID:               return "High";
        case SECURITY_MANDATORY_SYSTEM_RID:             return "System";
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:  return "Protected";
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%lX",
                     static_cast<unsigned long>(rid));
            return buf;
        }
    }
}

static void QueryTokenInfo(HANDLE process, ProcessInfo& info) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return;

    DWORD length = 0;

    /* User account */
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    if (length != 0) {
        std::vector<BYTE> buffer(length);
        if (GetTokenInformation(token, TokenUser, buffer.data(), length, &length)) {
            auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
            if (user->User.Sid)
                info.user = AccountNameFromSid(user->User.Sid);
        }
    }

    /* Integrity level */
    length = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &length);
    if (length != 0) {
        std::vector<BYTE> buffer(length);
        if (GetTokenInformation(token, TokenIntegrityLevel,
                                buffer.data(), length, &length)) {
            auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
            PSID sid = label->Label.Sid;
            if (sid) {
                PUCHAR count = GetSidSubAuthorityCount(sid);
                if (count && *count > 0) {
                    DWORD rid = *GetSidSubAuthority(sid, *count - 1);
                    info.integrity = IntegrityName(rid);
                }
            }
        }
    }

    /* Elevation flag for high-integrity admin tokens. */
    TOKEN_ELEVATION elevation = {};
    length = 0;
    if (GetTokenInformation(token, TokenElevation,
                            &elevation, sizeof(elevation), &length)) {
        info.elevated = elevation.TokenIsElevated != 0;
    }

    CloseHandle(token);
}

static void ResolveParent(ProcessInfo& info, HANDLE process) {
    DWORD parentPid = QueryParentPid(process);

    PROCESSENTRY32W self = {};
    if (parentPid == 0 && FindProcessEntry(info.pid, self))
        parentPid = self.th32ParentProcessID;

    if (parentPid == 0)
        return;

    info.hasParent = true;
    info.parentPid = parentPid;

    HANDLE parent = OpenProcessForQuery(parentPid);
    if (parent) {
        info.parentFound = QueryImagePath(parent, info.parentPath,
                                          info.parentName);
        CloseHandle(parent);
    }

    /* Toolhelp can still provide the image name for protected processes. */
    if (!info.parentFound || info.parentName.empty()) {
        PROCESSENTRY32W entry = {};
        if (FindProcessEntry(parentPid, entry)) {
            info.parentName = WideToUtf8(entry.szExeFile);
            info.parentFound = !info.parentName.empty();
        }
    }
}

/* -------------------------------------------------------------------------
 * Public entry point
 * ------------------------------------------------------------------------- */

ProcessInfo QueryProcessInfo(DWORD pid, bool includeParent) {
    ProcessInfo info;
    info.pid = pid;

    if (pid == 0) {
        info.error = "PID 0 is the System Idle Process; no process object exists.";
        return info;
    }

    EnableDebugPrivilegeOnce();

    HANDLE process = OpenProcessForQuery(pid);
    if (!process) {
        const DWORD error = GetLastError();

        if (error == ERROR_INVALID_PARAMETER) {
            info.error = "Process is not running (PID has exited or is invalid).";
        } else if (error == ERROR_ACCESS_DENIED) {
            info.error = "Access denied (protected process or insufficient rights).";
        } else {
            info.error = "Cannot open process: " + Win32ErrorText(error);
        }

        /* Fall back to the process snapshot for at least a name. */
        PROCESSENTRY32W entry = {};
        if (FindProcessEntry(pid, entry)) {
            info.imageName = WideToUtf8(entry.szExeFile);
            info.found = !info.imageName.empty();

            if (includeParent && entry.th32ParentProcessID != 0) {
                info.hasParent = true;
                info.parentPid = entry.th32ParentProcessID;

                PROCESSENTRY32W parentEntry = {};
                if (FindProcessEntry(info.parentPid, parentEntry)) {
                    info.parentName = WideToUtf8(parentEntry.szExeFile);
                    info.parentFound = !info.parentName.empty();
                }
            }
        }
        return info;
    }

    info.opened = true;

    QueryImagePath(process, info.imagePath, info.imageName);

    /* Protected processes may hide the path even when a handle is available. */
    if (info.imageName.empty()) {
        PROCESSENTRY32W entry = {};
        if (FindProcessEntry(pid, entry)) {
            info.imageName = WideToUtf8(entry.szExeFile);
        }
    }

    info.commandLine = QueryCommandLine(process);
    QueryTokenInfo(process, info);

    if (includeParent)
        ResolveParent(info, process);

    CloseHandle(process);

    info.found = info.opened ||
                 !info.imageName.empty() ||
                 !info.imagePath.empty() ||
                 !info.user.empty();

    if (!info.found && info.error.empty())
        info.error = "No process details available.";

    return info;
}
