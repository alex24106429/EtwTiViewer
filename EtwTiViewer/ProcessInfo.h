#pragma once
/*
 * ProcessInfo.h — best-effort live process metadata for the details panel.
 *
 * All lookups are explicit: callers decide when to pay the cost.  The GUI
 * only resolves the calling/target processes when the selected event changes,
 * never for every event that arrives.
 */

#include <Windows.h>
#include <string>
#include <cstdint>

struct ProcessInfo {
    DWORD       pid = 0;

    /* Opened means OpenProcess succeeded; fields may still be partial. */
    bool        opened = false;
    bool        found = false;
    std::string error;

    std::string imageName;
    std::string imagePath;
    std::string commandLine;
    std::string user;
    std::string integrity;
    bool        elevated = false;

    /* Immediate parent, used for lineage. */
    bool        hasParent = false;
    DWORD       parentPid = 0;
    bool        parentFound = false;
    std::string parentName;
    std::string parentPath;
};

/*
 * Query a live process by PID.
 *
 * includeParent additionally resolves the immediate parent's image name and
 * path.  Parent lookup is deliberately shallow (no recursive lineage).
 *
 * This enables SeDebugPrivilege once, if the token allows it, to improve
 * coverage for protected/sibling processes.  Failures are reported in
 * ProcessInfo::error instead of throwing.
 */
ProcessInfo QueryProcessInfo(DWORD pid, bool includeParent);
