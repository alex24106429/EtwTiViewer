#pragma once
/*
 * Headless.h — console-free capture mode used for automation and verification.
 *
 *   EtwTiViewer.exe --capture 30 --log out.jsonl [--keywords 0x...]
 *                   [--session 0MyThreatIntelTrace] [--max-events N]
 *
 * This bypasses ImGui/DirectX entirely and exercises exactly the same
 * EtwConsumer + SecurityTrace path as the GUI, so CI can prove that live
 * Threat-Intelligence events are being received without PPL or kernel
 * patching.
 */

#include <Windows.h>
#include <cstdint>
#include <string>

struct HeadlessOptions {
    std::wstring sessionName;               /* empty = built-in default */
    std::wstring logPath;                   /* empty = no JSONL file */
    int          seconds    = 20;
    uint64_t     maxEvents  = 0;            /* 0 = unlimited */
    int          cycles     = 1;            /* >1 exercises re-attach */
    ULONGLONG    keywordMask = 0;           /* 0 = all keywords */
};

/* Returns 0 when attached and the capture completed, non-zero on failure. */
int RunHeadless(const HeadlessOptions& options);
