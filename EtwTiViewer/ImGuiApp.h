#pragma once
/*
 * ImGuiApp.h — Single-window ImGui application.
 *
 * Layout (no docking, no floating panels):
 *
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │  TOOLBAR  (two rows, ~80px)                                  │
 *   ├────────────┬───────────────────────────┬─────────────────────┤
 *   │  KEYWORDS  │  EVENT LIST               │  EVENT DETAILS      │
 *   │  260px     │  fills remaining space    │  resizable, 360px   │
 *   └────────────┴───────────────────────────┴─────────────────────┘
 *
 * Clicking a row selects it; the right-hand panel shows every decoded
 * property with per-value copy actions and a Copy-as-JSON button.
 */

#include <Windows.h>
#include <d3d11.h>
#include <string>
#include <vector>
#include <atomic>
#include <fstream>
#include <chrono>
#include <mutex>

#include "EventBuffer.h"
#include "EtwConsumer.h"

/* -------------------------------------------------------------------------
 * Keyword table entry
 * ------------------------------------------------------------------------- */
struct KeywordEntry {
    ULONGLONG    mask;
    const char*  name;
    bool         checked;
};

/* -------------------------------------------------------------------------
 * Row colour categories
 * ------------------------------------------------------------------------- */
enum class RowColor { Default, Remote, RemoteKernelCaller, Suspicious };

class ImGuiApp {
public:
    ImGuiApp();
    ~ImGuiApp();

    /* Call once after D3D11 device creation */
    bool Init(ID3D11Device* device, ID3D11DeviceContext* ctx, HWND hwnd);

    /* Call once per frame */
    void Render();

    /* Call on WM_SIZE (kept for compat; layout uses DisplaySize internally) */
    void OnResize(UINT w, UINT h) { m_width = w; m_height = h; }

private:
    /* ---- Layout helpers ---- */
    void RenderToolbar();
    void RenderKeywordsContent();   /* renders inside the already-begun child */
    void RenderEventTable();        /* renders inside the already-begun child */
    void RenderEventDetails();      /* renders inside the already-begun child */

    /* ---- Session helpers ---- */
    void DoStart();
    void DoStop();

    static ULONGLONG BuildKeywordMask(const std::vector<KeywordEntry>& kw);
    static RowColor  ClassifyEvent(const TiEvent& ev);
    static std::string FormatTimestamp(const FILETIME& ft);
    static std::string FormatTimestampFull(const FILETIME& ft);
    static std::string BuildEventJson(const TiEvent& ev);

    /* ---- File logging ---- */
    void LogEventToFile(const TiEvent& ev);
    void FlushLogIfDue();

    /* ---- State ---- */
    HWND                m_hwnd   = nullptr;
    UINT                m_width  = 1440;
    UINT                m_height = 900;

    /* Keywords */
    std::vector<KeywordEntry> m_keywords;

    /* Circular event buffer (50 000 entries) */
    EventBuffer         m_evBuf;

    /* Direct user-mode ETW-TI consumer (receives ALLOCVM/PROTECTVM/etc.) */
    EtwConsumer         m_etwConsumer;
    std::string         m_etwError;     /* shown in toolbar on failure */

    /* UI state */
    bool                m_sessionRunning  = false;
    bool                m_autoScroll      = true;
    bool                m_logToFile       = false;
    char                m_logPath[512]    = "etw_ti.jsonl";
    char                m_filter[256]     = {};
    int                 m_maxRows         = 5000;

    /* Event details panel */
    bool                m_hasSelection    = false;
    TiEvent             m_selected;
    uint64_t            m_selectedSeq     = 0;
    float               m_detailWidth     = 360.0f;

    /* File log */
    std::ofstream       m_logFile;
    std::chrono::steady_clock::time_point m_lastFlush;
};
