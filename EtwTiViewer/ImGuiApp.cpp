/*
 * ImGuiApp.cpp — Single-window ImGui UI implementation.
 *
 * Layout: one fullscreen ImGui window (no docking, no floating panels).
 * Toolbar at top, then keywords (260px) + event list + details panel.
 */

#include "ImGuiApp.h"

#include "../third_party/imgui/imgui.h"
#include "../third_party/imgui/backends/imgui_impl_win32.h"
#include "../third_party/imgui/backends/imgui_impl_dx11.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>

/* JSON string escaping (used by the event log and Copy-as-JSON). */
static std::string EscapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04X", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

/* =========================================================================
 * Keyword table
 * ========================================================================= */
static const struct { ULONGLONG mask; const char* name; } kKeywords[] = {
    {0x0000000000000001ULL, "ALLOCVM_LOCAL"},
    {0x0000000000000002ULL, "ALLOCVM_LOCAL_KERNEL_CALLER"},
    {0x0000000000000004ULL, "ALLOCVM_REMOTE"},
    {0x0000000000000008ULL, "ALLOCVM_REMOTE_KERNEL_CALLER"},
    {0x0000000000000010ULL, "PROTECTVM_LOCAL"},
    {0x0000000000000020ULL, "PROTECTVM_LOCAL_KERNEL_CALLER"},
    {0x0000000000000040ULL, "PROTECTVM_REMOTE"},
    {0x0000000000000080ULL, "PROTECTVM_REMOTE_KERNEL_CALLER"},
    {0x0000000000000100ULL, "MAPVIEW_LOCAL"},
    {0x0000000000000200ULL, "MAPVIEW_LOCAL_KERNEL_CALLER"},
    {0x0000000000000400ULL, "MAPVIEW_REMOTE"},
    {0x0000000000000800ULL, "MAPVIEW_REMOTE_KERNEL_CALLER"},
    {0x0000000000001000ULL, "QUEUEUSERAPC_REMOTE"},
    {0x0000000000002000ULL, "QUEUEUSERAPC_REMOTE_KERNEL_CALLER"},
    {0x0000000000004000ULL, "SETTHREADCONTEXT_REMOTE"},
    {0x0000000000008000ULL, "SETTHREADCONTEXT_REMOTE_KERNEL_CALLER"},
    {0x0000000000010000ULL, "READVM_LOCAL"},
    {0x0000000000020000ULL, "READVM_REMOTE"},
    {0x0000000000040000ULL, "WRITEVM_LOCAL"},
    {0x0000000000080000ULL, "WRITEVM_REMOTE"},
    {0x0000000000100000ULL, "SUSPEND_THREAD"},
    {0x0000000000200000ULL, "RESUME_THREAD"},
    {0x0000000000400000ULL, "SUSPEND_PROCESS"},
    {0x0000000000800000ULL, "RESUME_PROCESS"},
    {0x0000000001000000ULL, "FREEZE_PROCESS"},
    {0x0000000002000000ULL, "THAW_PROCESS"},
    {0x0000000004000000ULL, "CONTEXT_PARSE"},
    {0x0000000008000000ULL, "EXECUTION_ADDRESS_VAD_PROBE"},
    {0x0000000010000000ULL, "EXECUTION_ADDRESS_MMF_NAME_PROBE"},
    {0x0000000020000000ULL, "READWRITEVM_NO_SIGNATURE_RESTRICTION"},
    {0x0000000040000000ULL, "DRIVER_EVENTS"},
    {0x0000000080000000ULL, "DEVICE_EVENTS"},
    {0x0000000100000000ULL, "READVM_REMOTE_FILL_VAD"},
    {0x0000000200000000ULL, "WRITEVM_REMOTE_FILL_VAD"},
    {0x0000000400000000ULL, "PROTECTVM_LOCAL_FILL_VAD"},
    {0x0000000800000000ULL, "PROTECTVM_LOCAL_KERNEL_CALLER_FILL_VAD"},
    {0x0000001000000000ULL, "PROTECTVM_REMOTE_FILL_VAD"},
    {0x0000002000000000ULL, "PROTECTVM_REMOTE_KERNEL_CALLER_FILL_VAD"},
    {0x0000004000000000ULL, "PROCESS_IMPERSONATION_UP"},
    {0x0000008000000000ULL, "PROCESS_IMPERSONATION_REVERT"},
    {0x0000010000000000ULL, "PROCESS_SYSCALL_USAGE"},
    {0x0000020000000000ULL, "QUEUEUSERAPC_AT_DPC"},
    {0x0000040000000000ULL, "PROCESS_IMPERSONATION_DOWN"},
};

struct KwGroup { const char* label; const char* prefixes[8]; };
static const KwGroup kGroups[] = {
    { "Memory Ops",     { "ALLOCVM_", "PROTECTVM_", "MAPVIEW_", "READVM_", "WRITEVM_", nullptr } },
    { "Thread/Process", { "QUEUEUSERAPC_", "SETTHREADCONTEXT_", "SUSPEND_", "RESUME_",
                          "FREEZE_", "THAW_", "PROCESS_", nullptr } },
    { "Misc",           { "CONTEXT_PARSE", "EXECUTION_ADDRESS_", "DRIVER_EVENTS",
                          "DEVICE_EVENTS", "READWRITEVM_NO_SIGNATURE_RESTRICTION", nullptr } },
};

static bool NameMatchesGroup(const char* name, const KwGroup& g) {
    for (int i = 0; g.prefixes[i]; ++i)
        if (strncmp(name, g.prefixes[i], strlen(g.prefixes[i])) == 0)
            return true;
    return false;
}

/*
 * Keywords that generate a lot of low-value noise and are therefore unticked
 * by default.  They can still be enabled manually in the sidebar or via [All].
 */
static bool KeywordDefaultChecked(const char* name) {
    static const char* kOffByDefault[] = {
        "ALLOCVM_LOCAL",
        "PROTECTVM_LOCAL",
        "WRITEVM_LOCAL",
        nullptr,
    };
    for (int i = 0; kOffByDefault[i]; ++i)
        if (strcmp(name, kOffByDefault[i]) == 0)
            return false;
    return true;
}

/* =========================================================================
 * Constructor / destructor
 * ========================================================================= */

ImGuiApp::ImGuiApp()
    : m_evBuf(50000)
    , m_lastFlush(std::chrono::steady_clock::now())
{
    for (auto& k : kKeywords)
        m_keywords.push_back({ k.mask, k.name, KeywordDefaultChecked(k.name) });
}

ImGuiApp::~ImGuiApp() {
    m_etwConsumer.Stop();
    SecurityTrace::Cleanup();
    if (m_logFile.is_open()) m_logFile.close();
}

/* =========================================================================
 * Init
 * ========================================================================= */

bool ImGuiApp::Init(ID3D11Device* device, ID3D11DeviceContext* ctx, HWND hwnd) {
    m_hwnd = hwnd;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    /* No docking — layout is fixed child-window split */

    /* ---- Style ---- */
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.FrameRounding = 3.0f;
    style.GrabRounding  = 3.0f;
    style.WindowRounding = 0.0f;
    style.ChildRounding  = 4.0f;
    style.ScrollbarRounding = 3.0f;

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]      = {0.10f, 0.10f, 0.11f, 1.0f};
    colors[ImGuiCol_ChildBg]       = {0.13f, 0.13f, 0.14f, 1.0f};
    colors[ImGuiCol_Header]        = {0.20f, 0.20f, 0.22f, 1.0f};
    colors[ImGuiCol_HeaderHovered] = {0.28f, 0.28f, 0.30f, 1.0f};
    colors[ImGuiCol_HeaderActive]  = {0.35f, 0.35f, 0.38f, 1.0f};
    colors[ImGuiCol_Button]        = {0.20f, 0.45f, 0.68f, 1.0f};
    colors[ImGuiCol_ButtonHovered] = {0.26f, 0.55f, 0.78f, 1.0f};
    colors[ImGuiCol_ButtonActive]  = {0.15f, 0.35f, 0.58f, 1.0f};
    colors[ImGuiCol_FrameBg]       = {0.18f, 0.18f, 0.20f, 1.0f};
    colors[ImGuiCol_FrameBgHovered]= {0.24f, 0.24f, 0.27f, 1.0f};

    /* ---- Font ---- */
    ImFont* font = io.Fonts->AddFontFromFileTTF("./fonts/ProggyClean.ttf", 13.0f);
    if (!font) {
        /* File not found; ImGui uses built-in default automatically */
    }

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(device, ctx);

    /* Automation hook: --autostart / ETWTI_AUTOSTART=1 attaches immediately. */
    {
        WCHAR autostart[8] = {};
        if (GetEnvironmentVariableW(L"ETWTI_AUTOSTART", autostart,
                                    ARRAYSIZE(autostart)) > 0 &&
            wcscmp(autostart, L"0") != 0)
        {
            DoStart();
        }
    }

    return true;
}

/* =========================================================================
 * Render — called once per frame
 * ========================================================================= */

void ImGuiApp::Render() {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    /* Update OS window title each frame */
    if (m_hwnd) {
        SetWindowTextW(m_hwnd,
            m_sessionRunning
                ? L"EtwTi Viewer \x2014 [Running]"
                : L"EtwTi Viewer \x2014 [Stopped]");
    }

    FlushLogIfDue();

    /* ---- Full-screen single window ---- */
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos({0.0f, 0.0f});
    ImGui::SetNextWindowSize(io.DisplaySize);

    static const ImGuiWindowFlags kMainFlags =
        ImGuiWindowFlags_NoTitleBar        |
        ImGuiWindowFlags_NoResize          |
        ImGuiWindowFlags_NoMove            |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoScrollbar       |
        ImGuiWindowFlags_NoScrollWithMouse;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {6.0f, 6.0f});
    ImGui::Begin("##main", nullptr, kMainFlags);
    ImGui::PopStyleVar();

    /* ---- Toolbar (two rows, pinned at top) ---- */
    RenderToolbar();
    ImGui::Spacing();

    /* ---- Three-column workspace ---- */
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, {4.0f, 3.0f});

    const float kwW       = 260.0f;
    const float gap       = 4.0f;
    const float splitW    = 5.0f;
    const float fullW     = ImGui::GetContentRegionAvail().x;
    const float minEventW = 280.0f;

    /* Keep the details panel usable on narrow windows while preserving a
     * sensible minimum width for the event list. */
    const float maxDetailW = (std::max)(240.0f,
        (std::min)(640.0f, fullW - kwW - gap * 3.0f - splitW - minEventW));
    const float detailW = std::clamp(m_detailWidth, 240.0f, maxDetailW);
    const float eventW  = (std::max)(160.0f,
        fullW - kwW - gap * 3.0f - splitW - detailW);

    /* Left: keyword panel */
    if (ImGui::BeginChild("##keywords", {kwW, 0.0f}, true,
                          ImGuiWindowFlags_NoScrollbar)) {
        RenderKeywordsContent();
    }
    ImGui::EndChild();

    ImGui::SameLine(0.0f, gap);

    /* Middle: event list */
    if (ImGui::BeginChild("##events", {eventW, 0.0f}, false)) {
        RenderEventTable();
    }
    ImGui::EndChild();

    /* Draggable splitter for the details panel */
    ImGui::SameLine(0.0f, gap);
    ImGui::InvisibleButton("##details_splitter",
                           {splitW, ImGui::GetContentRegionAvail().y});
    const bool splitHot = ImGui::IsItemHovered() || ImGui::IsItemActive();
    if (splitHot)
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    if (ImGui::IsItemActive())
        m_detailWidth = std::clamp(m_detailWidth - ImGui::GetIO().MouseDelta.x,
                                   240.0f, 640.0f);

    /* Thin divider line makes the resize handle discoverable. */
    const ImVec2 splitMin = ImGui::GetItemRectMin();
    const ImVec2 splitMax = ImGui::GetItemRectMax();
    ImGui::GetWindowDrawList()->AddLine(
        {splitMin.x + splitW * 0.5f, splitMin.y},
        {splitMin.x + splitW * 0.5f, splitMax.y},
        ImGui::GetColorU32(splitHot ? ImGuiCol_SeparatorActive
                                    : ImGuiCol_Separator),
        1.0f);

    ImGui::SameLine(0.0f, gap);

    /* Right: selected event details */
    if (ImGui::BeginChild("##details", {detailW, 0.0f}, true,
                          ImGuiWindowFlags_NoScrollbar)) {
        RenderEventDetails();
    }
    ImGui::EndChild();

    ImGui::PopStyleVar();

    ImGui::End();

    ImGui::Render();
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}

/* =========================================================================
 * Toolbar — two rows rendered directly inside the main window
 * ========================================================================= */

void ImGuiApp::RenderToolbar() {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {6.0f, 4.0f});

    /* Row 1: Start/Stop  Clear  Filter  Log toggle + path */
    if (!m_sessionRunning) {
        if (ImGui::Button("Start")) DoStart();
    } else {
        if (ImGui::Button(" Stop ")) DoStop();
    }
    ImGui::SameLine();

    if (ImGui::Button("Clear")) {
        m_evBuf.Clear();
        m_hasSelection = false;
    }
    ImGui::SameLine(0.0f, 12.0f);

    ImGui::TextUnformatted("Filter:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.0f);
    ImGui::InputText("##filter", m_filter, sizeof(m_filter));
    ImGui::SameLine(0.0f, 12.0f);

    /* Log toggle button */
    {
        bool  prev = m_logToFile;
        ImVec4 btnCol = m_logToFile
            ? ImVec4{0.20f, 0.60f, 0.20f, 1.0f}
            : ImGui::GetStyle().Colors[ImGuiCol_Button];
        ImGui::PushStyleColor(ImGuiCol_Button, btnCol);
        if (ImGui::Button(m_logToFile ? "Log [ON] " : "Log [OFF]"))
            m_logToFile = !m_logToFile;
        ImGui::PopStyleColor();

        if (m_logToFile && !prev) {
            /* Just enabled — open file */
            if (!m_logFile.is_open())
                m_logFile.open(m_logPath, std::ios::app);
        } else if (!m_logToFile && prev) {
            /* Just disabled — flush and close */
            if (m_logFile.is_open()) { m_logFile.flush(); m_logFile.close(); }
        }

        /* Inline path input (same row, visible only when log is on) */
        if (m_logToFile) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(280.0f);
            if (ImGui::InputText("##logpath", m_logPath, sizeof(m_logPath))) {
                if (m_logFile.is_open()) { m_logFile.flush(); m_logFile.close(); }
                m_logFile.open(m_logPath, std::ios::app);
            }
        }
    }

    /* ---- Row 2: component status indicators ---- */

    /* Helper: render a coloured dot + label as a single hoverable group.
     * col    — dot colour
     * label  — short text shown next to dot
     * tooltip — multi-line string shown on hover (nullptr = no tooltip)     */
    auto StatusIndicator = [](const char* label, ImVec4 col, const char* tooltip) {
        ImGui::BeginGroup();
        ImGui::TextColored(col, "\xe2\x97\x8f");   /* UTF-8 U+25CF FILLED CIRCLE */
        ImGui::SameLine(0.0f, 4.0f);
        ImGui::TextUnformatted(label);
        ImGui::EndGroup();
        if (tooltip && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 28.0f);
            ImGui::TextUnformatted(tooltip);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    };

    /* Thin vertical separator between groups */
    auto VSep = []() {
        ImGui::SameLine(0.0f, 10.0f);
        ImGui::TextDisabled("|");
        ImGui::SameLine(0.0f, 10.0f);
    };

    /* --- ETW-TI CONSUMER (AutoLogger / SecurityTrace) --- */
    {
        bool        etwOk = m_etwConsumer.IsRunning();
        const SecurityTrace::SessionInfo& s = m_etwConsumer.Session();
        const char* etwLabel;
        ImVec4      etwCol;

        char tip[900];
        if (etwOk) {
            etwLabel = "ETW-TI (AutoLogger)";
            etwCol   = {0.20f, 0.85f, 0.20f, 1.0f};
            snprintf(tip, sizeof(tip),
                "Microsoft-Windows-Threat-Intelligence\n"
                "  Mode      : AutoLogger attach (no PPL required)\n"
                "  Session   : %ls (real-time)\n"
                "  Logger ID : %lu%s\n"
                "  Keyword   : 0x%016llX\n"
                "  GUID      : {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}\n"
                "  Status    : Active\n\n"
                "  Delivers: ALLOCVM, PROTECTVM, MAPVIEW,\n"
                "            QUEUEUSERAPC, SETTHREADCONTEXT,\n"
                "            READVM, WRITEVM, SUSPEND/RESUME,\n"
                "            FREEZE/THAW, and more\n\n"
                "  The kernel enabled the provider at boot; the\n"
                "  in-process detour only bypasses the sechost\n"
                "  ControlTraceW(QUERY) access check.",
                s.name.c_str(), s.loggerId,
                s.protectedSession ? " (SecurityTrace-protected)" : "",
                (unsigned long long)s.providerMask);
        } else if (!m_etwError.empty()) {
            etwLabel = "ETW-TI (error)";
            etwCol   = {0.85f, 0.25f, 0.25f, 1.0f};
            snprintf(tip, sizeof(tip),
                "Microsoft-Windows-Threat-Intelligence\n"
                "  Status: FAILED\n\n"
                "%s",
                m_etwError.c_str());
        } else if (m_sessionRunning) {
            etwLabel = "ETW-TI (error)";
            etwCol   = {0.85f, 0.25f, 0.25f, 1.0f};
            snprintf(tip, sizeof(tip),
                "Microsoft-Windows-Threat-Intelligence\n"
                "  Status: not attached\n\n"
                "  Run EtwTiViewer as Administrator and press Start.");
        } else {
            etwLabel = "ETW-TI (idle)";
            etwCol   = {0.45f, 0.45f, 0.45f, 1.0f};
            snprintf(tip, sizeof(tip),
                "Microsoft-Windows-Threat-Intelligence\n"
                "  Session : %ls\n"
                "  Status  : Idle (not attached)\n\n"
                "  One-time setup (elevated, then reboot):\n"
                "    EtwTiViewer\\install_autologger.ps1\n\n"
                "  No PPL required: the kernel enabled the provider at boot.",
                s.name.empty() ? EtwConsumer::kDefaultSessionName
                               : s.name.c_str());
        }
        StatusIndicator(etwLabel, etwCol, tip);
    }

    VSep();

    /* --- STATS --- */
    {
        char statsTip[384];
        snprintf(statsTip, sizeof(statsTip),
            "Event throughput\n"
            "  EVT     : ETW-TI events decoded this session\n"
            "  BUF     : events currently in the ring buffer\n"
            "            (oldest are overwritten when full)");
        ImGui::BeginGroup();
        ImGui::Text("EVT \xe2\x94\x82 %llu   BUF \xe2\x94\x82 %zu",
            (unsigned long long)m_etwConsumer.EventCount(),
            m_evBuf.Size());
        ImGui::EndGroup();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(statsTip);
            ImGui::EndTooltip();
        }
    }

    VSep();

    /* --- CONTROLS --- */
    ImGui::SetNextItemWidth(100.0f);
    ImGui::SliderInt("Rows", &m_maxRows, 500, 50000);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        ImGui::SetTooltip("Maximum rows rendered in the event table.\nOldest events are hidden (not discarded) above this limit.");
    ImGui::SameLine(0.0f, 10.0f);

    ImGui::Checkbox("Auto-scroll", &m_autoScroll);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        ImGui::SetTooltip("Automatically scroll the event table to the newest entry.");

    ImGui::PopStyleVar(); /* FramePadding */
    ImGui::Separator();
}

/* =========================================================================
 * Keyword panel content — rendered inside the ##keywords child
 * ========================================================================= */

void ImGuiApp::RenderKeywordsContent() {
    /* [All] / [None] compact buttons */
    if (ImGui::SmallButton("All"))
        for (auto& k : m_keywords) k.checked = true;
    ImGui::SameLine();
    if (ImGui::SmallButton("None"))
        for (auto& k : m_keywords) k.checked = false;

    ImGui::Separator();

    /* Scrollable keyword list — leave room for Apply button at bottom */
    float applyH = ImGui::GetFrameHeightWithSpacing() + 6.0f;
    ImGui::BeginChild("##kwscroll", {0.0f, -applyH}, false);

    for (const auto& grp : kGroups) {
        if (ImGui::CollapsingHeader(grp.label,
                ImGuiTreeNodeFlags_DefaultOpen)) {
            for (auto& kw : m_keywords) {
                if (NameMatchesGroup(kw.name, grp))
                    ImGui::Checkbox(kw.name, &kw.checked);
            }
        }
    }

    ImGui::EndChild();

    /* Apply pinned to bottom */
    ImGui::Separator();
    if (ImGui::Button("Apply", {-1.0f, 0.0f})) {
        if (m_sessionRunning) DoStop();
        DoStart();
    }
}

/* =========================================================================
 * Event table — rendered inside the ##events child
 * ========================================================================= */

void ImGuiApp::RenderEventTable() {
    static const ImGuiTableFlags kTableFlags =
        ImGuiTableFlags_ScrollY       |
        ImGuiTableFlags_Resizable     |
        ImGuiTableFlags_BordersOuter  |
        ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_RowBg         |
        ImGuiTableFlags_SizingStretchProp;

    /* Use full available area for the table */
    ImVec2 tableSize = ImGui::GetContentRegionAvail();
    if (!ImGui::BeginTable("EventTable", 5, kTableFlags, tableSize))
        return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed,    90.0f);
    ImGui::TableSetupColumn("ID",        ImGuiTableColumnFlags_WidthFixed,    38.0f);
    ImGui::TableSetupColumn("Name",      ImGuiTableColumnFlags_WidthStretch,  1.00f);
    ImGui::TableSetupColumn("PID",       ImGuiTableColumnFlags_WidthFixed,    52.0f);
    ImGui::TableSetupColumn("TID",       ImGuiTableColumnFlags_WidthFixed,    52.0f);
    ImGui::TableHeadersRow();

    std::vector<TiEvent> snap = m_evBuf.Snapshot(static_cast<size_t>(m_maxRows));

    /* Apply filter */
    const std::string filterStr(m_filter);
    if (!filterStr.empty()) {
        snap.erase(std::remove_if(snap.begin(), snap.end(),
            [&](const TiEvent& ev) {
                if (ev.name.find(filterStr) != std::string::npos) return false;
                for (auto& [k, v] : ev.fields)
                    if (k.find(filterStr) != std::string::npos ||
                        v.find(filterStr) != std::string::npos)
                        return false;
                return true;
            }), snap.end());
    }

    static const ImVec4 kColRemote     {0.80f, 0.20f, 0.20f, 0.35f};
    static const ImVec4 kColRemoteKern {0.80f, 0.47f, 0.00f, 0.35f};
    static const ImVec4 kColSuspect    {0.67f, 0.67f, 0.00f, 0.30f};
    static const ImVec4 kColSelected   {0.18f, 0.42f, 0.66f, 1.00f};

    for (const auto& ev : snap) {
        ImGui::TableNextRow();

        RowColor rc = ClassifyEvent(ev);
        if (rc != RowColor::Default) {
            const ImVec4& bg = rc == RowColor::Remote           ? kColRemote     :
                               rc == RowColor::RemoteKernelCaller ? kColRemoteKern :
                                                                    kColSuspect;
            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                   ImGui::ColorConvertFloat4ToU32(bg));
        }

        const bool selected = m_hasSelection && ev.seq == m_selectedSeq;

        ImGui::TableSetColumnIndex(0);
        const std::string ts = FormatTimestamp(ev.timestamp);

        /* Timestamps repeat at millisecond resolution, so include the
         * monotonically increasing sequence number in the Selectable ID. */
        char rowLabel[64];
        snprintf(rowLabel, sizeof(rowLabel), "%s##%llu",
                 ts.c_str(), (unsigned long long)ev.seq);

        if (selected)
            ImGui::PushStyleColor(ImGuiCol_Header, kColSelected);
        if (ImGui::Selectable(rowLabel, selected,
                              ImGuiSelectableFlags_SpanAllColumns)) {
            m_selected     = ev;
            m_selectedSeq  = ev.seq;
            m_hasSelection = true;
        }
        if (selected)
            ImGui::PopStyleColor();

        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
            ImGui::SetTooltip("Click to show all properties in the details panel.");

        ImGui::TableSetColumnIndex(1);
        ImGui::Text("%u", (unsigned)ev.eventId);

        ImGui::TableSetColumnIndex(2);
        ImGui::TextUnformatted(ev.name.c_str());

        ImGui::TableSetColumnIndex(3);
        ImGui::Text("%u", ev.pid);

        ImGui::TableSetColumnIndex(4);
        ImGui::Text("%u", ev.tid);
    }

    if (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f)
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndTable();
}

/* =========================================================================
 * Process metadata helpers
 * ========================================================================= */

static const std::string* FindEventField(const TiEvent& ev, const char* name) {
    for (const auto& field : ev.fields) {
        if (field.first == name)
            return &field.second;
    }
    return nullptr;
}

static uint32_t ParsePidField(const TiEvent& ev, const char* name,
                              uint32_t fallback) {
    const std::string* value = FindEventField(ev, name);
    if (!value)
        return fallback;

    char* end = nullptr;
    const unsigned long pid = strtoul(value->c_str(), &end, 10);
    if (end == value->c_str())
        return fallback;
    return static_cast<uint32_t>(pid);
}

static std::string BuildProcessSummary(const ProcessInfo& info) {
    std::ostringstream out;
    out << "PID: " << info.pid << "\n";

    if (!info.imageName.empty())
        out << "Image: " << info.imageName << "\n";
    if (!info.imagePath.empty())
        out << "Path: " << info.imagePath << "\n";
    if (!info.commandLine.empty())
        out << "Command line: " << info.commandLine << "\n";

    if (info.hasParent) {
        out << "Parent: PID " << info.parentPid;
        if (!info.parentName.empty())
            out << " (" << info.parentName << ")";
        out << "\n";
        if (!info.parentPath.empty())
            out << "Parent path: " << info.parentPath << "\n";
    }

    if (!info.user.empty())
        out << "User: " << info.user << "\n";
    if (!info.integrity.empty()) {
        out << "Integrity: " << info.integrity;
        if (info.elevated)
            out << " (elevated)";
        out << "\n";
    }

    if (!info.error.empty())
        out << "Note: " << info.error << "\n";

    return out.str();
}

/* Label/value row with wrapped text and a right-click copy menu. */
static void RenderProcessField(const char* label, const std::string& value) {
    if (value.empty())
        return;

    ImGui::PushID(label);

    const float valueIndent = ImGui::GetCursorPosX() + 92.0f;

    ImGui::TextDisabled("%s", label);
    ImGui::SameLine(valueIndent);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(value.c_str());
    ImGui::PopTextWrapPos();

    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        ImGui::SetTooltip("Right-click to copy this value.");
    if (ImGui::IsItemHovered() &&
        ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
        ImGui::OpenPopup("##proc_value_menu");
    }
    if (ImGui::BeginPopup("##proc_value_menu")) {
        if (ImGui::MenuItem("Copy value"))
            ImGui::SetClipboardText(value.c_str());
        ImGui::EndPopup();
    }

    ImGui::PopID();
}

/* =========================================================================
 * Event details — rendered inside the ##details child
 * ========================================================================= */

void ImGuiApp::RenderEventDetails() {
    ImGui::TextDisabled("EVENT DETAILS");
    ImGui::Separator();

    if (!m_hasSelection) {
        ImGui::Spacing();
        ImGui::TextDisabled("No event selected");
        ImGui::Spacing();
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextDisabled("Click a row in the event list to inspect all of its "
                            "properties.");
        ImGui::PopTextWrapPos();
        return;
    }

    const TiEvent& ev = m_selected;
    const ImGuiStyle& style = ImGui::GetStyle();
    const bool newSelection = (m_contextSeq != ev.seq);

    /* Event name */
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.86f, 1.00f, 1.0f));
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(ev.name.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();

    /* Event metadata */
    const float metaIndent = ImGui::GetCursorPosX() + 92.0f;
    const std::string tsFull = FormatTimestampFull(ev.timestamp);

    ImGui::TextDisabled("Timestamp"); ImGui::SameLine(metaIndent);
    ImGui::TextUnformatted(tsFull.c_str());
    ImGui::TextDisabled("Event ID"); ImGui::SameLine(metaIndent);
    ImGui::Text("%u  (task %u)", (unsigned)ev.eventId, (unsigned)ev.task);
    ImGui::TextDisabled("PID / TID"); ImGui::SameLine(metaIndent);
    ImGui::Text("%u / %u", ev.pid, ev.tid);
    ImGui::TextDisabled("Keyword"); ImGui::SameLine(metaIndent);
    ImGui::Text("0x%016llX", (unsigned long long)ev.keyword);

    ImGui::Spacing();
    if (ImGui::Button("Copy event as JSON", {-1.0f, 0.0f})) {
        if (m_contextSeq != ev.seq)
            RefreshProcessContext();
        ImGui::SetClipboardText(BuildEventJson(ev).c_str());
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        ImGui::SetTooltip("Copy the event metadata, properties, and resolved "
                          "process context as JSON.");

    ImGui::Spacing();
    ImGui::Separator();

    /* Metadata and the copy button stay pinned; process context and all
     * properties share one scroll region. */
    ImGui::BeginChild("##details_body", {0.0f, 0.0f}, false);
    if (newSelection)
        ImGui::SetScrollY(0.0f);

    RenderProcessContext();

    ImGui::Spacing();
    ImGui::TextDisabled("Properties (%zu)", ev.fields.size());
    if (ev.fields.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("The provider did not expose any properties for this event.");
        ImGui::EndChild();
        return;
    }

    /* Values wrap; the Copy button is on the key line. */
    for (size_t i = 0; i < ev.fields.size(); ++i) {
        ImGui::PushID(static_cast<int>(i));

        const std::string& key   = ev.fields[i].first;
        const std::string& value = ev.fields[i].second;

        const float rowStartX = ImGui::GetCursorPosX();
        const float rowWidth  = ImGui::GetContentRegionAvail().x;
        const float copyW     = ImGui::CalcTextSize("Copy").x +
                                style.FramePadding.x * 2.0f;

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.56f, 0.76f, 0.96f, 1.0f));
        ImGui::TextUnformatted(key.c_str());
        ImGui::PopStyleColor();

        /* Right-align the copy button on the property-name line. */
        if (rowStartX + rowWidth - copyW >
            ImGui::GetCursorPosX() + style.ItemSpacing.x) {
            ImGui::SameLine(rowStartX + rowWidth - copyW);
        } else {
            ImGui::SameLine();
        }
        if (ImGui::SmallButton("Copy"))
            ImGui::SetClipboardText(value.c_str());
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
            ImGui::SetTooltip("Copy this value to the clipboard.");

        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(value.c_str());
        ImGui::PopTextWrapPos();

        if (ImGui::IsItemHovered() &&
            ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            ImGui::OpenPopup("##value_menu");
        }
        if (ImGui::BeginPopup("##value_menu")) {
            if (ImGui::MenuItem("Copy value"))
                ImGui::SetClipboardText(value.c_str());
            if (ImGui::MenuItem("Copy name=value")) {
                const std::string kv = key + "=" + value;
                ImGui::SetClipboardText(kv.c_str());
            }
            ImGui::EndPopup();
        }

        if (i + 1 < ev.fields.size())
            ImGui::Separator();
        else
            ImGui::Spacing();

        ImGui::PopID();
    }

    ImGui::EndChild();
}

/* =========================================================================
 * Process context — lazy lookup for the currently selected event
 * ========================================================================= */

void ImGuiApp::RefreshProcessContext() {
    m_contextSeq = m_selected.seq;

    m_contextCallingPid = ParsePidField(m_selected, "CallingProcessId",
                                        m_selected.pid);
    m_contextTargetPid  = ParsePidField(m_selected, "TargetProcessId", 0);

    m_callingInfo = QueryProcessInfo(m_contextCallingPid, true);

    if (m_contextTargetPid != 0 &&
        m_contextTargetPid != m_contextCallingPid) {
        m_targetInfo = QueryProcessInfo(m_contextTargetPid, true);
    } else {
        m_targetInfo = ProcessInfo{};
    }
}

void ImGuiApp::RenderProcessContext() {
    if (!m_hasSelection)
        return;

    if (m_contextSeq != m_selected.seq)
        RefreshProcessContext();

    if (!ImGui::CollapsingHeader("Process Context",
            ImGuiTreeNodeFlags_DefaultOpen)) {
        return;
    }

    auto RenderBlock = [](const char* heading, DWORD pid,
                          const ProcessInfo& info) {
        ImGui::PushID(static_cast<int>(pid));

        const ImGuiStyle& style = ImGui::GetStyle();
        const float startX = ImGui::GetCursorPosX();
        const float width  = ImGui::GetContentRegionAvail().x;
        const float copyW  = ImGui::CalcTextSize("Copy").x +
                             style.FramePadding.x * 2.0f;

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.86f, 1.00f, 1.0f));
        ImGui::Text("%s  (PID %u)", heading, (unsigned)pid);
        ImGui::PopStyleColor();

        if (startX + width - copyW >
            ImGui::GetCursorPosX() + style.ItemSpacing.x) {
            ImGui::SameLine(startX + width - copyW);
        } else {
            ImGui::SameLine();
        }
        if (ImGui::SmallButton("Copy"))
            ImGui::SetClipboardText(BuildProcessSummary(info).c_str());
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
            ImGui::SetTooltip("Copy this process summary to the clipboard.");

        if (!info.found) {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextDisabled("%s", info.error.empty()
                ? "Process details unavailable."
                : info.error.c_str());
            ImGui::PopTextWrapPos();
            ImGui::Spacing();
            ImGui::PopID();
            return;
        }

        if (!info.imageName.empty())
            RenderProcessField("Image", info.imageName);
        if (!info.imagePath.empty())
            RenderProcessField("Path", info.imagePath);
        if (!info.commandLine.empty())
            RenderProcessField("Command line", info.commandLine);

        if (info.hasParent) {
            std::string parent = "PID " + std::to_string(info.parentPid);
            if (!info.parentName.empty())
                parent += " (" + info.parentName + ")";
            RenderProcessField("Parent", parent);
            if (!info.parentPath.empty())
                RenderProcessField("Parent path", info.parentPath);
        }

        if (!info.user.empty())
            RenderProcessField("User", info.user);
        if (!info.integrity.empty()) {
            std::string integrity = info.integrity;
            if (info.elevated)
                integrity += " (elevated)";
            RenderProcessField("Integrity", integrity);
        }

        if (!info.error.empty()) {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextDisabled("%s", info.error.c_str());
            ImGui::PopTextWrapPos();
        }

        ImGui::Spacing();
        ImGui::PopID();
    };

    RenderBlock("CALLING PROCESS", m_contextCallingPid, m_callingInfo);

    if (m_contextTargetPid != 0 &&
        m_contextTargetPid != m_contextCallingPid) {
        ImGui::Separator();
        RenderBlock("TARGET PROCESS", m_contextTargetPid, m_targetInfo);
    }

    ImGui::Separator();
}

/* =========================================================================
 * ETW-TI session helpers
 * ========================================================================= */

void ImGuiApp::DoStart() {
    ULONGLONG mask = BuildKeywordMask(m_keywords);

    /*
     * Attach the user-mode ETW-TI consumer to the pre-existing AutoLogger
     * session.  This is the part that receives ALLOCVM_REMOTE, PROTECTVM_*,
     * MAPVIEW_*, etc.  It needs no PPL: the kernel enabled the provider at
     * boot, and SecurityTrace detours the sechost ControlTraceW(QUERY) check
     * inside this process.
     */
    m_etwError = m_etwConsumer.Start(mask, [this](TiEvent&& ev) {
        if (m_logToFile) LogEventToFile(ev);
        m_evBuf.Push(std::move(ev));
    });

    m_sessionRunning = m_etwError.empty();
}

void ImGuiApp::DoStop() {
    m_etwConsumer.Stop();
    m_etwError.clear();
    m_sessionRunning = false;
}

/* =========================================================================
 * Static helpers
 * ========================================================================= */

ULONGLONG ImGuiApp::BuildKeywordMask(const std::vector<KeywordEntry>& kw) {
    ULONGLONG mask = 0;
    for (const auto& k : kw)
        if (k.checked) mask |= k.mask;
    return mask;
}

RowColor ImGuiApp::ClassifyEvent(const TiEvent& ev) {
    const char* n = ev.name.c_str();
    /* Check kernel-caller remote first (more specific than plain _REMOTE) */
    if (strstr(n, "_REMOTE_KERNEL_CALLER")) return RowColor::RemoteKernelCaller;
    if (strstr(n, "_REMOTE"))               return RowColor::Remote;
    /* Suspend/resume/freeze/thaw (task 8 or 9) and impersonation */
    if (ev.task == 8 || ev.task == 9 || strstr(n, "IMPERSONATION"))
        return RowColor::Suspicious;
    return RowColor::Default;
}

std::string ImGuiApp::FormatTimestamp(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[16];
    snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%03u",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

std::string ImGuiApp::FormatTimestampFull(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[40];
    snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%03u UTC",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::string BuildProcessJson(const ProcessInfo& info) {
    std::ostringstream out;
    out << "{\"pid\":" << info.pid
        << ",\"found\":" << (info.found ? "true" : "false")
        << ",\"error\":\"" << EscapeJson(info.error) << "\""
        << ",\"image\":\"" << EscapeJson(info.imageName) << "\""
        << ",\"path\":\"" << EscapeJson(info.imagePath) << "\""
        << ",\"commandLine\":\"" << EscapeJson(info.commandLine) << "\""
        << ",\"parent\":";
    if (info.hasParent) {
        out << "{\"pid\":" << info.parentPid
            << ",\"found\":" << (info.parentFound ? "true" : "false")
            << ",\"image\":\"" << EscapeJson(info.parentName) << "\""
            << ",\"path\":\"" << EscapeJson(info.parentPath) << "\"}";
    } else {
        out << "null";
    }
    out << ",\"user\":\"" << EscapeJson(info.user) << "\""
        << ",\"integrity\":\"" << EscapeJson(info.integrity) << "\""
        << ",\"elevated\":" << (info.elevated ? "true" : "false")
        << "}";
    return out.str();
}

std::string ImGuiApp::BuildEventJson(const TiEvent& ev) const {
    char keyword[24];
    snprintf(keyword, sizeof(keyword), "0x%016llX",
             (unsigned long long)ev.keyword);

    std::ostringstream out;
    out << "{\"ts\":\"" << FormatTimestampFull(ev.timestamp) << "\""
        << ",\"id\":"   << ev.eventId
        << ",\"task\":" << ev.task
        << ",\"name\":\"" << EscapeJson(ev.name) << "\""
        << ",\"pid\":"  << ev.pid
        << ",\"tid\":"  << ev.tid
        << ",\"keyword\":\"" << keyword << "\""
        << ",\"fields\":{";
    for (size_t i = 0; i < ev.fields.size(); ++i) {
        if (i > 0) out << ",";
        out << "\"" << EscapeJson(ev.fields[i].first)
            << "\":\"" << EscapeJson(ev.fields[i].second) << "\"";
    }

    out << "},\"processes\":{\"calling\":"
        << BuildProcessJson(m_callingInfo);

    if (m_contextTargetPid != 0) {
        const ProcessInfo& target =
            (m_contextTargetPid == m_contextCallingPid)
                ? m_callingInfo
                : m_targetInfo;
        out << ",\"target\":" << BuildProcessJson(target);
    } else {
        out << ",\"target\":null";
    }

    out << "}}";
    return out.str();
}

/* =========================================================================
 * File logging (JSONL)
 * ========================================================================= */

void ImGuiApp::LogEventToFile(const TiEvent& ev) {
    if (!m_logFile.is_open()) return;

    std::string ts = FormatTimestamp(ev.timestamp);
    m_logFile << "{\"ts\":\"" << ts << "\""
              << ",\"id\":"   << ev.eventId
              << ",\"name\":\"" << EscapeJson(ev.name) << "\""
              << ",\"pid\":"  << ev.pid
              << ",\"tid\":"  << ev.tid
              << ",\"fields\":{";
    for (size_t i = 0; i < ev.fields.size(); ++i) {
        if (i > 0) m_logFile << ",";
        m_logFile << "\"" << EscapeJson(ev.fields[i].first)
                  << "\":\"" << EscapeJson(ev.fields[i].second) << "\"";
    }
    m_logFile << "}}\n";
}

void ImGuiApp::FlushLogIfDue() {
    if (!m_logFile.is_open()) return;
    auto now = std::chrono::steady_clock::now();
    if (now - m_lastFlush >= std::chrono::milliseconds(500)) {
        m_logFile.flush();
        m_lastFlush = now;
    }
}
