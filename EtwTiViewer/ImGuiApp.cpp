/*
 * ImGuiApp.cpp — Single-window ImGui UI implementation.
 *
 * Layout: one fullscreen ImGui window (no docking, no floating panels).
 * Toolbar at top, keyword child (260px) + event table child side by side.
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

/* =========================================================================
 * Constructor / destructor
 * ========================================================================= */

ImGuiApp::ImGuiApp()
    : m_evBuf(50000)
    , m_lastFlush(std::chrono::steady_clock::now())
{
    for (auto& k : kKeywords)
        m_keywords.push_back({ k.mask, k.name, true });
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

    /* ---- Side-by-side children ---- */
    /* Left: keyword panel (fixed 260 px, full remaining height) */
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, {4.0f, 3.0f});
    if (ImGui::BeginChild("##keywords", {260.0f, 0.0f}, true,
                          ImGuiWindowFlags_NoScrollbar)) {
        RenderKeywordsContent();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();

    ImGui::SameLine(0.0f, 4.0f);

    /* Right: event table (fill remaining width and height) */
    if (ImGui::BeginChild("##events", {0.0f, 0.0f}, false)) {
        RenderEventTable();
    }
    ImGui::EndChild();

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

    if (ImGui::Button("Clear")) m_evBuf.Clear();
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
    if (!ImGui::BeginTable("EventTable", 6, kTableFlags, tableSize))
        return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Timestamp", ImGuiTableColumnFlags_WidthFixed,    90.0f);
    ImGui::TableSetupColumn("ID",        ImGuiTableColumnFlags_WidthFixed,    38.0f);
    ImGui::TableSetupColumn("Name",      ImGuiTableColumnFlags_WidthStretch,  0.25f);
    ImGui::TableSetupColumn("PID",       ImGuiTableColumnFlags_WidthFixed,    52.0f);
    ImGui::TableSetupColumn("TID",       ImGuiTableColumnFlags_WidthFixed,    52.0f);
    ImGui::TableSetupColumn("Fields",    ImGuiTableColumnFlags_WidthStretch,  0.75f);
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

        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(FormatTimestamp(ev.timestamp).c_str());

        ImGui::TableSetColumnIndex(1);
        ImGui::Text("%u", (unsigned)ev.eventId);

        ImGui::TableSetColumnIndex(2);
        ImGui::TextUnformatted(ev.name.c_str());

        ImGui::TableSetColumnIndex(3);
        ImGui::Text("%u", ev.pid);

        ImGui::TableSetColumnIndex(4);
        ImGui::Text("%u", ev.tid);

        ImGui::TableSetColumnIndex(5);
        ImGui::TextUnformatted(FormatFields(ev, 140).c_str());
    }

    if (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f)
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndTable();
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

std::string ImGuiApp::FormatFields(const TiEvent& ev, size_t maxChars) {
    std::string out;
    for (size_t i = 0; i < ev.fields.size(); ++i) {
        if (i > 0) out += ", ";
        out += ev.fields[i].first + "=" + ev.fields[i].second;
        if (out.size() >= maxChars) {
            out.resize(maxChars);
            out += "...";
            break;
        }
    }
    return out;
}

/* =========================================================================
 * File logging (JSONL)
 * ========================================================================= */

void ImGuiApp::LogEventToFile(const TiEvent& ev) {
    if (!m_logFile.is_open()) return;

    auto escape = [](const std::string& s) {
        std::string r;
        for (char c : s) {
            if      (c == '"')  r += "\\\"";
            else if (c == '\\') r += "\\\\";
            else                r += c;
        }
        return r;
    };

    std::string ts = FormatTimestamp(ev.timestamp);
    m_logFile << "{\"ts\":\"" << ts << "\""
              << ",\"id\":"   << ev.eventId
              << ",\"name\":\"" << escape(ev.name) << "\""
              << ",\"pid\":"  << ev.pid
              << ",\"tid\":"  << ev.tid
              << ",\"fields\":{";
    for (size_t i = 0; i < ev.fields.size(); ++i) {
        if (i > 0) m_logFile << ",";
        m_logFile << "\"" << escape(ev.fields[i].first)
                  << "\":\"" << escape(ev.fields[i].second) << "\"";
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
