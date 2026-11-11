/*
 * main.cpp — WinMain entry point for EtwTiViewer.
 *
 * Creates a DirectX 11 device and swap chain, initialises ImGui,
 * and runs the standard message + render loop.
 *
 * The application must run as Administrator so it can:
 *   (a) open \\.\EtwTiDriver with CreateFile (kernel driver device),
 *   (b) call DeviceIoControl to start/stop the ETW session.
 *
 * The embedded manifest deliberately requests asInvoker instead of
 * requireAdministrator: elevation is performed at runtime by
 * EnsureElevated() below.  This is required because the UAC elevation
 * broker cannot resolve images that live on filesystems which are not
 * registered with the mount manager (VirtioFS/WinFsp shared folders and
 * some network drives).  ShellExecuteEx(..., "runas") on such an image
 * fails with ERROR_UNRECOGNIZED_VOLUME before the process ever starts.
 */

#include <Windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <shellapi.h>
#include <tchar.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "resource.h"
#include "ImGuiApp.h"
#include "Headless.h"
#include "../third_party/imgui/backends/imgui_impl_win32.h"
#include "../third_party/imgui/backends/imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

/* Forward declaration of ImGui Win32 message proc helper */
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

/* =========================================================================
 * DirectX 11 globals
 * ========================================================================= */

static ID3D11Device*            g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext    = nullptr;
static IDXGISwapChain*          g_pSwapChain           = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static UINT                     g_ResizeWidth          = 0;
static UINT                     g_ResizeHeight         = 0;

static ImGuiApp*                g_App                  = nullptr;

/* =========================================================================
 * D3D11 helpers
 * ========================================================================= */

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Width                   = 0;
    sd.BufferDesc.Height                  = 0;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = hWnd;
    sd.SampleDesc.Count                   = 1;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
#ifdef _DEBUG
    createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[] = {
        D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0
    };

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createDeviceFlags,
        featureLevelArray, 2,
        D3D11_SDK_VERSION,
        &sd,
        &g_pSwapChain,
        &g_pd3dDevice,
        &featureLevel,
        &g_pd3dDeviceContext);

    if (res == DXGI_ERROR_UNSUPPORTED) {
        /* Fallback to WARP software renderer */
        res = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            createDeviceFlags,
            featureLevelArray, 2,
            D3D11_SDK_VERSION, &sd,
            &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    }
    if (FAILED(res)) return false;

    /* Create render target view */
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
    return true;
}

static void CleanupDeviceD3D() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain)           { g_pSwapChain->Release();           g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext)    { g_pd3dDeviceContext->Release();     g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)           { g_pd3dDevice->Release();           g_pd3dDevice = nullptr; }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

/* =========================================================================
 * Window procedure
 * ========================================================================= */

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return TRUE;

    switch (msg) {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            g_ResizeWidth  = LOWORD(lParam);
            g_ResizeHeight = HIWORD(lParam);
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_KEYMENU) return 0; /* suppress Alt menu */
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

/* =========================================================================
 * Runtime elevation
 *
 * The manifest is asInvoker so that the image can at least be loaded from a
 * VirtioFS/WinFsp drive.  We then relaunch ourselves through the "runas"
 * verb.  If the elevation broker rejects the image because the volume is not
 * known to the mount manager (ERROR_UNRECOGNIZED_VOLUME), a copy is staged in
 * the local %TEMP% directory and that copy is elevated instead.
 * ========================================================================= */

static bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation = {};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation,
                                        &elevation, sizeof(elevation),
                                        &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

static std::wstring GetModulePath() {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD len = GetModuleFileNameW(nullptr, buffer.data(),
                                             static_cast<DWORD>(buffer.size()));
        if (len == 0)
            return {};
        if (len < buffer.size())
            return std::wstring(buffer.data(), len);
        buffer.resize(buffer.size() * 2);
    }
}

/* Command line with the executable name (first token) removed. */
static std::wstring GetArgsAfterImage() {
    const wchar_t* p = GetCommandLineW();
    if (p == nullptr)
        return {};

    while (*p == L' ' || *p == L'\t')
        ++p;

    if (*p == L'"') {
        ++p;
        while (*p != L'\0' && *p != L'"')
            ++p;
        if (*p == L'"')
            ++p;
    } else {
        while (*p != L'\0' && *p != L' ' && *p != L'\t')
            ++p;
    }

    while (*p == L' ' || *p == L'\t')
        ++p;

    return p;
}

static std::wstring GetCurrentDir() {
    DWORD len = GetCurrentDirectoryW(0, nullptr);
    if (len == 0)
        return {};

    std::vector<wchar_t> buffer(len);
    len = GetCurrentDirectoryW(len, buffer.data());
    if (len == 0)
        return {};

    return std::wstring(buffer.data(), len);
}

/*
 * Starts `file` elevated and waits for it.  Returns ERROR_SUCCESS when the
 * process was started, otherwise the ShellExecuteEx error code.
 */
static DWORD RunElevated(const std::wstring& file, const std::wstring& args,
                         const std::wstring& cwd, int& exitCode) {
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC |
                       SEE_MASK_FLAG_NO_UI;
    sei.lpVerb       = L"runas";
    sei.lpFile       = file.c_str();
    sei.lpParameters = args.empty() ? nullptr : args.c_str();
    sei.lpDirectory  = cwd.empty() ? nullptr : cwd.c_str();
    sei.nShow        = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei))
        return GetLastError();

    exitCode = 0;
    if (sei.hProcess != nullptr) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD code = 0;
        if (GetExitCodeProcess(sei.hProcess, &code))
            exitCode = static_cast<int>(code);
        CloseHandle(sei.hProcess);
    }
    return ERROR_SUCCESS;
}

/*
 * Copies the executable to %TEMP%\EtwTiViewer\run-<id>\EtwTiViewer.exe.
 * A per-launch subdirectory keeps the canonical image name (so Task Manager
 * and the window still say "EtwTiViewer.exe") without collisions when
 * several instances are running.
 */
static bool StageLocalCopy(const std::wstring& source, std::wstring& staged) {
    WCHAR tempDir[MAX_PATH] = {};
    const DWORD tempLen = GetTempPathW(ARRAYSIZE(tempDir), tempDir);
    if (tempLen == 0 || tempLen >= ARRAYSIZE(tempDir))
        return false;

    std::wstring root = tempDir;
    if (!root.empty() && root.back() != L'\\')
        root += L'\\';
    root += L"EtwTiViewer";

    if (!CreateDirectoryW(root.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS)
        return false;

    WCHAR unique[64] = {};
    swprintf_s(unique, L"\\run-%lu-%llu",
               static_cast<unsigned long>(GetCurrentProcessId()),
               static_cast<unsigned long long>(GetTickCount64()));

    const std::wstring dir = root + unique;
    if (!CreateDirectoryW(dir.c_str(), nullptr))
        return false;

    staged = dir + L"\\EtwTiViewer.exe";
    if (!CopyFileW(source.c_str(), staged.c_str(), FALSE))
        return false;

    /* Best-effort cleanup of stale copies left behind by crashed launches.
     * Only directories older than an hour are considered, so that a
     * concurrent launch cannot delete another instance's fresh copy.  A copy
     * that is still running cannot be deleted and stays anyway. */
    FILETIME nowFt = {};
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now = {};
    now.LowPart  = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    const ULONGLONG kMaxAge = 60ULL * 60ULL * 10000000ULL;  /* 1 hour */

    WIN32_FIND_DATAW fd = {};
    HANDLE find = FindFirstFileW((root + L"\\run-*").c_str(), &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                continue;
            const std::wstring oldDir = root + L"\\" + fd.cFileName;
            if (oldDir == dir)
                continue;
            ULARGE_INTEGER written = {};
            written.LowPart  = fd.ftLastWriteTime.dwLowDateTime;
            written.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            if (now.QuadPart - written.QuadPart < kMaxAge)
                continue;
            DeleteFileW((oldDir + L"\\EtwTiViewer.exe").c_str());
            RemoveDirectoryW(oldDir.c_str());
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }

    return true;
}

static void ShowElevationError(DWORD error, const std::wstring& file) {
    wchar_t* systemText = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, error, 0,
                   reinterpret_cast<LPWSTR>(&systemText), 0, nullptr);

    std::wstring text =
        L"EtwTiViewer could not start with administrator rights.\n\n";
    if (!file.empty()) {
        text += L"Image: ";
        text += file;
        text += L"\n\n";
    }
    if (systemText != nullptr) {
        text += systemText;
        LocalFree(systemText);
        while (!text.empty() &&
               (text.back() == L'\n' || text.back() == L'\r'))
            text.pop_back();
        text += L"\n\n";
    }
    text += L"If the executable is on a network or shared-folder drive, "
            L"copy it to a local disk and run it from there.";

    MessageBoxW(nullptr, text.c_str(), L"EtwTiViewer",
                MB_OK | MB_ICONERROR);
}

/*
 * Returns true when this process should continue (already elevated).
 * Returns false with `exitCode` set when the elevated instance was started
 * (or elevation failed), in which case WinMain must return immediately.
 */
static bool EnsureElevated(int& exitCode) {
    if (IsProcessElevated())
        return true;

    const std::wstring image = GetModulePath();
    if (image.empty()) {
        ShowElevationError(GetLastError(), image);
        exitCode = 1;
        return false;
    }

    std::wstring args = GetArgsAfterImage();

    /* Safety net: never spin if a relaunch comes back non-elevated. */
    if (args.find(L"--no-elevate") != std::wstring::npos)
        return true;
    args += L" --no-elevate";

    const std::wstring cwd = GetCurrentDir();

    DWORD result = RunElevated(image, args, cwd, exitCode);
    if (result == ERROR_SUCCESS)
        return false;

    if (result == ERROR_CANCELLED) {   /* user declined the UAC prompt */
        exitCode = 1;
        return false;
    }

    if (result == ERROR_UNRECOGNIZED_VOLUME) {
        /* The elevation broker resolves the image through the mount manager;
         * VirtioFS/WinFsp drives are not registered there.  Use a local copy. */
        std::wstring staged;
        if (StageLocalCopy(image, staged)) {
            result = RunElevated(staged, args, cwd, exitCode);
            if (result == ERROR_SUCCESS)
                return false;
            if (result == ERROR_CANCELLED) {
                exitCode = 1;
                return false;
            }
        }
    }

    ShowElevationError(result, image);
    exitCode = 1;
    return false;
}

/* =========================================================================
 * WinMain
 * ========================================================================= */

int WINAPI WinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_     LPSTR     lpCmdLine,
    _In_     int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    /* ---------------------------------------------------------------------
     * Optional headless/automation mode:
     *
     *   EtwTiViewer.exe --capture 30 --log out.jsonl [--keywords 0x...]
     *                   [--session 0MyThreatIntelTrace] [--max-events N]
     *
     * Uses exactly the same EtwConsumer/SecurityTrace path as the GUI and
     * needs no DirectX, so it can run in CI or an RDP-less VM.
     * ------------------------------------------------------------------- */
    HeadlessOptions headless;
    bool            runHeadless = false;
    bool            showHelp    = false;

    {
        int      argc = 0;
        LPWSTR*  argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        if (argv != nullptr)
        {
            for (int i = 1; i < argc; ++i)
            {
                const wchar_t* arg = argv[i];
                const bool hasValue = (i + 1) < argc;

                if (_wcsicmp(arg, L"--capture") == 0 && hasValue)
                {
                    headless.seconds = _wtoi(argv[++i]);
                    runHeadless = true;
                }
                else if (_wcsicmp(arg, L"--log") == 0 && hasValue)
                {
                    headless.logPath = argv[++i];
                }
                else if (_wcsicmp(arg, L"--keywords") == 0 && hasValue)
                {
                    headless.keywordMask = _wcstoui64(argv[++i], nullptr, 0);
                }
                else if (_wcsicmp(arg, L"--session") == 0 && hasValue)
                {
                    headless.sessionName = argv[++i];
                    SetEnvironmentVariableW(L"ETWTI_TRACE_NAME",
                                            headless.sessionName.c_str());
                }
                else if (_wcsicmp(arg, L"--autostart") == 0)
                {
                    SetEnvironmentVariableW(L"ETWTI_AUTOSTART", L"1");
                }
                else if (_wcsicmp(arg, L"--max-events") == 0 && hasValue)
                {
                    headless.maxEvents = _wcstoui64(argv[++i], nullptr, 10);
                }
                else if (_wcsicmp(arg, L"--cycles") == 0 && hasValue)
                {
                    headless.cycles = _wtoi(argv[++i]);
                    if (headless.cycles < 1)
                        headless.cycles = 1;
                }
                else if (_wcsicmp(arg, L"--help") == 0 ||
                         _wcsicmp(arg, L"-h") == 0)
                {
                    showHelp = true;
                }
            }

            LocalFree(argv);
        }
    }

    /* --help is answered before elevation so it also works for users who
     * cannot elevate (and from drives the UAC broker cannot resolve). */
    if (showHelp)
    {
        MessageBoxW(nullptr,
            L"EtwTiViewer — Microsoft-Windows-Threat-Intelligence viewer\n\n"
            L"GUI mode:\n"
            L"  EtwTiViewer.exe\n\n"
            L"Headless capture mode:\n"
            L"  EtwTiViewer.exe --capture <seconds> [--log <file.jsonl>]\n"
            L"                  [--keywords 0x<mask>]\n"
            L"                  [--session <AutoLogger name>]\n"
            L"                  [--max-events <n>] [--cycles <n>]\n\n"
            L"GUI automation:\n"
            L"  EtwTiViewer.exe --autostart\n\n"
            L"One-time setup (elevated):\n"
            L"  install_autologger.ps1   then reboot\n\n"
            L"No PPL, driver or kernel patch is required.",
            L"EtwTiViewer", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    /* ---------------------------------------------------------------------
     * Elevate now (the manifest is asInvoker on purpose — see the comment at
     * the top of this file).  EnsureElevated() either returns true because we
     * already have administrator rights, or starts the elevated instance and
     * tells us to exit.
     * ------------------------------------------------------------------- */
    {
        int exitCode = 0;
        if (!EnsureElevated(exitCode))
            return exitCode;
    }

    if (runHeadless)
        return RunHeadless(headless);

    /* ---- Register window class ---- */
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPICON));
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"EtwTiViewerClass";
    RegisterClassExW(&wc);

    /* ---- Create window ---- */
    HWND hwnd = CreateWindowW(
        wc.lpszClassName,
        L"EtwTi Viewer  —  Microsoft-Windows-Threat-Intelligence",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1440, 900,
        nullptr, nullptr, hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, hInstance);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    /* ---- Create and initialise application ---- */
    g_App = new ImGuiApp();
    g_App->Init(g_pd3dDevice, g_pd3dDeviceContext, hwnd);

    /* ---- Message loop ---- */
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            continue;
        }

        /* Handle resize */
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            UINT newW = g_ResizeWidth, newH = g_ResizeHeight;
            g_pSwapChain->ResizeBuffers(0, newW, newH, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
            g_App->OnResize(newW, newH);
        }

        /* Clear frame */
        const float clearColor[] = { 0.10f, 0.10f, 0.10f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);

        g_App->Render();

        g_pSwapChain->Present(1, 0); /* vsync */
    }

    /* ---- Cleanup ---- */
    delete g_App;
    g_App = nullptr;

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInstance);

    return 0;
}
