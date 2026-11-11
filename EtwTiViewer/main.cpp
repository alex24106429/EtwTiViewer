/*
 * main.cpp — WinMain entry point for EtwTiViewer.
 *
 * Creates a DirectX 11 device and swap chain, initialises ImGui,
 * and runs the standard message + render loop.
 *
 * The application must run as Administrator so it can:
 *   (a) open \\.\EtwTiDriver with CreateFile (kernel driver device),
 *   (b) call DeviceIoControl to start/stop the ETW session.
 */

#include <Windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <shellapi.h>
#include <tchar.h>
#include <cstdio>
#include <cstdlib>

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
    {
        int      argc = 0;
        LPWSTR*  argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        if (argv != nullptr)
        {
            HeadlessOptions headless;
            bool            runHeadless = false;
            bool            showHelp    = false;

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

            if (runHeadless)
            {
                return RunHeadless(headless);
            }
        }
    }

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
