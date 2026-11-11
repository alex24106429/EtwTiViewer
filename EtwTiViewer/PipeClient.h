#pragma once
/*
 * PipeClient.h — Named pipe server that the kernel driver connects to as a
 * write client.  The viewer owns the server side (PIPE_ACCESS_INBOUND) and
 * reads events; the driver opens the pipe with ZwCreateFile(GENERIC_WRITE).
 *
 * Architecture:
 *   Viewer  → CreateNamedPipe  → waits for driver (ConnectNamedPipe)
 *   Driver  → ZwCreateFile     → connects and writes events
 *   Viewer  → ReadFile loop    → parses PipeEventHeader + payload → TiEvent
 *
 * On pipe break the viewer recreates the server instance and waits again.
 * The UI sees IsConnected() / IsReconnecting() for status badges.
 */

#include <Windows.h>
#include <atomic>
#include <thread>
#include <functional>
#include <vector>
#include "EventBuffer.h"
#include "../EtwTiDriver/EtwTiShared.h"

class PipeClient {
public:
    using EventCallback = std::function<void(TiEvent&&)>;

    explicit PipeClient(EventCallback cb)
        : m_cb(std::move(cb))
        , m_connected(false)
        , m_reconnecting(false)
        , m_stop(false)
    {}

    ~PipeClient() { Stop(); }

    void Start();
    void Stop();

    bool IsConnected()    const { return m_connected.load(std::memory_order_relaxed); }
    bool IsReconnecting() const { return m_reconnecting.load(std::memory_order_relaxed); }

private:
    void ThreadProc();
    bool CreateServerAndWait(HANDLE& hPipe);
    void ReadLoop(HANDLE pipe);
    static TiEvent ParseMessage(const PIPE_EVENT_HEADER& hdr,
                                const uint8_t* nameBytes,
                                const uint8_t* fieldBytes);

    EventCallback     m_cb;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_reconnecting;
    std::atomic<bool> m_stop;
    std::thread       m_thread;
};
