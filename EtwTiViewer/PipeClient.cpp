/*
 * PipeClient.cpp — Named pipe server implementation.
 *
 * The viewer creates the server instance with CreateNamedPipe, then calls
 * ConnectNamedPipe to wait for the kernel driver to open the write end.
 * Once connected it reads messages in a loop until the pipe breaks.
 */

#include "PipeClient.h"
#include <cstring>

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

void PipeClient::Start() {
    m_stop.store(false, std::memory_order_relaxed);
    m_thread = std::thread(&PipeClient::ThreadProc, this);
}

void PipeClient::Stop() {
    m_stop.store(true, std::memory_order_relaxed);
    if (m_thread.joinable())
        m_thread.join();
}

/* -------------------------------------------------------------------------
 * Thread entry — outer reconnection loop
 * ------------------------------------------------------------------------- */

void PipeClient::ThreadProc() {
    while (!m_stop.load(std::memory_order_relaxed)) {
        m_connected.store(false, std::memory_order_relaxed);
        m_reconnecting.store(true, std::memory_order_relaxed);

        HANDLE hPipe = INVALID_HANDLE_VALUE;
        if (!CreateServerAndWait(hPipe)) {
            /* Pipe creation failed or stop requested; brief back-off */
            for (int i = 0; i < 20 && !m_stop.load(); ++i)
                Sleep(100);
            continue;
        }

        m_connected.store(true, std::memory_order_relaxed);
        m_reconnecting.store(false, std::memory_order_relaxed);

        ReadLoop(hPipe);

        CloseHandle(hPipe);
    }

    m_connected.store(false, std::memory_order_relaxed);
    m_reconnecting.store(false, std::memory_order_relaxed);
}

/* -------------------------------------------------------------------------
 * CreateServerAndWait
 * Creates a new server-side pipe instance and blocks in ConnectNamedPipe
 * until the driver connects (or m_stop fires via a 500 ms poll).
 * Returns true with hPipe set to the connected handle, false on error/stop.
 * ------------------------------------------------------------------------- */

bool PipeClient::CreateServerAndWait(HANDLE& hPipe) {
    hPipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\EtwTiForwarder",
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,                   /* max instances: one driver at a time */
        0,                   /* outbound quota (driver writes to us, we read) */
        PIPE_MAX_MSG_BYTES * 16,  /* inbound buffer */
        0,                   /* default timeout */
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE)
        return false;

    /* Use overlapped ConnectNamedPipe so we can check m_stop periodically */
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
        return false;
    }

    BOOL connected = ConnectNamedPipe(hPipe, &ov);
    if (!connected) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            /* Poll until connected or stop requested */
            while (!m_stop.load(std::memory_order_relaxed)) {
                DWORD wait = WaitForSingleObject(ov.hEvent, 500);
                if (wait == WAIT_OBJECT_0) {
                    DWORD dummy;
                    if (GetOverlappedResult(hPipe, &ov, &dummy, FALSE)) {
                        connected = TRUE;
                    }
                    break;
                }
            }
        } else if (err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;  /* driver was already waiting */
        }
    }

    CloseHandle(ov.hEvent);

    if (!connected || m_stop.load(std::memory_order_relaxed)) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
        return false;
    }

    return true;
}

/* -------------------------------------------------------------------------
 * ReadLoop — overlapped reads until pipe breaks or stop requested
 * ------------------------------------------------------------------------- */

void PipeClient::ReadLoop(HANDLE pipe) {
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return;

    std::vector<uint8_t> buf(PIPE_MAX_MSG_BYTES);

    while (!m_stop.load(std::memory_order_relaxed)) {
        DWORD bytesRead = 0;
        ResetEvent(ov.hEvent);

        BOOL ok = ReadFile(pipe, buf.data(), static_cast<DWORD>(buf.size()),
                           &bytesRead, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD wait = WaitForSingleObject(ov.hEvent, 200);
                if (wait == WAIT_TIMEOUT) continue;
                if (wait != WAIT_OBJECT_0) break;
                if (!GetOverlappedResult(pipe, &ov, &bytesRead, FALSE)) break;
            } else if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                break;
            } else {
                break;
            }
        }

        if (bytesRead < sizeof(PIPE_EVENT_HEADER)) continue;

        const PIPE_EVENT_HEADER* hdr =
            reinterpret_cast<const PIPE_EVENT_HEADER*>(buf.data());

        if (hdr->Magic != PIPE_EVENT_MAGIC) continue;

        size_t expected = sizeof(PIPE_EVENT_HEADER) + hdr->NameLen + hdr->FieldsLen;
        if (bytesRead < expected) continue;

        const uint8_t* nameBytes  = buf.data() + sizeof(PIPE_EVENT_HEADER);
        const uint8_t* fieldBytes = nameBytes + hdr->NameLen;

        m_cb(ParseMessage(*hdr, nameBytes, fieldBytes));
    }

    CloseHandle(ov.hEvent);
}

/* -------------------------------------------------------------------------
 * ParseMessage
 * ------------------------------------------------------------------------- */

TiEvent PipeClient::ParseMessage(
    const PIPE_EVENT_HEADER& hdr,
    const uint8_t*           nameBytes,
    const uint8_t*           fieldBytes)
{
    TiEvent ev;
    ev.timestamp.dwLowDateTime  = static_cast<DWORD>(hdr.Timestamp & 0xFFFFFFFF);
    ev.timestamp.dwHighDateTime = static_cast<DWORD>(hdr.Timestamp >> 32);
    ev.eventId = hdr.EventId;
    ev.task    = hdr.Task;
    ev.keyword = hdr.Keyword;
    ev.pid     = hdr.Pid;
    ev.tid     = hdr.Tid;
    ev.name.assign(reinterpret_cast<const char*>(nameBytes), hdr.NameLen);

    const char* p   = reinterpret_cast<const char*>(fieldBytes);
    const char* end = p + hdr.FieldsLen;
    while (p < end) {
        const char* nul = static_cast<const char*>(
            memchr(p, '\0', static_cast<size_t>(end - p)));
        if (!nul) nul = end;
        std::string pair(p, nul);
        if (!pair.empty()) {
            size_t eq = pair.find('=');
            if (eq != std::string::npos)
                ev.fields.emplace_back(pair.substr(0, eq), pair.substr(eq + 1));
            else
                ev.fields.emplace_back(pair, std::string{});
        }
        p = nul + 1;
    }
    return ev;
}
