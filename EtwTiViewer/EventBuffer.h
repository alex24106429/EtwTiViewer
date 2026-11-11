#pragma once
/*
 * EventBuffer.h — Thread-safe circular ring buffer for TiEvent objects.
 *
 * Capacity is fixed at construction.  When full, the oldest entry is
 * overwritten (tail advances with head).  All operations are O(1).
 *
 * Locking: a single std::mutex guards head/tail; producers call Push(),
 * the render thread reads via a snapshot copy or direct iteration under
 * the lock.
 */

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <Windows.h>

/* Decoded event from the pipe */
struct TiEvent {
    FILETIME    timestamp;
    uint16_t    eventId;
    uint16_t    task;     /* EVENT_DESCRIPTOR.Task  — operation category (1=ALLOCVM, 2=PROTECTVM, …) */
    uint64_t    keyword;  /* EVENT_DESCRIPTOR.Keyword bitmask — LOCAL/REMOTE/KERNEL_CALLER variant   */
    uint32_t    pid;
    uint32_t    tid;
    std::string name;
    /* Parsed key=value pairs from the fields blob */
    std::vector<std::pair<std::string, std::string>> fields;
};

class EventBuffer {
public:
    explicit EventBuffer(size_t capacity)
        : m_capacity(capacity), m_buf(capacity), m_head(0), m_tail(0), m_size(0)
    {}

    /* Push a new event; drops oldest if full */
    void Push(TiEvent&& ev) {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_buf[m_head] = std::move(ev);
        m_head = (m_head + 1) % m_capacity;
        if (m_size < m_capacity) {
            ++m_size;
        } else {
            /* Overwrite oldest: advance tail */
            m_tail = (m_tail + 1) % m_capacity;
        }
    }

    /*
     * Snapshot the current contents into a vector (oldest first).
     * Caller receives a copy so it can iterate without holding the lock.
     * maxRows = 0 means "all".
     */
    std::vector<TiEvent> Snapshot(size_t maxRows = 0) const {
        std::lock_guard<std::mutex> lk(m_mutex);
        size_t count = (maxRows > 0 && maxRows < m_size) ? maxRows : m_size;

        std::vector<TiEvent> out;
        out.reserve(count);

        /* Start from the newest - count events so we show the last N */
        size_t start = (m_head + m_capacity - count) % m_capacity;
        for (size_t i = 0; i < count; ++i) {
            out.push_back(m_buf[(start + i) % m_capacity]);
        }
        return out;
    }

    size_t Size() const {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_size;
    }

    void Clear() {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_head = m_tail = m_size = 0;
    }

private:
    size_t                  m_capacity;
    std::vector<TiEvent>    m_buf;
    size_t                  m_head;     /* next write position */
    size_t                  m_tail;     /* oldest entry position */
    size_t                  m_size;
    mutable std::mutex      m_mutex;
};
