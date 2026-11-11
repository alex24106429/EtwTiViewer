/*
 * DriverControl.cpp
 */

#include "DriverControl.h"
#include <cstring>

DriverControl::DriverControl() : m_handle(INVALID_HANDLE_VALUE) {}

DriverControl::~DriverControl() { Close(); }

bool DriverControl::TryOpen() {
    if (m_handle != INVALID_HANDLE_VALUE)
        return true;

    m_handle = CreateFileW(
        ETWTI_USER_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    return m_handle != INVALID_HANDLE_VALUE;
}

void DriverControl::Close() {
    if (m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
}

bool DriverControl::Start(ULONGLONG keywordMask) {
    if (m_handle == INVALID_HANDLE_VALUE)
        return false;

    ETWTI_START_INPUT in;
    in.KeywordMask = keywordMask;

    DWORD bytesRet = 0;
    return DeviceIoControl(m_handle,
                           IOCTL_ETWTI_START,
                           &in, sizeof(in),
                           nullptr, 0,
                           &bytesRet, nullptr) != FALSE;
}

bool DriverControl::Stop() {
    if (m_handle == INVALID_HANDLE_VALUE)
        return false;

    DWORD bytesRet = 0;
    return DeviceIoControl(m_handle,
                           IOCTL_ETWTI_STOP,
                           nullptr, 0,
                           nullptr, 0,
                           &bytesRet, nullptr) != FALSE;
}

bool DriverControl::SetVerbose(bool enable) {
    if (m_handle == INVALID_HANDLE_VALUE)
        return false;

    ULONG flag = enable ? 1u : 0u;
    DWORD bytesRet = 0;
    return DeviceIoControl(m_handle,
                           IOCTL_ETWTI_SET_VERBOSE,
                           &flag, sizeof(flag),
                           nullptr, 0,
                           &bytesRet, nullptr) != FALSE;
}

bool DriverControl::QueryStatus(ETWTI_STATUS_OUTPUT& out) {
    if (m_handle == INVALID_HANDLE_VALUE)
        return false;

    DWORD bytesRet = 0;
    return DeviceIoControl(m_handle,
                           IOCTL_ETWTI_STATUS,
                           nullptr, 0,
                           &out, sizeof(out),
                           &bytesRet, nullptr) != FALSE
           && bytesRet >= sizeof(out);
}
