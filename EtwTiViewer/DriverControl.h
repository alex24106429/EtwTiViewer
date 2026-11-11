#pragma once
/*
 * DriverControl.h — User-mode IOCTL interface to EtwTiDriver.
 *
 * Opens \\.\EtwTiDriver with CreateFile and wraps the three IOCTLs:
 *   IOCTL_ETWTI_START   — begin ETW session with a keyword mask
 *   IOCTL_ETWTI_STOP    — stop ETW session
 *   IOCTL_ETWTI_STATUS  — query running/eventsPerSec/dropped
 */

#include <Windows.h>
#include "../EtwTiDriver/EtwTiShared.h"

class DriverControl {
public:
    DriverControl();
    ~DriverControl();

    /* (Re-)open the driver handle.  Returns true if the driver is present. */
    bool TryOpen();

    /* Close the driver handle */
    void Close();

    bool IsOpen() const { return m_handle != INVALID_HANDLE_VALUE; }

    /* IOCTL_ETWTI_START — sends keywordMask to driver */
    bool Start(ULONGLONG keywordMask);

    /* IOCTL_ETWTI_STOP */
    bool Stop();

    /* IOCTL_ETWTI_STATUS */
    bool QueryStatus(ETWTI_STATUS_OUTPUT& out);

    /* IOCTL_ETWTI_SET_VERBOSE */
    bool SetVerbose(bool enable);

private:
    HANDLE m_handle;
};
