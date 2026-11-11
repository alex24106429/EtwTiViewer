/*
 * EtwTiDriver.h  —  Internal driver declarations (not shared with user-mode)
 */

#pragma once

/*
 * ntifs.h is a superset of ntddk.h and wdm.h — it includes everything they
 * provide plus file-system and named-pipe APIs (ZwCreateNamedPipeFile,
 * FSCTL_PIPE_LISTEN, etc.).  Including ntddk.h or wdm.h alongside ntifs.h
 * causes PEPROCESS/PETHREAD redefinition errors; include only ntifs.h.
 */
#include <ntifs.h>
#include <ntstrsafe.h>
#include "EtwTiShared.h"

/* -------------------------------------------------------------------------
 * ETW-TI provider GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
 * Defined as a plain const in EtwTiDriver.c to avoid needing INITGUID.
 * ------------------------------------------------------------------------- */
extern const GUID GUID_EtwTiProvider;

/* -------------------------------------------------------------------------
 * Kernel ETW registration handle (returned by EtwRegister)
 * ------------------------------------------------------------------------- */
extern REGHANDLE g_EtwRegHandle;

/* -------------------------------------------------------------------------
 * Driver global state
 * ------------------------------------------------------------------------- */
typedef struct _DRIVER_STATE {
    /* Synchronises all state mutations */
    KSPIN_LOCK       Lock;

    /* ETW session is active */
    BOOLEAN          SessionActive;

    /* Current keyword mask */
    ULONGLONG        KeywordMask;

    /* Control device object + symbolic link created */
    PDEVICE_OBJECT   ControlDevice;
    BOOLEAN          SymlinkCreated;

    /* PS notify callbacks are currently registered */
    BOOLEAN          CallbacksRegistered;

    /* Reserved padding */
    BOOLEAN          _pad[3];

    /* Pipe I/O */
    HANDLE           PipeHandle;
    PFILE_OBJECT     PipeFileObject;
    BOOLEAN          PipeConnected;

    /* Statistics (updated with InterlockedIncrement, read with KeMemoryBarrier) */
    volatile LONG    EventCount;        /* total since session start */
    volatile LONG    DroppedCount;      /* dropped: pipe full / error */
    volatile LONG    EventsThisSec;     /* accumulator for rate calc  */
    volatile LONG    EventsPerSec;      /* snapshotted each second    */

    /* 1-second stats timer */
    KTIMER           StatsTimer;
    KDPC             StatsDpc;

    /* Worker thread for pipe connection / reconnection */
    HANDLE           WorkerThread;
    KEVENT           WorkerStopEvent;

} DRIVER_STATE, *PDRIVER_STATE;

extern DRIVER_STATE g_State;

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */

/* Dispatch routines */
DRIVER_DISPATCH DispatchCreate;
DRIVER_DISPATCH DispatchClose;
DRIVER_DISPATCH DispatchIoControl;
DRIVER_UNLOAD   DriverUnloadRoutine;

/* Pipe helpers */
NTSTATUS PipeCreate(void);
void     PipeDestroy(void);
NTSTATUS PipeWriteEvent(PPIPE_EVENT_HEADER pHdr, const UCHAR *pName,
                        const UCHAR *pFields);

/* ETW helpers */
NTSTATUS EtwSessionStart(ULONGLONG keywordMask);
void     EtwSessionStop(void);

/* Callback teardown (idempotent, safe to call from IOCTL or DriverUnload) */
void     CallbacksRemove(void);

/* Verbose per-event KdPrintEx flag — toggled by IOCTL_ETWTI_SET_VERBOSE */
extern volatile BOOLEAN g_VerboseDebug;

/*
 * Kernel ETW callback — called by the kernel ETW infrastructure when an
 * event matching our subscription arrives.  Signature matches
 * PENABLECALLBACK (EtwEnableCallback).
 */
VOID NTAPI EtwEnableCallback(
    _In_     LPCGUID                  SourceId,
    _In_     ULONG                    IsEnabled,
    _In_     UCHAR                    Level,
    _In_     ULONGLONG                MatchAnyKeyword,
    _In_     ULONGLONG                MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID                    CallbackContext);

/* Stats DPC */
KDEFERRED_ROUTINE StatsDpcRoutine;

/* Worker thread entry */
KSTART_ROUTINE PipeWorkerThread;

/*
 * Fallback kernel notification callbacks.
 * These fire without ELAM and provide process/image telemetry
 * even when the ETW-TI subscription is denied.
 */
VOID FallbackProcessNotify(
    _Inout_ PEPROCESS              Process,
    _In_    HANDLE                 ProcessId,
    _In_    PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID FallbackImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo);
