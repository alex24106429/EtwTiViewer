/*
 * EtwTiDriver.c  —  WDM kernel driver that subscribes to the
 * Microsoft-Windows-Threat-Intelligence ETW provider and forwards
 * decoded events to a user-mode ImGui viewer via a named pipe.
 *
 * ARCHITECTURE
 * ============
 * ETW-TI is a Secure ETW (Analytic) provider.  The kernel's ETW access
 * check evaluates the EPROCESS->Protection field of the *calling* process
 * when EtwRegister is invoked.  Because we want that check to run against
 * EtwTiViewer.exe (which can be patched in WinDbg) rather than the System
 * process, EtwRegister is deferred to the IOCTL_ETWTI_START handler.
 *
 * ENABLING KERNEL DEBUG OUTPUT
 * ============================
 * All prints use DbgPrintEx with DPFLTR_IHVDRIVER_ID.  To enable them from
 * WinDbg without recompiling:
 *
 *   kd> ed nt!Kd_IHVDRIVER_Mask 0xFFFFFFFF
 *
 * After that every [EtwTi] message appears in the WinDbg output window.
 * Filter with:  kd> .logopen C:\etwtrace.txt   then grep for "[EtwTi]".
 *
 * KNOWN LIMITATION
 * ================
 * Without an ELAM certificate, EtwRegister on the ETW-TI GUID succeeds
 * but the callback may never fire (STATUS_ACCESS_DENIED at session setup).
 * Workaround: patch EtwTiViewer.exe's EPROCESS->Protection to 0x31 before
 * sending IOCTL_ETWTI_START — see the comment above that IOCTL handler.
 */

#include "EtwTiDriver.h"

/* =========================================================================
 * Globals
 * ========================================================================= */

DRIVER_STATE       g_State;
REGHANDLE          g_EtwRegHandle  = (REGHANDLE)0;
volatile BOOLEAN   g_VerboseDebug  = FALSE;

/* Pool tag for all allocations in this driver */
#define POOL_TAG 'iTwE'

/*
 * ETWTRACE uses DbgPrintEx (not KdPrintEx) so that prints survive in
 * Release builds.  KdPrintEx expands to nothing when DBG==0 (free build);
 * DbgPrintEx always links against the kernel export and is only gated by
 * the runtime component filter mask set with:
 *   kd> ed nt!Kd_IHVDRIVER_Mask 0xFFFFFFFF
 */
#define ETWTRACE(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EtwTi] " fmt, ##__VA_ARGS__)

/*_
 * ETW-TI provider GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
 * Defined as a plain const so no INITGUID dance is needed.
 */
const GUID GUID_EtwTiProvider = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

/* =========================================================================
 * DriverEntry
 * ========================================================================= */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS         status;
    UNICODE_STRING   devName, linkName;
    PDEVICE_OBJECT   devObj = NULL;
    LARGE_INTEGER    dueTime;
    HANDLE           hThread;

    UNREFERENCED_PARAMETER(RegistryPath);

    ETWTRACE("DriverEntry start\n");

    /* Zero global state before touching any fields */
    RtlZeroMemory(&g_State, sizeof(g_State));
    KeInitializeSpinLock(&g_State.Lock);

    /* -----------------------------------------------------------------------
     * Create control device object \\Device\\EtwTiDriver
     * --------------------------------------------------------------------- */
    RtlInitUnicodeString(&devName, ETWTI_DEVICE_NAME);
    status = IoCreateDevice(DriverObject,
                            0,
                            &devName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &devObj);
    if (!NT_SUCCESS(status)) {
        ETWTRACE("IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    g_State.ControlDevice = devObj;
    devObj->Flags |= DO_BUFFERED_IO;
    ETWTRACE("Device created: \\Device\\EtwTiDriver\n");

    /* Symbolic link \\DosDevices\\EtwTiDriver → \\.\EtwTiDriver */
    RtlInitUnicodeString(&linkName, ETWTI_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&linkName, &devName);
    if (!NT_SUCCESS(status)) {
        ETWTRACE("IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(devObj);
        return status;
    }
    g_State.SymlinkCreated = TRUE;
    ETWTRACE("Symbolic link created: \\DosDevices\\EtwTiDriver\n");

    /* -----------------------------------------------------------------------
     * Wire up dispatch table
     * NOTE: No EtwRegister here. ETW-TI subscription is deferred to the
     * IOCTL_ETWTI_START handler so the access check runs against the
     * user-mode caller (EtwTiViewer.exe), not the System process.
     * --------------------------------------------------------------------- */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
    DriverObject->DriverUnload                          = DriverUnloadRoutine;

    /* -----------------------------------------------------------------------
     * Install fallback kernel notification callbacks.
     * These fire unconditionally regardless of ELAM/ETW-TI status and
     * provide process/image telemetry via the pipe even without ETW-TI.
     * --------------------------------------------------------------------- */
    PsSetCreateProcessNotifyRoutineEx(FallbackProcessNotify, FALSE);
    PsSetLoadImageNotifyRoutine(FallbackImageNotify);
    g_State.CallbacksRegistered = TRUE;

    /* -----------------------------------------------------------------------
     * Initialise the stats timer (fires every 1 second)
     * --------------------------------------------------------------------- */
    KeInitializeTimer(&g_State.StatsTimer);
    KeInitializeDpc(&g_State.StatsDpc, StatsDpcRoutine, NULL);

    dueTime.QuadPart = -10000000LL; /* 1 second, relative */
    KeSetTimerEx(&g_State.StatsTimer, dueTime, 1000, &g_State.StatsDpc);

    /* -----------------------------------------------------------------------
     * Spawn the pipe worker thread
     * --------------------------------------------------------------------- */
    KeInitializeEvent(&g_State.WorkerStopEvent, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&hThread,
                                  THREAD_ALL_ACCESS,
                                  NULL, NULL, NULL,
                                  PipeWorkerThread,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        ETWTRACE("PsCreateSystemThread failed: 0x%08X\n", status);
        /* Still functional for IOCTL; pipe output will be absent */
    } else {
        ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL,
                                  KernelMode,
                                  (PVOID*)&g_State.WorkerThread, NULL);
        ZwClose(hThread);
        ETWTRACE("Pipe server started\n");
    }

    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    ETWTRACE("DriverEntry complete, waiting for IOCTLs\n");
    return STATUS_SUCCESS;
}

/* =========================================================================
 * DriverUnload
 * ========================================================================= */

VOID
DriverUnloadRoutine(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    ETWTRACE("DriverUnload called\n");

    /* Stop ETW session and unregister handle */
    EtwSessionStop();
    if (g_EtwRegHandle != (REGHANDLE)0) {
        EtwUnregister(g_EtwRegHandle);
        g_EtwRegHandle = (REGHANDLE)0;
    }
    ETWTRACE("ETW session torn down\n");

    /* Signal the pipe worker thread to exit and wait */
    KeSetEvent(&g_State.WorkerStopEvent, 0, FALSE);
    if (g_State.WorkerThread) {
        KeWaitForSingleObject(g_State.WorkerThread, Executive,
                              KernelMode, FALSE, NULL);
        ObDereferenceObject(g_State.WorkerThread);
        g_State.WorkerThread = NULL;
    }

    /* Cancel the stats timer — must happen after thread exits */
    KeCancelTimer(&g_State.StatsTimer);

    ETWTRACE("Pipe server stopped\n");

    /* Remove fallback callbacks (idempotent) */
    CallbacksRemove();

    /* Tear down pipe handle */
    PipeDestroy();

    /* Remove symbolic link and device */
    if (g_State.SymlinkCreated) {
        UNICODE_STRING linkName;
        RtlInitUnicodeString(&linkName, ETWTI_SYMLINK_NAME);
        IoDeleteSymbolicLink(&linkName);
    }
    if (g_State.ControlDevice) {
        IoDeleteDevice(g_State.ControlDevice);
        g_State.ControlDevice = NULL;
    }
    ETWTRACE("Symbolic link and device removed\n");
    ETWTRACE("Unload complete\n");
}

/* =========================================================================
 * IRP dispatch
 * ========================================================================= */

NTSTATUS
DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack  = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code   = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID              inBuf  = Irp->AssociatedIrp.SystemBuffer;
    PVOID              outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG              inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS           status = STATUS_SUCCESS;
    ULONG_PTR          info   = 0;

    switch (code) {

    /* ------------------------------------------------------------------
     * IOCTL_ETWTI_START  — input: ETWTI_START_INPUT (KeywordMask)
     *
     * ETW-TI subscription is intentionally deferred to this IOCTL handler.
     * The kernel ETW access check (PS_PROTECTED_ANTIMALWARE_LIGHT) runs
     * against the calling process context (EtwTiViewer.exe).  Before
     * sending this IOCTL, patch EtwTiViewer.exe's EPROCESS->Protection
     * to 0x31 in WinDbg:
     *
     *   1. kd> !process 0 0 EtwTiViewer.exe    -- get EPROCESS address
     *   2. kd> dt nt!_EPROCESS <addr> Protection  -- get field offset
     *   3. kd> eb <addr>+<offset> 31
     *
     * Then send the IOCTL.  Restore Protection to 0x00 after if desired.
     * ------------------------------------------------------------------ */
    case IOCTL_ETWTI_START:
        ETWTRACE("IOCTL_START received\n");
        ETWTRACE("Calling process: PID=%lu, EPROCESS=%p\n",
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
                 (PVOID)PsGetCurrentProcess());

        if (inLen < sizeof(ETWTI_START_INPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            PETWTI_START_INPUT pIn = (PETWTI_START_INPUT)inBuf;

            ETWTRACE("Requested keyword mask: 0x%016llX\n", pIn->KeywordMask);

            /* Stop any running session and drop the existing reg handle */
            if (g_State.SessionActive)
                EtwSessionStop();
            if (g_EtwRegHandle != (REGHANDLE)0) {
                EtwUnregister(g_EtwRegHandle);
                g_EtwRegHandle = (REGHANDLE)0;
            }

            /*
             * EtwRegister runs HERE — in the context of EtwTiViewer.exe.
             * The kernel ETW protection check therefore evaluates the
             * Protection field of EtwTiViewer.exe's EPROCESS, not System.
             */
            NTSTATUS regSt = EtwRegister(&GUID_EtwTiProvider,
                                          EtwEnableCallback,
                                          NULL,
                                          &g_EtwRegHandle);
            ETWTRACE("EtwRegister result: 0x%08X\n", regSt);

            if (!NT_SUCCESS(regSt)) {
                ETWTRACE("ETW-TI session start FAILED — status 0x%08X. "
                         "If STATUS_ACCESS_DENIED, patch EPROCESS->Protection "
                         "to 0x31 on PID %lu before sending IOCTL_START\n",
                         regSt,
                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
                status = regSt;
                break;
            }

            status = EtwSessionStart(pIn->KeywordMask);
            ETWTRACE("ETW session start result: 0x%08X\n", status);

            if (NT_SUCCESS(status)) {
                ETWTRACE("ETW-TI session started successfully, consuming events\n");
            } else {
                ETWTRACE("ETW-TI session start FAILED — status 0x%08X. "
                         "If STATUS_ACCESS_DENIED, patch EPROCESS->Protection "
                         "to 0x31 on PID %lu before sending IOCTL_START\n",
                         status,
                         (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
            }
        }
        break;

    /* ------------------------------------------------------------------
     * IOCTL_ETWTI_STOP
     * ------------------------------------------------------------------ */
    case IOCTL_ETWTI_STOP:
        ETWTRACE("IOCTL_STOP received\n");
        EtwSessionStop();
        {
            NTSTATUS unregSt = STATUS_SUCCESS;
            if (g_EtwRegHandle != (REGHANDLE)0) {
                unregSt = EtwUnregister(g_EtwRegHandle);
                g_EtwRegHandle = (REGHANDLE)0;
            }
            ETWTRACE("ETW session stopped, status: 0x%08X\n", unregSt);
        }
        CallbacksRemove();
        break;

    /* ------------------------------------------------------------------
     * IOCTL_ETWTI_STATUS  — output: ETWTI_STATUS_OUTPUT
     * ------------------------------------------------------------------ */
    case IOCTL_ETWTI_STATUS:
        if (outLen < sizeof(ETWTI_STATUS_OUTPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            PETWTI_STATUS_OUTPUT pOut = (PETWTI_STATUS_OUTPUT)outBuf;
            pOut->Running      = g_State.SessionActive;
            pOut->EventsPerSec = (ULONG)InterlockedExchangeAdd(&g_State.EventsPerSec, 0);
            pOut->Dropped      = (ULONG)InterlockedExchangeAdd(&g_State.DroppedCount, 0);
            info = sizeof(ETWTI_STATUS_OUTPUT);
        }
        break;

    /* ------------------------------------------------------------------
     * IOCTL_ETWTI_SET_VERBOSE  — input: ULONG (non-zero = enable)
     * Enables per-event KdPrintEx output.  Activate KD filter first:
     *   kd> ed nt!Kd_IHVDRIVER_Mask 0xFFFFFFFF
     * ------------------------------------------------------------------ */
    case IOCTL_ETWTI_SET_VERBOSE:
        if (inLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        g_VerboseDebug = (*(PULONG)inBuf != 0) ? TRUE : FALSE;
        ETWTRACE("Verbose debug %s\n", g_VerboseDebug ? "enabled" : "disabled");
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        ETWTRACE("Unknown IOCTL code 0x%08X\n", code);
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* =========================================================================
 * ETW session management
 * ========================================================================= */

NTSTATUS
EtwSessionStart(ULONGLONG keywordMask)
{
    /* g_EtwRegHandle must already be registered by the IOCTL handler */
    if (g_EtwRegHandle == (REGHANDLE)0) {
        ETWTRACE("EtwSessionStart: called without valid registration handle\n");
        return STATUS_INVALID_HANDLE;
    }

    g_State.KeywordMask   = keywordMask;
    g_State.SessionActive = TRUE;

    InterlockedExchange(&g_State.EventCount,    0);
    InterlockedExchange(&g_State.DroppedCount,  0);
    InterlockedExchange(&g_State.EventsThisSec, 0);
    InterlockedExchange(&g_State.EventsPerSec,  0);

    ETWTRACE("Session started, keywordMask=0x%016llX\n", keywordMask);
    return STATUS_SUCCESS;
}

VOID
EtwSessionStop(void)
{
    if (!g_State.SessionActive)
        return;

    g_State.SessionActive = FALSE;
    g_State.KeywordMask   = 0;
    ETWTRACE("Session stopped\n");
}

/*
 * CallbacksRemove — idempotent teardown of PS notify callbacks.
 *
 * Called from IOCTL_ETWTI_STOP (before sc stop) to remove callbacks
 * early so Windows 11 does not reject the NtUnloadDriver call.
 * DriverUnloadRoutine calls it again; the second call is a no-op.
 */
VOID
CallbacksRemove(void)
{
    if (!g_State.CallbacksRegistered)
        return;

    PsSetCreateProcessNotifyRoutineEx(FallbackProcessNotify, TRUE);
    PsRemoveLoadImageNotifyRoutine(FallbackImageNotify);
    g_State.CallbacksRegistered = FALSE;
    ETWTRACE("PS notify callbacks removed\n");
}

/* =========================================================================
 * ETW enable/disable callback
 * ========================================================================= */

VOID NTAPI
EtwEnableCallback(
    _In_     LPCGUID                  SourceId,
    _In_     ULONG                    IsEnabled,
    _In_     UCHAR                    Level,
    _In_     ULONGLONG                MatchAnyKeyword,
    _In_     ULONGLONG                MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID                    CallbackContext)
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    ETWTRACE("EtwEnableCallback: IsEnabled=%u\n", IsEnabled);

    if (IsEnabled) {
        g_State.SessionActive = TRUE;
    }
}

/* =========================================================================
 * Fallback: Process-creation notification
 * ========================================================================= */

VOID
FallbackProcessNotify(
    _Inout_ PEPROCESS              Process,
    _In_    HANDLE                 ProcessId,
    _In_    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (!g_State.SessionActive || !g_State.PipeConnected)
        return;

    const char *evtName = (CreateInfo != NULL) ? "PROCESS_CREATE" : "PROCESS_EXIT";
    USHORT nameLen = (USHORT)strlen(evtName);

    char fields[256];
    USHORT fieldsLen = 0;

    if (CreateInfo != NULL && CreateInfo->ImageFileName != NULL) {
        char imgBuf[200] = {0};
        ULONG copyLen = min(CreateInfo->ImageFileName->Length / sizeof(WCHAR),
                            (ULONG)(sizeof(imgBuf) - 1));
        for (ULONG i = 0; i < copyLen; i++) {
            WCHAR wc = CreateInfo->ImageFileName->Buffer[i];
            imgBuf[i] = (wc < 128) ? (char)wc : '?';
        }
        RtlStringCbPrintfA(fields, sizeof(fields), "Image=%s", imgBuf);
        fieldsLen = (USHORT)(strlen(fields) + 1);
    }

    LARGE_INTEGER    sysTime;
    PIPE_EVENT_HEADER hdr = {0};
    KeQuerySystemTime(&sysTime);

    hdr.Magic     = PIPE_EVENT_MAGIC;
    hdr.EventId   = (CreateInfo != NULL) ? 1 : 2;
    hdr.Pid       = (UINT32)(ULONG_PTR)ProcessId;
    hdr.Tid       = 0;
    hdr.Timestamp = (UINT64)sysTime.QuadPart;
    hdr.NameLen   = nameLen;
    hdr.FieldsLen = fieldsLen;

    if (g_VerboseDebug) {
        ETWTRACE("Event: ID=%u PID=%lu TID=%lu\n",
                 (ULONG)hdr.EventId, (ULONG)hdr.Pid, (ULONG)hdr.Tid);
    }

    PipeWriteEvent(&hdr, (const UCHAR *)evtName, (const UCHAR *)fields);
    InterlockedIncrement(&g_State.EventCount);
    InterlockedIncrement(&g_State.EventsThisSec);
}

/* =========================================================================
 * Fallback: Image-load notification
 * ========================================================================= */

VOID
FallbackImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!g_State.SessionActive || !g_State.PipeConnected)
        return;

    const char *evtName = "IMAGE_LOAD";
    USHORT nameLen = (USHORT)strlen(evtName);

    char fields[256] = {0};
    USHORT fieldsLen = 0;

    if (FullImageName != NULL) {
        static const char kPrefix[] = "Image=";
        static const USHORT kPrefixLen = sizeof(kPrefix) - 1;
        ULONG maxPath = (ULONG)(sizeof(fields) - kPrefixLen - 2);
        ULONG copyLen = min(FullImageName->Length / sizeof(WCHAR), maxPath);
        RtlCopyMemory(fields, kPrefix, kPrefixLen);
        for (ULONG i = 0; i < copyLen; i++) {
            WCHAR wc = FullImageName->Buffer[i];
            fields[kPrefixLen + i] = (wc < 128) ? (char)wc : '?';
        }
        fields[kPrefixLen + copyLen] = '\0';
        fieldsLen = (USHORT)(kPrefixLen + copyLen + 1);
    }

    LARGE_INTEGER    sysTime;
    PIPE_EVENT_HEADER hdr = {0};
    KeQuerySystemTime(&sysTime);

    hdr.Magic     = PIPE_EVENT_MAGIC;
    hdr.EventId   = 3;
    hdr.Pid       = (UINT32)(ULONG_PTR)ProcessId;
    hdr.Tid       = 0;
    hdr.Timestamp = (UINT64)sysTime.QuadPart;
    hdr.NameLen   = nameLen;
    hdr.FieldsLen = fieldsLen;

    if (g_VerboseDebug) {
        ETWTRACE("Event: ID=%u PID=%lu TID=%lu\n",
                 (ULONG)hdr.EventId, (ULONG)hdr.Pid, (ULONG)hdr.Tid);
    }

    PipeWriteEvent(&hdr, (const UCHAR *)evtName, (const UCHAR *)fields);
    InterlockedIncrement(&g_State.EventCount);
    InterlockedIncrement(&g_State.EventsThisSec);
}

/* =========================================================================
 * Stats DPC — fires once per second
 * ========================================================================= */

VOID
StatsDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    LONG snap = InterlockedExchange(&g_State.EventsThisSec, 0);
    InterlockedExchange(&g_State.EventsPerSec, snap);
}

/* =========================================================================
 * Named pipe — driver is the WRITE CLIENT, viewer is the READ SERVER
 * ========================================================================= */

NTSTATUS
PipeCreate(void)
{
    UNICODE_STRING    pipeName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;

    RtlInitUnicodeString(&pipeName, ETWTI_PIPE_NAME);
    InitializeObjectAttributes(&oa, &pipeName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    NTSTATUS status = ZwCreateFile(
        &g_State.PipeHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        ETWTRACE("ZwCreateFile(pipe) failed: 0x%08X\n", status);
        g_State.PipeHandle = NULL;
    }
    return status;
}

VOID
PipeDestroy(void)
{
    if (g_State.PipeHandle) {
        ZwClose(g_State.PipeHandle);
        g_State.PipeHandle    = NULL;
        g_State.PipeConnected = FALSE;
    }
}

NTSTATUS
PipeWriteEvent(
    PPIPE_EVENT_HEADER pHdr,
    const UCHAR       *pName,
    const UCHAR       *pFields)
{
    if (!g_State.PipeConnected || !g_State.PipeHandle)
        return STATUS_PIPE_NOT_AVAILABLE;

    ULONG totalSize = sizeof(PIPE_EVENT_HEADER) + pHdr->NameLen + pHdr->FieldsLen;
    if (totalSize > PIPE_MAX_MSG_BYTES) {
        InterlockedIncrement(&g_State.DroppedCount);
        return STATUS_BUFFER_OVERFLOW;
    }

    UCHAR *buf = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalSize, POOL_TAG);
    if (!buf) {
        InterlockedIncrement(&g_State.DroppedCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(buf, pHdr, sizeof(PIPE_EVENT_HEADER));
    if (pHdr->NameLen   > 0) RtlCopyMemory(buf + sizeof(PIPE_EVENT_HEADER),                   pName,   pHdr->NameLen);
    if (pHdr->FieldsLen > 0) RtlCopyMemory(buf + sizeof(PIPE_EVENT_HEADER) + pHdr->NameLen, pFields, pHdr->FieldsLen);

    IO_STATUS_BLOCK iosb = {0};
    NTSTATUS status = ZwWriteFile(g_State.PipeHandle,
                                  NULL, NULL, NULL,
                                  &iosb,
                                  buf,
                                  totalSize,
                                  NULL, NULL);

    ExFreePoolWithTag(buf, POOL_TAG);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&g_State.DroppedCount);
        g_State.PipeConnected = FALSE;
        ETWTRACE("Pipe write failed (client gone?), status: 0x%08X\n", status);
    }
    return status;
}

/* =========================================================================
 * Pipe worker thread
 * ========================================================================= */

VOID
PipeWorkerThread(_In_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    ETWTRACE("PipeWorkerThread started\n");

    for (;;) {
        /* Non-blocking check for stop signal */
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        NTSTATUS waitStatus = KeWaitForSingleObject(&g_State.WorkerStopEvent,
                                                    Executive, KernelMode,
                                                    FALSE, &zero);
        if (waitStatus == STATUS_SUCCESS)
            break;

        if (!g_State.PipeHandle) {
            NTSTATUS st = PipeCreate();
            if (!NT_SUCCESS(st)) {
                /* Pipe server not ready; wait 2 s but wake if stop fires */
                LARGE_INTEGER delay;
                delay.QuadPart = -20000000LL;
                NTSTATUS ws = KeWaitForSingleObject(&g_State.WorkerStopEvent,
                                                    Executive, KernelMode,
                                                    FALSE, &delay);
                if (ws == STATUS_SUCCESS)
                    goto done;
                continue;
            }
            g_State.PipeConnected = TRUE;
            ETWTRACE("Pipe client connected\n");
        }

        /* Monitor connection; wake on stop event or disconnect */
        while (g_State.PipeConnected) {
            LARGE_INTEGER delay;
            delay.QuadPart = -2000000LL; /* 200 ms */
            NTSTATUS ws = KeWaitForSingleObject(&g_State.WorkerStopEvent,
                                                Executive, KernelMode,
                                                FALSE, &delay);
            if (ws == STATUS_SUCCESS)
                goto done;
        }

        ETWTRACE("Pipe client disconnected\n");
        PipeDestroy();
    }

done:
    PipeDestroy();
    ETWTRACE("PipeWorkerThread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}
