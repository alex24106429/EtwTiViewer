/*
 * EtwTiShared.h
 * Shared definitions between EtwTiDriver (kernel) and EtwTiViewer (user-mode).
 * Included by both components; must use only types valid in both contexts.
 */

#pragma once

#ifdef _KERNEL_MODE
#  include <ntddk.h>
#else
#  include <Windows.h>
#endif

/* -------------------------------------------------------------------------
 * Device name / symbolic link
 * ------------------------------------------------------------------------- */
#define ETWTI_DEVICE_NAME      L"\\Device\\EtwTiDriver"
#define ETWTI_SYMLINK_NAME     L"\\DosDevices\\EtwTiDriver"
#define ETWTI_USER_DEVICE_PATH L"\\\\.\\EtwTiDriver"

/* -------------------------------------------------------------------------
 * Named pipe
 * ------------------------------------------------------------------------- */
#define ETWTI_PIPE_NAME        L"\\Device\\NamedPipe\\EtwTiForwarder"
#define ETWTI_PIPE_USER_PATH   L"\\\\.\\pipe\\EtwTiForwarder"

/* -------------------------------------------------------------------------
 * IOCTL codes
 * FILE_DEVICE_UNKNOWN = 0x22, METHOD_BUFFERED = 0, FILE_ANY_ACCESS = 0
 * CTL_CODE(DeviceType, Function, Method, Access)
 * ------------------------------------------------------------------------- */
#define ETWTI_IOCTL_BASE       0x800

#define IOCTL_ETWTI_START       CTL_CODE(FILE_DEVICE_UNKNOWN, ETWTI_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ETWTI_STOP        CTL_CODE(FILE_DEVICE_UNKNOWN, ETWTI_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ETWTI_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, ETWTI_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* IOCTL_ETWTI_SET_VERBOSE — input: ULONG (non-zero = enable verbose KdPrintEx per event).
 * Enable from WinDbg: kd> ed nt!Kd_IHVDRIVER_Mask 0xFFFFFFFF */
#define IOCTL_ETWTI_SET_VERBOSE CTL_CODE(FILE_DEVICE_UNKNOWN, ETWTI_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Input buffer for IOCTL_ETWTI_START */
typedef struct _ETWTI_START_INPUT {
    ULONGLONG KeywordMask;   /* ETW keyword bitmask from the keyword table */
} ETWTI_START_INPUT, *PETWTI_START_INPUT;

/* Output buffer for IOCTL_ETWTI_STATUS */
typedef struct _ETWTI_STATUS_OUTPUT {
    BOOLEAN   Running;
    ULONG     EventsPerSec;  /* rolling 1-second average */
    ULONG     Dropped;       /* events dropped due to pipe full */
} ETWTI_STATUS_OUTPUT, *PETWTI_STATUS_OUTPUT;

/* -------------------------------------------------------------------------
 * Pipe wire format (binary, little-endian)
 * Each message = PipeEventHeader, then nameLen UTF-8 bytes (event name),
 * then fieldsLen bytes of NUL-terminated "key=value\0" pairs.
 * ------------------------------------------------------------------------- */
#define PIPE_EVENT_MAGIC  0x54495445u  /* 'ETIT' little-endian */

#pragma pack(push, 1)
typedef struct _PIPE_EVENT_HEADER {
    UINT32  Magic;       /* must equal PIPE_EVENT_MAGIC                        */
    UINT16  EventId;
    UINT16  Task;        /* EVENT_DESCRIPTOR.Task  — operation category         */
    UINT64  Keyword;     /* EVENT_DESCRIPTOR.Keyword bitmask (LOCAL/REMOTE/…)  */
    UINT32  Pid;
    UINT32  Tid;
    UINT64  Timestamp;   /* FILETIME (100-ns intervals since 1601)              */
    UINT16  NameLen;     /* byte count of UTF-8 event name that follows        */
    UINT16  FieldsLen;   /* byte count of fields blob that follows             */
} PIPE_EVENT_HEADER, *PPIPE_EVENT_HEADER;
#pragma pack(pop)

/* Maximum total message size we'll ever send; driver drops larger ones. */
#define PIPE_MAX_MSG_BYTES  4096u
