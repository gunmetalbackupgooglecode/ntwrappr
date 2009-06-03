#pragma once

extern "C"
{

#define stricmp _stricmp

#define INITIAL_TEB XYZZ
#define PINITIAL_TEB PXYZZ
#define _INITIAL_TEB _XYZZ

#include <ntifs.h>
#include <ntddkbd.h>
#include <stdarg.h>

#undef INITIAL_TEB
#undef PINITIAL_TEB
#undef _INITIAL_TEB

typedef struct _INITIAL_TEB {
    struct {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

NTSYSAPI 
NTSTATUS
NTAPI
NtDisplayString(
  IN PUNICODE_STRING      String );

NTSYSAPI 
NTSTATUS
NTAPI
ZwDisplayString(
  IN PUNICODE_STRING      String );

NTSYSAPI 
NTSTATUS
NTAPI
NtTerminateProcess(
  IN HANDLE               ProcessHandle,
  IN NTSTATUS             ExitStatus );

NTSYSAPI 
NTSTATUS
NTAPI
NtDelayExecution(
  IN BOOLEAN              Alertable,
  IN PLARGE_INTEGER       DelayInterval );

VOID
NTAPI
RtlRaiseStatus(
  IN NTSTATUS             Status );

NTSYSAPI 
NTSTATUS
NTAPI
NtCreateDirectoryObject(
  OUT PHANDLE             DirectoryHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes );

NTSYSAPI 
NTSTATUS
NTAPI
NtCreateSymbolicLinkObject (
  OUT PHANDLE             pHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes,
  IN PUNICODE_STRING      DestinationName );

NTSYSAPI 
NTSTATUS
NTAPI
NtOpenFile(
  OUT PHANDLE             FileHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes,
  OUT PIO_STATUS_BLOCK    IoStatusBlock,
  IN ULONG                ShareAccess,
  IN ULONG                OpenOptions );

NTSYSAPI 
NTSTATUS
NTAPI
ZwCreateProcess(
  OUT PHANDLE           ProcessHandle,
  IN ACCESS_MASK        DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
  IN HANDLE             ParentProcess,
  IN BOOLEAN            InheritObjectTable,
  IN HANDLE             SectionHandle OPTIONAL,
  IN HANDLE             DebugPort OPTIONAL,
  IN HANDLE             ExceptionPort OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
NtCreateProcess(
  OUT PHANDLE           ProcessHandle,
  IN ACCESS_MASK        DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
  IN HANDLE             ParentProcess,
  IN BOOLEAN            InheritObjectTable,
  IN HANDLE             SectionHandle OPTIONAL,
  IN HANDLE             DebugPort OPTIONAL,
  IN HANDLE             ExceptionPort OPTIONAL );


NTSYSAPI 
NTSTATUS
NTAPI
NtProtectVirtualMemory(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN OUT PULONG           NumberOfBytesToProtect,
  IN ULONG                NewAccessProtection,
  OUT PULONG              OldAccessProtection );

NTSYSAPI 
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN OUT PULONG           NumberOfBytesToProtect,
  IN ULONG                NewAccessProtection,
  OUT PULONG              OldAccessProtection );

NTSYSAPI 
NTSTATUS
NTAPI
ZwResumeThread(
  IN HANDLE               ThreadHandle,
  OUT PULONG              SuspendCount OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
NtResumeThread(
  IN HANDLE               ThreadHandle,
  OUT PULONG              SuspendCount OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
NtTerminateThread(
  IN HANDLE               ThreadHandle,
  IN NTSTATUS             ExitStatus );

NTSYSAPI 
NTSTATUS
NTAPI
ZwTerminateThread(
  IN HANDLE               ThreadHandle,
  IN NTSTATUS             ExitStatus );

NTSYSAPI 
NTSTATUS
NTAPI
ZwCreateThread(
  OUT PHANDLE             ThreadHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
  IN HANDLE               ProcessHandle,
  OUT PCLIENT_ID          ClientId,
  IN PCONTEXT             ThreadContext,
  IN PINITIAL_TEB         InitialTeb,
  IN BOOLEAN              CreateSuspended );

NTSYSAPI 
NTSTATUS
NTAPI
NtCreateThread(
  OUT PHANDLE             ThreadHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
  IN HANDLE               ProcessHandle,
  OUT PCLIENT_ID          ClientId,
  IN PCONTEXT             ThreadContext,
  IN PINITIAL_TEB         InitialTeb,
  IN BOOLEAN              CreateSuspended );

NTSYSAPI 
NTSTATUS
NTAPI
ZwDelayExecution(
  IN BOOLEAN              Alertable,
  IN PLARGE_INTEGER       DelayInterval );


int _cdecl _snwprintf(
   wchar_t *buffer,
   size_t count,
   const wchar_t *format,
   ... 
);

int _cdecl _snprintf(
   char *buffer,
   size_t count,
   const char *format,
   ... 
);

int _cdecl _vsnwprintf(
   wchar_t *buffer,
   size_t count,
   const wchar_t *format,
   va_list va 
);

int _cdecl _vsnprintf(
   char *buffer,
   size_t count,
   const char *format,
   va_list va 
);
size_t _cdecl mbstowcs(
   wchar_t *wcstr,
   const char *mbstr,
   size_t count 
);

size_t _cdecl wcstombs(
   char *mbstr,
   const wchar_t *wcstr,
   size_t count 
);

NTSYSAPI 
NTSTATUS
NTAPI
LdrLoadDll(
  IN PWCHAR               PathToFile OPTIONAL,
  IN PULONG               DllCharacteristics OPTIONAL,
  IN PUNICODE_STRING      ModuleFileName,
  OUT PVOID              *ModuleHandle );

NTSYSAPI 
NTSTATUS
NTAPI
LdrGetDllHandle(
  IN PWCHAR               PathToFile OPTIONAL,
  IN PULONG               DllCharacteristics OPTIONAL,
  IN PUNICODE_STRING      ModuleFileName,
  OUT PVOID              *ModuleHandle );

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress (
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG ProcedureNumber OPTIONAL,
    OUT PVOID *ProcedureAddress
    );

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

VOID
NTAPI
RtlNormalizeProcessParams(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

typedef struct _RTL_USER_PROCESS_INFORMATION {
  ULONG                   Size;
  HANDLE                  ProcessHandle;
  HANDLE                  ThreadHandle;
  CLIENT_ID               ClientId;
  SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

NTSYSAPI 
NTSTATUS
NTAPI
RtlCreateUserThread(
  IN HANDLE               ProcessHandle,
  IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
  IN BOOLEAN              CreateSuspended,
  IN ULONG                StackZeroBits,
  IN SIZE_T               StackReserved,
  IN SIZE_T               StackCommit,
  IN PVOID                StartAddress,
  IN PVOID                StartParameter OPTIONAL,
  OUT PHANDLE             ThreadHandle,
  OUT PCLIENT_ID          ClientID );

NTSYSAPI 
NTSTATUS
NTAPI
RtlCreateUserProcess(
  IN PUNICODE_STRING      ImagePath,
  IN ULONG                ObjectAttributes,
  IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
  IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
  IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
  IN HANDLE               ParentProcess,
  IN BOOLEAN              InheritHandles,
  IN HANDLE               DebugPort OPTIONAL,
  IN HANDLE               ExceptionPort OPTIONAL,
  OUT PRTL_USER_PROCESS_INFORMATION ProcessInformation );


NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParameters(
    OUT PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    IN PUNICODE_STRING ImagePathName OPTIONAL,
    IN PUNICODE_STRING DllPath OPTIONAL,
    IN PUNICODE_STRING CurrentDirectory OPTIONAL,
    IN PUNICODE_STRING CommandLine OPTIONAL,
    IN PUNICODE_STRING Environment OPTIONAL,
    IN PUNICODE_STRING WindowTitle OPTIONAL,
    IN PUNICODE_STRING DesktopInfo OPTIONAL,
    IN PUNICODE_STRING ShellInfo OPTIONAL,
    IN PUNICODE_STRING RuntimeInfo OPTIONAL
   );

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyProcessParameters(
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters
	);

NTSYSAPI
VOID
NTAPI
RtlExitUserThread (
	NTSTATUS Status
	);

#undef KdPrint
#define KdPrint(X) Print X

/*
typedef struct _TEB {
	NT_TIB Tib;
	PVOID EnvironmentPointer;
	CLIENT_ID Cid;
	PVOID ActiveRpcInfo;
	PVOID TLSPointer;
	PPEB Peb;
} TEB, *PTEB;
*/

inline __declspec(naked) PTEB NtCurrentTeb ()
{
	__asm
	{
		mov eax, fs:[0x18]
		retn
	}
}

inline PPEB NtCurrentPeb ()
{
	return NtCurrentTeb()->Peb;
}

typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;
  BOOLEAN                 ReadImageFileExecOptions;
  BOOLEAN                 BeingDebugged;
  BOOLEAN                 Spare;
  HANDLE                  Mutant;
  PVOID                   ImageBaseAddress;
  PVOID                   LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID                   SubSystemData;
  PVOID                   ProcessHeap;
  PVOID                   FastPebLock;
  PVOID                   FastPebLockRoutine;
  PVOID                   FastPebUnlockRoutine;
  ULONG                   EnvironmentUpdateCount;
  PVOID                   KernelCallbackTable;
  PVOID                   EventLogSection;
  PVOID                   EventLog;
  PVOID                   FreeList;
  ULONG                   TlsExpansionCounter;
  PVOID                   TlsBitmap;
  ULONG                   TlsBitmapBits[0x2];
  PVOID                   ReadOnlySharedMemoryBase;
  PVOID                   ReadOnlySharedMemoryHeap;
  PVOID                   ReadOnlyStaticServerData;
  PVOID                   AnsiCodePageData;
  PVOID                   OemCodePageData;
  PVOID                   UnicodeCaseTableData;
  ULONG                   NumberOfProcessors;
  ULONG                   NtGlobalFlag;
  UCHAR                   Spare2[0x4];
  LARGE_INTEGER           CriticalSectionTimeout;
  ULONG                   HeapSegmentReserve;
  ULONG                   HeapSegmentCommit;
  ULONG                   HeapDeCommitTotalFreeThreshold;
  ULONG                   HeapDeCommitFreeBlockThreshold;
  ULONG                   NumberOfHeaps;
  ULONG                   MaximumNumberOfHeaps;
  PVOID                   *ProcessHeaps;
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  UCHAR                   TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId;
} PEB, *PPEB;

inline PUNICODE_STRING GetCommandLine ()
{
	return &NtCurrentTeb()->Peb->ProcessParameters->CommandLine;
}



//
// Debug Object Access Masks
//
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

//
// Debug Object Information Classes for NtQueryDebugObject
//
typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

//
// Debug Message API Number
//
typedef enum _DBGKM_APINUMBER
{
    DbgKmExceptionApi = 0,
    DbgKmCreateThreadApi = 1,
    DbgKmCreateProcessApi = 2,
    DbgKmExitThreadApi = 3,
    DbgKmExitProcessApi = 4,
    DbgKmLoadDllApi = 5,
    DbgKmUnloadDllApi = 6,
    DbgKmErrorReportApi = 7,
    DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

//
// Debug Object Information Structures
//
typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION
{
    ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, *PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;



//
// Debug States
//
typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

//
// Debug Message Structures
//
typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

//
// User-Mode Debug State Change Structure
//
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        struct
        {
            HANDLE HandleToThread;
            DBGKM_CREATE_THREAD NewThread;
        } CreateThread;
        struct
        {
            HANDLE HandleToProcess;
            HANDLE HandleToThread;
            DBGKM_CREATE_PROCESS NewProcess;
        } CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_EXCEPTION Exception;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE

//                                
// LPC Port Message               
//                              

typedef struct _PORT_MESSAGE      
{                                 
    union                         
    {                             
        struct                    
        {                         
            USHORT DataLength;    
            USHORT TotalLength;   
        } s1;                     
        ULONG Length;             
    } u1;                         
    union                         
    {                             
        struct                    
        {                         
            USHORT Type;          
            USHORT DataInfoOffset;
        } s2;                     
        ULONG ZeroInit;           
    } u2;                         
    union                         
    {                             
        LPC_CLIENT_ID ClientId;   
        double DoNotUseThisField; 
    };                            
    ULONG MessageId;              
    union                         
    {                             
        LPC_SIZE_T ClientViewSize;
        ULONG CallbackId;         
    };                            
} PORT_MESSAGE, *PPORT_MESSAGE;   

typedef ULONG CSR_API_NUMBER;
//
// LPC Debug Message
//
typedef struct _DBGKM_MSG
{
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber;
    ULONG ReturnedStatus;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGKM_CREATE_THREAD CreateThread;
        DBGKM_CREATE_PROCESS CreateProcess;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    };
} DBGKM_MSG, *PDBGKM_MSG;


NTSYSAPI
NTSTATUS
NTAPI
DbgUiConnectToDbg(
	VOID
	);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiContinue(
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus
	);


NTSYSAPI
NTSTATUS 
NTAPI 
DbgUiConvertStateChangeStructure(
	IN PDBGUI_WAIT_STATE_CHANGE  WaitStateChange,
	OUT PVOID                    Win32DebugEvent	 
	);

NTSYSAPI
NTSTATUS 
NTAPI 
DbgUiDebugActiveProcess(
	IN HANDLE Process
	);

NTSYSAPI
HANDLE 
NTAPI 
DbgUiGetThreadDebugObject(
	VOID
	);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiIssueRemoteBreakin(
	IN HANDLE Process
	);

NTSYSAPI
VOID
NTAPI
DbgUiRemoteBreakin(
	VOID
	);

NTSYSAPI
VOID
NTAPI
DbgUiSetThreadDebugObject(
	IN HANDLE DebugObject
	);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiStopDebugging(
	IN HANDLE Process
	);

NTSYSAPI
NTSTATUS
NTAPI
DbgUiWaitStateChange(
	OUT PDBGUI_WAIT_STATE_CHANGE DbgUiWaitStateChange,
	IN PLARGE_INTEGER TimeOut
	);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
	NTSTATUS Status
	);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32Error(
	ULONG ErrorCode
	);

NTSYSAPI
ULONG
NTAPI
RtlGetLastWin32Error(
	);

int _cdecl atoi( const char* );

NTSYSAPI
USHORT
NTAPI
RtlGetCurrentDirectory_U(
	USHORT MaxLen,
	PWSTR Buffer
	);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetCurrentDirectory_U(
	PUNICODE_STRING Path
	);

typedef enum _HARDERROR_RESPONSE_OPTION {
	OptionAbortRetryIgnore, 
	OptionOk, 
	OptionOkCancel, 
	OptionRetryCancel, 
	OptionYesNo, 
	OptionYesNoCancel, 
	OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {
	ResponseReturnToCaller, 
	ResponseNotHandled, 
	ResponseAbort, 
	ResponseCancel, 
	ResponseIgnore, 
	ResponseNo, 
	ResponseOk, 
	ResponseRetry, 
	ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef struct _HARDERROR_MSG {
  LPC_MESSAGE             LpcMessageHeader;
  NTSTATUS                ErrorStatus;
  LARGE_INTEGER           ErrorTime;
  HARDERROR_RESPONSE_OPTION ResponseOption;
  HARDERROR_RESPONSE      Response;
  ULONG                   NumberOfParameters;
  PVOID                   UnicodeStringParameterMask;
  ULONG                   Parameters[4];
} HARDERROR_MSG, *PHARDERROR_MSG;


NTSYSAPI 
NTSTATUS
NTAPI
ZwRaiseHardError(
	IN NTSTATUS ErrorStatus, 
	IN ULONG NumberOfParameters, 
	IN PUNICODE_STRING UnicodeStringParameterMask OPTIONAL, 
	IN PVOID *Parameters, 
	IN HARDERROR_RESPONSE_OPTION ResponseOption, 
	OUT PHARDERROR_RESPONSE Response 
	); 

NTSYSAPI
NTSTATUS 
NTAPI
RtlAdjustPrivilege(
  ULONG    Privilege,
  BOOLEAN  Enable,
  BOOLEAN  CurrentThread,
  PBOOLEAN Enabled
 );

#define SE_MACHINE_ACCOUNT_PRIVILEGE      (6L)
#define SE_TCB_PRIVILEGE                  (7L)
#define SE_SECURITY_PRIVILEGE             (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE       (9L)
#define SE_LOAD_DRIVER_PRIVILEGE          (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE       (11L)
#define SE_SYSTEMTIME_PRIVILEGE           (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE    (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE      (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE     (16L)
#define SE_BACKUP_PRIVILEGE               (17L)
#define SE_RESTORE_PRIVILEGE              (18L)
#define SE_SHUTDOWN_PRIVILEGE             (19L)
#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_AUDIT_PRIVILEGE                (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE        (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      (24L)
#define SE_UNDOCK_PRIVILEGE               (25L)
#define SE_SYNC_AGENT_PRIVILEGE           (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE    (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE        (28L)
#define SE_IMPERSONATE_PRIVILEGE          (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE        (30L)

typedef struct _LPC_SECTION_OWNER_MEMORY {
  ULONG                   Length;
  HANDLE                  SectionHandle;
  ULONG                   OffsetInSection;
  ULONG                   ViewSize;
  PVOID                   ViewBase;
  PVOID                   OtherSideViewBase;
} LPC_SECTION_OWNER_MEMORY, *PLPC_SECTION_OWNER_MEMORY;

typedef struct _LPC_SECTION_MEMORY {
  ULONG                   Length;
  ULONG                   ViewSize;
  PVOID                   ViewBase;
} LPC_SECTION_MEMORY, *PLPC_SECTION_MEMORY;


NTSYSAPI 
NTSTATUS
NTAPI
ZwCreatePort(
  OUT PHANDLE             PortHandle,
  IN POBJECT_ATTRIBUTES   ObjectAttributes,
  IN ULONG                MaxConnectInfoLength,
  IN ULONG                MaxDataLength,
  IN OUT PULONG           Reserved OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
ZwReplyWaitReceivePort(
  IN HANDLE               PortHandle,
  OUT PHANDLE             ReceivePortHandle OPTIONAL,
  IN PLPC_MESSAGE         Reply OPTIONAL,
  OUT PLPC_MESSAGE        IncomingRequest );

NTSYSAPI 
NTSTATUS
NTAPI
ZwRequestPort(
  IN HANDLE               PortHandle,
  IN PLPC_MESSAGE         Request );

NTSYSAPI 
NTSTATUS
NTAPI
ZwRequestWaitReplyPort(
  IN HANDLE               PortHandle,
  IN PLPC_MESSAGE         Request,
  OUT PLPC_MESSAGE        IncomingReply );

NTSYSAPI 
NTSTATUS
NTAPI
ZwReplyPort(
  IN HANDLE               PortHandle,
  IN PLPC_MESSAGE         Reply );

NTSYSAPI 
NTSTATUS
NTAPI
ZwAcceptConnectPort(
  OUT PHANDLE             ServerPortHandle,
  IN HANDLE               AlternativeReceivePortHandle OPTIONAL,
  IN PLPC_MESSAGE         ConnectionReply,
  IN BOOLEAN              AcceptConnection,
  IN OUT PLPC_SECTION_OWNER_MEMORY ServerSharedMemory OPTIONAL,
  OUT PLPC_SECTION_MEMORY ClientSharedMemory OPTIONAL );

NTSYSAPI 
NTSTATUS
NTAPI
ZwCompleteConnectPort(
  IN HANDLE               PortHandle );

NTSYSAPI 
NTSTATUS
NTAPI
ZwSetDefaultHardErrorPort(
  IN HANDLE               PortHandle );

typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot, 
    ShutdownReboot, 
    ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

NTSYSAPI 
NTSTATUS
NTAPI
ZwShutdownSystem(
    IN SHUTDOWN_ACTION Action ); 

}
