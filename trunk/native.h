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
  IN ULONG                Flags OPTIONAL,
  IN PUNICODE_STRING      ModuleFileName,
  OUT PHANDLE             ModuleHandle );

typedef struct {
	ULONG Unknown[21];
	UNICODE_STRING CommandLine;
	UNICODE_STRING ImageFile;
} ENVIRONMENT_INFORMATION, *PENVIRONMENT_INFORMATION;

typedef struct {
	ULONG Unknown[2];
	PVOID ImageBase;
	PENVIRONMENT_INFORMATION Environment;
} STARTUP_ARGUMENT, *PSTARTUP_ARGUMENT;

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

#undef KdPrint
#define KdPrint(X) Print X

}
