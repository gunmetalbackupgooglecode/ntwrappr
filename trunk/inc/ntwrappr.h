#pragma once

#ifndef _X86_

#define DBG 1
#define _X86_

#endif

#include "native.h"

/*
ULONG 
_cdecl 
DisplayString (
	PWSTR Format, 
	...
	);
*/

extern "C" {

LONG 
NTAPI
ExceptionFilter(
	PEXCEPTION_POINTERS einfo
	);

#include "file.h"

HANDLE
NTAPI
CreateFile (
	PWSTR FileName, 
	ULONG AccessMode, 
	ULONG ShareMode, 
	ULONG Disposition, 
	ULONG Options,
	ULONG Attributes
	);

HANDLE
NTAPI
OpenFile (
	PWSTR FileName,
	ULONG AccessMode,
	ULONG ShareAccess,
	ULONG OpenOptions
	);

ULONG 
NTAPI
ReadFile (
	HANDLE hFile, 
	PVOID Buffer, 
	ULONG MaxLen, 
	ULONG Position
	);

typedef const void *PCVOID;

ULONG 
NTAPI
WriteFile (
	HANDLE hFile, 
	PCVOID Buffer, 
	ULONG Length, 
	ULONG Position
	);

BOOLEAN
NTAPI
CloseHandle (
	HANDLE hObject
	);

BOOLEAN
NTAPI
QueryDirectory (
	HANDLE hDir, 
	BOOLEAN RestartScan,
	PFILE_BOTH_DIR_INFORMATION Buffer,
	ULONG MaxLen
	);

VOID
NTAPI
hfree (
	PVOID Ptr
	);

PVOID
NTAPI
halloc (
	SIZE_T Size
	);

BOOLEAN 
NTAPI
InitializeWrapper(
	);

PVOID
NTAPI
GetSystemInformation (
	SYSTEM_INFORMATION_CLASS InfoClass
	);

HANDLE 
NTAPI
OpenKeyboard (
	int nClass
	);

enum READ_CHAR_STATUS
{
	ReadCharFailure,	// Error occurred.
	ReadCharSystemKey,	// ReadChar() call should be repeated.
	ReadCharSuccess		// Key was successfully read
};

UCHAR
NTAPI
ReadChar (
	HANDLE hKeyboard, 
	char* Buffer
	);

ULONG
NTAPI
ReadString (
	HANDLE hKeyboard, 
	char *prompt,
	char *Buffer, 
	int MaxLen,
	char ReplaceChar
	);

HANDLE
NTAPI
GetDefaultKeyboard(
	);

ULONG
_cdecl
Print (
	PCH Format,
	...
	);

ULONG
_cdecl
PrintXY (
	int x,
	int y,
	PCH Format,
	...
	);

BOOLEAN
NTAPI
MemoryEnterProtectedSection(
    );

VOID
NTAPI
MemoryLeaveProtectedSection(
    );

#ifdef SET_ENTRY
NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	);

#ifdef ENTRY_SPEC
ENTRY_SPEC
#endif
VOID 
NTAPI 
EntryPoint(
	IN PPEB Peb
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOLEAN InProtectedSection = FALSE;

    // Put all initialization code in try-except block
	__try
	{
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters = Peb->ProcessParameters;

        // Normalize process parameters.
        // RtlCreateUserProcess de-normalizes parameters for new process and 
        // pointers in RTL_USER_PROCESS_PARAMETERS are converted to offsets.
        // RtlNormalizeProcessParams reverses this operation.
        RtlNormalizeProcessParams (ProcessParameters);

        // Initialize NT Wrapper DLL
		if (InitializeWrapper ())
		{
            // Enter memory protected section.
            // We can trace memory leaks now.
            if (!MemoryEnterProtectedSection())
            {
                Print("MemoryEnterProtectedSection() failed\n");
                Status = STATUS_UNSUCCESSFUL;
            }

            InProtectedSection = TRUE;

            Status = NativeEntry (	&ProcessParameters->ImagePathName,
                                    &ProcessParameters->CommandLine );

            // Leave memory protected section and check for leaks.
            MemoryLeaveProtectedSection ();

            InProtectedSection = FALSE;
        }
	}
	__except (ExceptionFilter(GetExceptionInformation()))
	{
		Status = GetExceptionCode();

#ifdef CHECK_FOR_LEAKS_ON_EXCEPTION
        if (InProtectedSection)
        {
            // Leave memory protected section and check for leaks.
            MemoryLeaveProtectedSection ();
        }
#endif

#ifdef FAIL_ON_EXCEPTION
		HARDERROR_RESPONSE Response;
		BOOLEAN Enabled;
		NTSTATUS St;

		for (int i=5; i>0; i--)
		{
			KdPrint (("Waiting %2d seconds...\r", i));

			LARGE_INTEGER second = {-1000*10000, -1};
			ZwDelayExecution (FALSE, &second);
		}

		St = RtlAdjustPrivilege (
			SE_SHUTDOWN_PRIVILEGE,
			TRUE,
			FALSE,
			&Enabled
			);

		if (!NT_SUCCESS(St))
			Print("RtlAdjustPrivilege failed with status %08x\n", St);
		else
		{
			Print("ZwRaiseHardError failed...with status %08x\n",
				ZwRaiseHardError (
					Status,
					1,
					NULL,
					(PVOID*) &Status,
					OptionShutdownSystem,
					&Response
					));
		}
#endif

#ifdef WAIT_N_SECONDS
		for (int i=10; i>0; i--)
		{
			KdPrint (("Waiting %2d seconds...\r", i));

			LARGE_INTEGER second = {-1000*10000, -1};
			ZwDelayExecution (FALSE, &second);
		}

#endif

//        KdPrint(("Loading Windows ...      \n"));
	}

	ZwTerminateProcess (NtCurrentProcess(), Status);
}
#endif

typedef struct _TASKLIST_CONTEXT
{
	PSYSTEM_PROCESSES_INFORMATION Buffer;
	PSYSTEM_PROCESSES_INFORMATION Proc;
} TASKLIST_CONTEXT, *PTASKLIST_CONTEXT;


BOOLEAN
NTAPI
ProcessFirst (
	PTASKLIST_CONTEXT *pContext
	);

BOOLEAN
NTAPI
ProcessNext (
	PTASKLIST_CONTEXT *Context
	);

HANDLE
NTAPI
CreateDirectory(
	PWSTR Path
	);

HANDLE
NTAPI
CreateSymbolicLink(
	PWSTR Name,
	PWSTR Target
	);

BOOLEAN
NTAPI
CreateProcess(
	PWSTR ApplicationName,
	PWSTR CommandLine,
	PCLIENT_ID ClientId,
	BOOLEAN WaitForProcess,
    BOOLEAN CreateSuspended,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation OPTIONAL
	);

BOOLEAN
NTAPI
CreateThread(
	HANDLE ProcessHandle,
	BOOLEAN CreateSuspended,
	PVOID StartAddress,
	PVOID Parameter OPTIONAL,
	PHANDLE ThreadHandle OPTIONAL,
	PCLIENT_ID ClientId OPTIONAL
	);


BOOLEAN
NTAPI
CommandLineToArgv(
	PSTR CommandLine,
	int *pArgc,
	PSTR *pArgv
	);

BOOLEAN
NTAPI
CommandLineToArgvW(
	PWSTR CommandLine,
	int *pArgc,
	PWSTR *pArgv
	);

VOID
NTAPI
SetLastStatus(
	NTSTATUS Status
	);

NTSTATUS
NTAPI
GetLastStatus(
	);

NTSTATUS
NTAPI
WinPathToNtPath(
	OUT PUNICODE_STRING NtPath,
	IN PUNICODE_STRING WinPath
	);

NTSTATUS
NTAPI
AllocateUnicodeString(
	OUT PUNICODE_STRING String,
	IN USHORT MaximumLength
	);

VOID
NTAPI
GetCurrentDirectory(
	OUT PUNICODE_STRING Path
	);

VOID
NTAPI
SetCurrentDirectory(
    IN PUNICODE_STRING Path
    );

VOID
NTAPI
SetProcessHeap(
	HANDLE hHeap
	);

HANDLE
NTAPI
GetProcessHeap(
	);

HANDLE
NTAPI
CreatePort(
	PWSTR PortName OPTIONAL,
	ULONG MaximumDataLength
	);

BOOLEAN
NTAPI
WaitReceivePort(
	HANDLE hPort,
	PLPC_MESSAGE Msg
	);

BOOLEAN
NTAPI
ReplyPort(
	HANDLE hPort,
	PLPC_MESSAGE Msg
	);

BOOLEAN
NTAPI
AcceptPort(
	PLPC_MESSAGE Msg,
	PHANDLE AcceptedHandle
	);

NTSTATUS
NTAPI
Sleep(
    ULONG Milliseconds
    );

VOID
NTAPI
DisableExitOnEsc(
    );

PVOID
NTAPI
LoadDll(
    PWSTR ImagePath,
    ULONG Chars
    );

PVOID
NTAPI
FindDll(
    PWSTR ImagePath
    );

PVOID
NTAPI
GetProcedureAddress(
    PVOID ImageBase,
    PCHAR ProcedureName
    );

BOOLEAN
NTAPI
TryExit(
    );

int _cdecl str_replace_char (char *string, char ch1, char ch2);
int _cdecl stri_replace_char (char *string, char ch1, char ch2);

BOOLEAN
NTAPI
CheckNtStatus(
	NTSTATUS Status
	);

HANDLE
NTAPI
CreateEvent(
    ULONG AccessMask,
    PWSTR wEventName OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
    );

HANDLE
NTAPI
OpenEvent(
    ULONG AccessMask,
    PWSTR Name
    );

#define EVENT_STATE_ERROR   ((ULONG)-1)

ULONG
NTAPI
SetEvent(
    HANDLE hEvent
    );

}

char* _cdecl strdup (char* s);

#if NTWRAPPR
#undef NT_SUCCESS
#define NT_SUCCESS(STATUS) CheckNtStatus(STATUS)
#endif
