#pragma once

#define NTWRAPPER_VERSION_A "0.3.0-alpha"
#define NTWRAPPER_VERSION_W L"0.3.0-alpha"

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

#include "files.h"

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


#include "procthrd.h"
#include "runtime.h"
#include "objects.h"

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


}

char* _cdecl strdup (char* s);

#if NTWRAPPR
#undef NT_SUCCESS
#define NT_SUCCESS(STATUS) CheckNtStatus(STATUS)
#endif
