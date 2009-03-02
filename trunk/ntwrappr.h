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

LONG 
NTAPI
ExceptionFilter(
	PEXCEPTION_POINTERS einfo
	);

HANDLE
NTAPI
OpenFile (
	PWSTR FileName, 
	ULONG AccessMode, 
	ULONG ShareMode, 
	ULONG Disposition, 
	ULONG Options
	);

ULONG 
NTAPI
ReadFile (
	HANDLE hFile, 
	PVOID Buffer, 
	ULONG MaxLen, 
	ULONG Position
	);

VOID
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

#ifdef SET_ENTRY
NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	);

VOID 
NTAPI 
EntryPoint(
	IN PSTARTUP_ARGUMENT Startup
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	__try
	{
		Print ("Env->Unknown: ");

		for (int i=0; i<21; i++)
		{
			Print("[%d] = %08x ", i, Startup->Environment->Unknown[i]);
		}

		Print ("Starting...\n");

		if (InitializeWrapper ())
		{
			Status = NativeEntry (	&Startup->Environment->ImageFile,
									&Startup->Environment->CommandLine );
		}
	}
	__except (ExceptionFilter(GetExceptionInformation()))
	{
		Status = GetExceptionCode();
	}

	KdPrint(("\n"));

	for (int i=10; i>0; i--)
	{
		KdPrint (("Waiting %2d seconds...\r", i));

		LARGE_INTEGER second = {-1000*10000, -1};
		ZwDelayExecution (FALSE, &second);
	}

	KdPrint(("\n"));

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
	PCLIENT_ID ClientId,
	BOOLEAN WaitForProcess
	);
