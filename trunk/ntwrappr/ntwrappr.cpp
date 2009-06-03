//
// NT Wrapper Source
//
// (C) Great, 2006-2009
//

#include "ntwrappr.h"

BOOLEAN
CheckNtStatus(
	NTSTATUS Status
	)
{
	if (Status < 0)
	{
		SetLastStatus (Status);
		return FALSE;
	}
	return TRUE;
}

ULONG
_cdecl
Print (
	PCH Format,
	...
	)
{
	ANSI_STRING as;
	char Buffer[1024];
	va_list va;
	UNICODE_STRING us;
	NTSTATUS Status;
	ULONG nSymbols;

	va_start (va, Format);

	nSymbols = _vsnprintf (Buffer, sizeof(Buffer)-1, Format, va);

	RtlInitAnsiString (&as, Buffer);
	Status = RtlAnsiStringToUnicodeString (&us, &as, TRUE);
	if (NT_SUCCESS(Status))
	{
		if (!NT_SUCCESS(ZwDisplayString (&us)))
			nSymbols = 0;

		RtlFreeUnicodeString (&us);
	}
	else nSymbols = 0;

	return nSymbols;
}

#ifdef NTTEST
extern "C" int _cdecl printf (const char*, ...);
#define Print printf
#endif

//
// Native exception filter
//
LONG 
NTAPI
ExceptionFilter(
	PEXCEPTION_POINTERS einfo
	)
{
	PEXCEPTION_RECORD erec = einfo->ExceptionRecord;

	if (erec->ExceptionCode != MANUALLY_INITIATED_CRASH)
	{
		Print (
			"********************************************\n"
			"*       Unhandled exception caught         *\n"
			"********************************************\n"
			"Exception Record: %08x\n"
			"Context Record: %08x\n"
			"********************************************\n"
			"Exception %08x occurred at %08x\n"
			"Number parameters: %d\n"
			"Parameters: %08x %08x %08x %08x\n"
			"The process will be terminated\n"
			"********************************************\n"
			,
			einfo->ExceptionRecord,
			einfo->ContextRecord,
			erec->ExceptionCode,
			erec->ExceptionAddress,
			erec->NumberParameters,
			erec->ExceptionInformation[0],
			erec->ExceptionInformation[1],
			erec->ExceptionInformation[2],
			erec->ExceptionInformation[3]
			);
	}
	else
	{
		ZwTerminateProcess (NtCurrentProcess(), 
			MANUALLY_INITIATED_CRASH);
	}

	return EXCEPTION_EXECUTE_HANDLER;
}


PVOID
NTAPI
GetSystemInformation (
	SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	NTSTATUS Status;
	PVOID Buffer;
	ULONG Size = PAGE_SIZE;

	do
	{
		Buffer = halloc (Size);

		Status = ZwQuerySystemInformation ( InfoClass,
											Buffer,
											Size,
											&Size );

		if (Status == STATUS_INFO_LENGTH_MISMATCH)
			hfree (Buffer);

	}
	while (Status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Status))
	{
		hfree (Buffer);
		return NULL;
	}

	return Buffer;
}


BOOLEAN bWrapperInitialized = FALSE;
extern HANDLE hKeyboard;
extern HANDLE heap;

#define HEAP_NO_SERIALIZE               0x00000001      
#define HEAP_GROWABLE                   0x00000002      

BOOLEAN
NTAPI
InitializeWrapper(
	)
{
//	KdPrint(("Initializing wrapper.\n"));

	if (bWrapperInitialized)
	{
		KdPrint(("Already initialized.\n"));
		return TRUE;
	}

//	KdPrint(("Creating heap\n"));

	heap = RtlCreateHeap (HEAP_GROWABLE|HEAP_NO_SERIALIZE, 0, 0, 0, 0, 0);

	if (heap == NULL)
	{
		KdPrint(("RtlCreateHeap failed!\n"));
		return FALSE;
	}

	SetProcessHeap (heap);

//	KdPrint(("heap = %08x\n", heap));

	for (int i=0; i<10; i++)
	{
		if (hKeyboard = OpenKeyboard (i))
		{
//			KdPrint(("Found keyboard class N%u\n", i));
			break;
		}
	}

//	KdPrint(("hKeyboard = %08x\n", hKeyboard));

	if (hKeyboard == NULL)
	{
		KdPrint(("Could not open keyboard.\n"));
		return FALSE;
	}

//	KdPrint(("Initialization successful\n"));

	bWrapperInitialized = TRUE;
	return TRUE;
}

char CurrentDirectory[1024] = "\\";


#ifndef NTTEST
NTSTATUS
NTAPI
Sleep(
    ULONG Milliseconds
    )
{
    if (Milliseconds != -1)
    {
        LARGE_INTEGER Timeout = { - 10000 * Milliseconds, -1 };
        return ZwDelayExecution (FALSE, &Timeout);
    }

    return ZwDelayExecution (FALSE, NULL);
}
#endif

