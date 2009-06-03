//
// NT Wrapper Source
//
// (C) Great, 2006-2009
//

#include "ntwrappr.h"

/*
ULONG
_cdecl 
DisplayString (
	PWSTR Format, 
	...
	)
{
	UNICODE_STRING us;
	wchar_t Buffer[1024];
	char cBuffer[1024];
	va_list va;
	ULONG nSymbols;
	ANSI_STRING us;

	va_start (va, Format);

	_vsnprintf (cBuffer, 

	nSymbols = _vsnwprintf (Buffer, sizeof(Buffer)-1, Format, va);

	RtlInitUnicodeString (&us, Buffer);
	
	if (!NT_SUCCESS(ZwDisplayString (&us)))
		nSymbols = 0;

	return nSymbols;
}
*/

VOID
NTAPI
SetLastStatus(
	NTSTATUS Status
	)
{
	// Use this place to store NTSTATUS.
	RtlSetLastWin32Error (Status);
}

NTSTATUS
NTAPI
GetLastStatus(
	)
{
	return RtlGetLastWin32Error ();
}

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

/*
#pragma pack(push,1)
struct WRITE_STRUCT
{
	ULONG X;
	ULONG Y;
	UCHAR Unk1;
	CHAR Buffer[1024];
};
#pragma pack(pop)

HANDLE hPrint;

ULONG
_cdecl
PrintXY (
	int x,
	int y,
	PCH Format,
	...
	)
{
	WRITE_STRUCT ws;
	va_list va;
	ULONG nSymbols;

	va_start (va, Format);

	ws.X = (ULONG) x;
	ws.Y = (ULONG) y;
	ws.Unk1 = TRUE;

	nSymbols = _vsnprintf (ws.Buffer, sizeof(ws.Buffer)-1, Format, va);

	if (hPrint == NULL)
	{
		hPrint = CreateFile (L"\\Device\\DisplayStringXY", 
			GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
			FILE_ATTRIBUTE_NORMAL
			);

		if (hPrint == NULL)
		{
			KdPrint(("OpenFile failed for driver\n"));
			return 0;
		}
	}

	WriteFile (hPrint, &ws, sizeof(ws), -1);

	return nSymbols;
}
*/

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


BOOLEAN
NTAPI
CloseHandle (
	HANDLE hObject
	)
{
	return NT_SUCCESS (ZwClose (hObject));
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


HANDLE
NTAPI
CreateDirectory(
	PWSTR Path
	)
{
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING us;
	HANDLE hDir;
	NTSTATUS Status;

	RtlInitUnicodeString (&us, Path);
	InitializeObjectAttributes (&Oa, &us, 0, 0, 0);

	Status = ZwCreateDirectoryObject (
		&hDir,
		DIRECTORY_ALL_ACCESS,
		&Oa
		);

	if (!NT_SUCCESS(Status))
		hDir = NULL;

	return hDir;
}

HANDLE
NTAPI
CreateSymbolicLink(
	PWSTR Name,
	PWSTR Target
	)
{
	NTSTATUS Status;
	HANDLE hLink;
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING Src, Dst;

	RtlInitUnicodeString (&Src, Name);
	RtlInitUnicodeString (&Dst, Target);
	InitializeObjectAttributes (&Oa, &Src, 0, 0, 0);

	Status = ZwCreateSymbolicLinkObject (
		&hLink,
		FILE_READ_ATTRIBUTES,
	  	&Oa,
		&Dst
		);

	if (!NT_SUCCESS(Status))
		hLink = NULL;

	return hLink;
}

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

HANDLE
NTAPI
CreateEvent(
    ULONG AccessMask,
    PWSTR wEventName OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING EventName, *pEventName = NULL;
    HANDLE EventHandle;

    if (ARGUMENT_PRESENT(wEventName))
    {
        RtlInitUnicodeString (&EventName, wEventName);
        pEventName = &EventName;
    }

    InitializeObjectAttributes (&Oa, pEventName, 0, 0, 0);

    Status = ZwCreateEvent (
        &EventHandle,
        AccessMask,
        &Oa,
        EventType,
        InitialState);

    if (!NT_SUCCESS(Status))
    {
        EventHandle = NULL;
    }

    return EventHandle;
}

HANDLE
NTAPI
OpenEvent(
    ULONG AccessMask,
    PWSTR Name
    )
{
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING EventName;
    NTSTATUS Status;
    HANDLE EventHandle;

    RtlInitUnicodeString (&EventName, Name);
    InitializeObjectAttributes (&Oa, &EventName, OBJ_CASE_INSENSITIVE, 0, 0);

    Status = ZwOpenEvent (
        &EventHandle,
        AccessMask,
        &Oa);

    if (!NT_SUCCESS(Status))
    {
        EventHandle = NULL;
    }

    return EventHandle;
}

ULONG
NTAPI
SetEvent(
    HANDLE hEvent
    )
{
    ULONG PreviousState;
    NTSTATUS Status;

    Status = ZwSetEvent (hEvent, &PreviousState);
    if (!NT_SUCCESS(Status))
    {
        PreviousState = EVENT_STATE_ERROR;
    }

    return PreviousState;
}
