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

static
BOOLEAN
CheckNtStatus(
	NTSTATUS Status
	)
{
	if (!NT_SUCCESS(Status))
	{
		SetLastStatus (Status);
		return FALSE;
	}
	return TRUE;
}

#undef NT_SUCCESS
#define NT_SUCCESS(STATUS) CheckNtStatus(STATUS)

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


#define VK_BACKSPACE 8

char ascii_codes[] =
{
	0,0,'1','2','3','4','5','6','7','8','9','0','-','=',VK_BACKSPACE,0,
	'q','w','e','r','t','y','u','i','o','p','[',']','\n',0,
	'a','s','d','f','g','h','j','k','l',';','\'', '`',0,
	'\\','z','x','c','v','b','n','m',',','.','/',0,'*',0,
	' ',0, 0,0,0,0,0,0,0,0,0,0, 0,0, '7','8','9','-','4','5',
	'6','+','1','2','3','0','.', 0,0
};

char ascii_codes_shifted[] =
{
	0,0,'!','@','#','$','%','^','&','*','(',')','_','+',VK_BACKSPACE,0,
	'Q','W','E','R','T','Y','U','I','O','P','{','}','\n',0,
	'A','S','D','F','G','H','J','K','L',':','"', '~',0,
	'|','Z','X','C','V','B','N','M','<','>','?',0,'*',0,
	' ',0, 0,0,0,0,0,0,0,0,0,0, 0,0, '7','8','9','-','4','5',
	'6','+','1','2','3','0','.', 0,0
};

BOOLEAN Shifted = FALSE;
BOOLEAN CapsLock = FALSE;

VOID
NTAPI
CloseHandle (
	HANDLE hObject
	)
{
	ZwClose (hObject);
}

//
// Open any file
//

HANDLE
NTAPI
OpenFile (
	PWSTR FileName,
	ULONG AccessMode,
	ULONG ShareAccess,
	ULONG OpenOptions
	)
{
	UNICODE_STRING Name;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	HANDLE Handle;
	OBJECT_ATTRIBUTES Oa;

	RtlInitUnicodeString (&Name, FileName);
	InitializeObjectAttributes (&Oa, &Name, OBJ_CASE_INSENSITIVE, 0, 0);

	Status = ZwOpenFile (
		&Handle,
		AccessMode,
		&Oa,
		&IoStatus,
		ShareAccess,
		OpenOptions
		);

	if (NT_SUCCESS(Status))
		return Handle;

	KdPrint (( "ZwOpenFile for [%S] returned ntstatus %08x\n", FileName, Status ));
	return NULL;

}

HANDLE
NTAPI
CreateFile (
	PWSTR FileName, 
	ULONG AccessMode, 
	ULONG ShareMode, 
	ULONG Disposition, 
	ULONG Options,
	ULONG Attributes
	)
{
	UNICODE_STRING Name;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	HANDLE Handle;
	OBJECT_ATTRIBUTES Oa;

	RtlInitUnicodeString (&Name, FileName);
	InitializeObjectAttributes (&Oa, &Name, OBJ_CASE_INSENSITIVE, 0, 0);

	Status = ZwCreateFile (
		&Handle,
		AccessMode,
		&Oa,
		&IoStatus,
		NULL,
		Attributes,
		ShareMode,
		Disposition,
		Options,
		0,
		0);

	if (NT_SUCCESS(Status))
		return Handle;

	KdPrint (( "ZwCreateFile for [%S] returned ntstatus %08x\n", FileName, Status ));
	return NULL;
}

//
// Read the file
//

ULONG 
NTAPI
ReadFile (
	HANDLE hFile, 
	PVOID Buffer, 
	ULONG MaxLen, 
	ULONG Position
	)
{
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	LARGE_INTEGER Pos = {0};
	HANDLE hEvent;
	OBJECT_ATTRIBUTES EventAttributes;

	Pos.LowPart = Position;

	InitializeObjectAttributes (
		&EventAttributes,
		0, 0, 0, 0 );

	Status = ZwCreateEvent (
		&hEvent,
		EVENT_ALL_ACCESS,
		&EventAttributes,
		SynchronizationEvent,
		0 );

	if (!NT_SUCCESS(Status))
	{
		KdPrint (("ZwCreatEvent failed with status %08x\n", Status));
		return -1;
	}

	Status = ZwReadFile (
		hFile,
		hEvent,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		MaxLen,
		Position == -1 ? NULL : &Pos,
		NULL );
	
	if (Status == STATUS_PENDING)
	{
		Status = ZwWaitForSingleObject (hEvent, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if (NT_SUCCESS(Status))
	{
		ZwClose (hEvent);
		return IoStatus.Information;
	}

	if (Status != STATUS_END_OF_FILE)
	{
		KdPrint (("ZwReadFile failed with status %08x\n", Status));
		return -1;
	}
	
	return -2;
}

ULONG 
NTAPI
WriteFile (
	HANDLE hFile, 
	PVOID Buffer, 
	ULONG Length, 
	ULONG Position
	)
{
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	LARGE_INTEGER Pos = {0};
	HANDLE hEvent;
	OBJECT_ATTRIBUTES EventAttributes;

	Pos.LowPart = Position;

	InitializeObjectAttributes (
		&EventAttributes,
		0, 0, 0, 0 );

	Status = ZwCreateEvent (
		&hEvent,
		EVENT_ALL_ACCESS,
		&EventAttributes,
		SynchronizationEvent,
		0 );

	if (!NT_SUCCESS(Status))
	{
		KdPrint (("ZwCreatEvent failed with status %08x\n", Status));
		return -1;
	}

	Status = ZwWriteFile (
		hFile,
		hEvent,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		Length,
		Position == -1 ? NULL : &Pos,
		NULL );
	
	if (Status == STATUS_PENDING)
	{
		Status = ZwWaitForSingleObject (hEvent, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if (NT_SUCCESS(Status))
	{
		ZwClose (hEvent);
		return IoStatus.Information;
	}

	KdPrint (("ZwWriteFile failed with status %08x\n", Status));
	return -1;
}

//
// Query directory file
//

BOOLEAN
NTAPI
QueryDirectory (
	HANDLE hDir, 
	BOOLEAN RestartScan,
	PFILE_BOTH_DIR_INFORMATION Buffer,
	ULONG MaxLen
	)
{
	HANDLE hEvent;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Oa = {sizeof(Oa)};
	IO_STATUS_BLOCK IoStatus;
	
	Status = ZwCreateEvent (&hEvent, EVENT_ALL_ACCESS, &Oa,
		SynchronizationEvent, FALSE);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ZwCreateEvent failed with status %08x\n", Status));
		return NULL;
	}

	Status = ZwQueryDirectoryFile (
		hDir,
		hEvent,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		MaxLen,
		FileBothDirectoryInformation,
		TRUE,
		NULL,
		RestartScan
		);

	ZwClose (hEvent);
	return NT_SUCCESS(Status);
}


HANDLE heap;

#define HEAP_NO_SERIALIZE               0x00000001      
#define HEAP_GROWABLE                   0x00000002      
#define HEAP_ZERO_MEMORY                0x00000008      

VOID
NTAPI
hfree (
	PVOID Ptr
	)
{
	RtlFreeHeap (heap, 0, Ptr);
}

PVOID
NTAPI
halloc (
	SIZE_T Size
	)
{
	return RtlAllocateHeap (heap, HEAP_ZERO_MEMORY, Size);
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

//
// Open keyboard device & return its handle
//
HANDLE 
NTAPI
OpenKeyboard (
	int nClass
	)
{
	wchar_t buff[32];

	_snwprintf (buff, sizeof(buff)-1, L"\\Device\\KeyboardClass%d", nClass);

	return CreateFile (buff, 
		GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES, 
		0,
		FILE_OPEN,
		1,
		FILE_ATTRIBUTE_NORMAL);
}

//
// ReadChar() - read character from keyboard with ascii translation
//

UCHAR
NTAPI
ReadChar (
	HANDLE hKeyboard, 
	char* Buffer
	)
{
	KEYBOARD_INPUT_DATA InputData[1];
	UCHAR Ret = ReadCharFailure;
	ULONG BytesRead = 0;

	//
	// Read from keyboard
	//

	memset (&InputData, 0, sizeof(InputData));

	BytesRead = ReadFile (hKeyboard, &InputData, sizeof(InputData), 0);

	if (BytesRead != -1)
	{
		if (!BytesRead || (BytesRead % sizeof(KEYBOARD_INPUT_DATA)))
		{
			KdPrint (("ZwReadFile returned %d bytes - INVALID SIZE\n",BytesRead));
			goto _exit;
		}

		//
		// Get scan-code and other values
		//

		USHORT  ScanCode = InputData->MakeCode;
		BOOLEAN Extended = InputData->Flags & KEY_E0;
		BOOLEAN Up = InputData->Flags & KEY_BREAK;

		char ascii;
		
		if (Shifted)
			ascii = ascii_codes_shifted[ScanCode];
		else
			ascii = ascii_codes [ScanCode];

		if (ascii)
		{
			//
			// If user released ascii key, skip this.
			//

			if (Up)
			{
				Ret = ReadCharSystemKey;
			}
			else
			{
				//
				// Else write ascii code to buffer
				//

				Ret = ReadCharSuccess;
				*Buffer = ascii;
			}
		}
		else
		{
			//
			// User pressed/released system key
			//

			Ret = ReadCharSystemKey;
			
			switch (ScanCode)
			{
			case 0x2A:	// Left shift
			case 0x36:	// Right shift
				
				if (Up == 0)
					Shifted = !CapsLock;
				else
					Shifted = CapsLock;
				break;

			case 0x3A:	// Caps lock

				if (Up == 0)
					CapsLock = !CapsLock;

				break;

#if DBG
			case 1: // Escape
				
				//
				// Terminate now.. in debugging purposes.
				//
				RtlRaiseStatus (MANUALLY_INITIATED_CRASH);
				break;
#endif

			}
		}
	}

_exit:
	return Ret;
}

//
// Read null-terminated string from keyboard.
// User presses some keys and finishes with ENTER
//
ULONG
NTAPI
ReadString (
	HANDLE hKeyboard, 
	char *prompt,
	char *Buffer, 
	int MaxLen,
	char ReplaceChar
	)
{
	int i;

	Print("%s", prompt);

	for (i=0; i<MaxLen; i++)
	{
		UCHAR Status;

		do
		{
			Status = ReadChar (hKeyboard, &Buffer[i]);
			//DisplayString(L".");
		}
		while (Status == ReadCharSystemKey);

		if (Buffer[i] == VK_BACKSPACE)
		{
			if (i == 0)
			{
				i--;
				continue;
			}

			i-=2;

			Buffer[i+1] = ' ';

			int j;

			Print("\r%s", prompt);
			for (j=0; j<=i; j++)
			{
				Print("%c", ReplaceChar ? ReplaceChar : Buffer[j]);
			}

			Print(" \r%s", prompt);
			for (j=0; j<=i; j++)
			{
				Print("%c", ReplaceChar ? ReplaceChar : Buffer[j]);
			}

			continue;
		}

		if (Buffer[i] == '\n')
		{
			Print("\n");
			break;
		}

		Print("%c", ReplaceChar ? ReplaceChar : Buffer[i]);
	}

	Buffer[i] = 0;
	return i;
}

HANDLE hKeyboard;

HANDLE
NTAPI
GetDefaultKeyboard(
	)
{
	return hKeyboard;
}

BOOLEAN bWrapperInitialized = FALSE;

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

BOOLEAN
NTAPI
ProcessFirst (
	PTASKLIST_CONTEXT *pContext
	)
{
	PTASKLIST_CONTEXT Context;

	Context = (PTASKLIST_CONTEXT) halloc (sizeof(TASKLIST_CONTEXT));
	if (Context)
	{
		Context->Buffer = (PSYSTEM_PROCESSES_INFORMATION)
			GetSystemInformation (SystemProcessesAndThreadsInformation);

		if (Context->Buffer)
		{
			Context->Proc = Context->Buffer;

			*pContext = Context;

			return TRUE;
		}

		hfree (Context);
	}

	return FALSE;
}

BOOLEAN
NTAPI
ProcessNext (
	PTASKLIST_CONTEXT *Context
	)
{
	if ((*Context)->Proc->NextEntryDelta)
	{
		*(ULONG*)&(*Context)->Proc += (*Context)->Proc->NextEntryDelta;
		return TRUE;
	}

	hfree ((*Context)->Buffer);
	hfree (*Context);
	*Context = NULL;
	
	return FALSE;
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

BOOLEAN
NTAPI
CreateProcess(
	PWSTR ApplicationName,
	PWSTR CommandLine,
	PCLIENT_ID ClientId OPTIONAL,
	BOOLEAN WaitForProcess
	)
{
	BOOLEAN Succeeded = FALSE;
	UNICODE_STRING ImagePath, CmdLine;
	RTL_USER_PROCESS_INFORMATION Info = {0};
	PRTL_USER_PROCESS_PARAMETERS Params = NULL;
	NTSTATUS Status;

	RtlInitUnicodeString (&ImagePath, ApplicationName);
	RtlInitUnicodeString (&CmdLine, CommandLine);

	Status = RtlCreateProcessParameters (
		&Params,
		&ImagePath,
		NULL,
		NULL,
		&CmdLine,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
		);

	if (NT_SUCCESS(Status))
	{
		Status = RtlCreateUserProcess (
			&ImagePath,
			OBJ_CASE_INSENSITIVE,
			Params,
			NULL,
			NULL,
			NtCurrentProcess (),
			FALSE,
			NULL,
			NULL,
			&Info
			);

		if (NT_SUCCESS(Status))
		{
			Status = ZwResumeThread (Info.ThreadHandle, NULL);

			if (!NT_SUCCESS(Status))
			{
				Print("ZwResumeThread = %08x\n", Status);
			}
			else
			{
				Succeeded = TRUE;

				if (ClientId)
					*ClientId = Info.ClientId;

				if (WaitForProcess)
				{
					Status = ZwWaitForSingleObject (
						Info.ProcessHandle,
						FALSE,
						NULL
						);

					if (!NT_SUCCESS(Status))
					{
						Print("ZwWaitForSingleObject = %08x\n", Status);
					}
				}
			}
		}
		else
		{
			Print("RtlCreateUserProcess = %08x\n", Status);
		}

		RtlDestroyProcessParameters (Params);
	}
	else
	{
		Print("RtlCreateProcessParameters = %08x\n", Status);
	}

	return Succeeded;
}

BOOLEAN
NTAPI
CreateThread(
	HANDLE ProcessHandle,
	BOOLEAN CreateSuspended,
	PVOID StartAddress,
	PVOID Parameter OPTIONAL,
	PHANDLE ThreadHandle OPTIONAL,
	PCLIENT_ID ClientId OPTIONAL
	)
{
	ULONG StackLimit = 0;
	ULONG StackBase = 0;
	NTSTATUS Status;
	HANDLE hThread;
	CLIENT_ID Cid;

	Status = RtlCreateUserThread (
		ProcessHandle,
		NULL,
		CreateSuspended,
		0,
		0,
		PAGE_SIZE,
		StartAddress,
		Parameter,
		&hThread,
		&Cid
		);

	if (NT_SUCCESS(Status))
	{
		KdPrint(("RtlCreateUserThread OK, stack: %08x %08x h %08x TID %08x PID %08x\n",
			StackLimit,
			StackBase,
			hThread,
			Cid.UniqueThread,
			Cid.UniqueProcess
			));

		if (ThreadHandle)
			*ThreadHandle = hThread;
		else
			CloseHandle (hThread);

		if (ClientId)
			*ClientId = Cid;

		return TRUE;
	}

	KdPrint(("RtlUserCreateProcess failed with status %08x\n", Status));

	return FALSE;
}

BOOLEAN
NTAPI
CommandLineToArgv(
	PSTR CommandLine,
	int *pArgc,
	PSTR *pArgv
	)
{
	char *ptr;
	char **args = pArgv;

	for (ptr = CommandLine; isspace(*ptr); ptr++);

	ULONG l = strlen(ptr);
	while (isspace(ptr[l-1]))
	{
		l --;
		ptr[l] = 0;
	}

	if (strlen(ptr) == 0)
		return FALSE;

	int arg=0;
	char *prev = ptr;

	for (char *sp = ptr; ; sp++)
	{
		if (*sp == 0)
		{
			args[arg++] = prev;
			break;
		}

		if (isspace(*sp))
		{
			*(sp++) = 0;
			args[arg++] = prev;

			if (arg == 20)
				break;
			
			while (isspace(*sp))
				sp++;

			prev = sp;
		}
	}

	*pArgc = arg;

	return TRUE;
}

BOOLEAN
NTAPI
CommandLineToArgvW(
	PWSTR CommandLine,
	int *pArgc,
	PWSTR *pArgv
	)
{
	wchar_t *ptr;
	wchar_t **args = pArgv;

	for (ptr = CommandLine; isspace(*ptr); ptr++);

	ULONG l = wcslen(ptr);
	while (isspace(ptr[l-1]))
	{
		l --;
		ptr[l] = 0;
	}

	if (wcslen(ptr) == 0)
		return FALSE;

	int arg=0;
	wchar_t *prev = ptr;

	for (wchar_t *sp = ptr; ; sp++)
	{
		if (*sp == 0)
		{
			args[arg++] = prev;
			break;
		}

		if (iswspace(*sp))
		{
			*(sp++) = 0;
			args[arg++] = prev;

			if (arg == 20)
				break;
			
			while (iswspace(*sp))
				sp++;

			prev = sp;
		}
	}

	*pArgc = arg;

	return TRUE;
}

NTSTATUS
NTAPI
WinPathToNtPath(
	OUT PUNICODE_STRING NtPath,
	IN PUNICODE_STRING WinPath
	)
{
	RtlInitUnicodeString (NtPath, L"\\??\\");
	return RtlAppendUnicodeStringToString (NtPath, WinPath);
}

NTSTATUS
NTAPI
AllocateUnicodeString(
	OUT PUNICODE_STRING String,
	IN USHORT MaximumLength
	)
{
	String->Length = 0;
	String->MaximumLength = MaximumLength;
	String->Buffer = (PWSTR) halloc (MaximumLength);
	if (String->Buffer == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	String->Buffer[0] = L'\0';
	return STATUS_SUCCESS;
}

VOID
NTAPI
SetProcessHeap(
	HANDLE hHeap
	)
{
	NtCurrentTeb()->Peb->ProcessHeap = hHeap;
}

HANDLE
NTAPI
GetProcessHeap(
	)
{
	return NtCurrentTeb()->Peb->ProcessHeap;
}

VOID
NTAPI
GetCurrentDirectory(
	OUT PUNICODE_STRING Path
	)
{
	Path->Length = RtlGetCurrentDirectory_U (Path->MaximumLength, Path->Buffer);
}

HANDLE
NTAPI
CreatePort(
	PWSTR PortName OPTIONAL,
	ULONG MaximumDataLength
	)
{
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING Name;
	NTSTATUS Status;
	HANDLE hPort = NULL;

	if (PortName)
	{
		RtlInitUnicodeString (&Name, PortName);
		InitializeObjectAttributes (&Oa, &Name, OBJ_CASE_INSENSITIVE, 0, 0);
	}
	else
	{
		InitializeObjectAttributes (&Oa, 0, 0, 0, 0);
	}

	if (MaximumDataLength == 0)
		MaximumDataLength = 0x130;

	Status = ZwCreatePort(
		&hPort,
		&Oa,
		0,
		MaximumDataLength,
		NULL
		);

	return NT_SUCCESS(Status) ? hPort : NULL;
}

BOOLEAN
NTAPI
WaitReceivePort(
	HANDLE hPort,
	PLPC_MESSAGE Msg
	)
{
	NTSTATUS Status;

	Status = ZwReplyWaitReceivePort (
		hPort,
		NULL,
		NULL,
		Msg
		);

	return NT_SUCCESS(Status);
}

BOOLEAN
NTAPI
ReplyPort(
	HANDLE hPort,
	PLPC_MESSAGE Msg
	)
{
	NTSTATUS Status;

	Status = ZwReplyPort (hPort, Msg);

	return NT_SUCCESS(Status);
}

BOOLEAN
NTAPI
AcceptPort(
	PLPC_MESSAGE Msg,
	PHANDLE AcceptedHandle
	)
{
	NTSTATUS Status;

	Status = ZwAcceptConnectPort (
		AcceptedHandle,
		NULL,
		Msg,
		TRUE,
		NULL,
		NULL
		);

	if (NT_SUCCESS(Status))
	{
		Status = ZwCompleteConnectPort (*AcceptedHandle);
	}

	return NT_SUCCESS(Status);
}
