//
// Tiny Native command processor
//
// (C) Great, 2006-2008
//

#include "ntwrappr.h"

//NTSTATUS NativeEntry(IN PUNICODE_STRING ImageFile, IN PUNICODE_STRING CommandLine);

//
// Display formatted unicode string
//

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
			"Exception %08x occurred at %08x\n"
			"Number parameters: %d\n"
			"Parameters: %08x %08x %08x %08x\n"
			"The process will be terminated\n",
			erec->ExceptionCode,
			erec->ExceptionAddress,
			erec->NumberParameters,
			erec->ExceptionInformation[0],
			erec->ExceptionInformation[1],
			erec->ExceptionInformation[2],
			erec->ExceptionInformation[3]
			);
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
	PCLIENT_ID ClientId,
	BOOLEAN WaitForProcess
	)
{
	BOOLEAN Succeeded = FALSE;

	/*
	IO_STATUS_BLOCK IoStatus;
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING Name;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	HANDLE hProcess = NULL;
	NTSTATUS Status;
	HANDLE hThread = NULL;

	__try
	{
		RtlInitUnicodeString (&Name, ApplicationName);
		InitializeObjectAttributes (&Oa,
			&Name,
			OBJ_CASE_INSENSITIVE,
			0,
			NULL
			);

		Status = ZwOpenFile (
			&hFile,
			SYNCHRONIZE | FILE_EXECUTE,
			&Oa,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_DELETE,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
			);

		KdPrint(("ZwOpenFile = %08x\n", Status));

		if (!NT_SUCCESS(Status))
			__leave;

		Status = ZwCreateSection (
			&hSection,
			SECTION_ALL_ACCESS,
			NULL,
			NULL,
			PAGE_EXECUTE,
			SEC_IMAGE,
			hFile
			);

		KdPrint(("ZwCreateSection = %08x\n", Status));

		ZwClose (hFile);
		hFile = NULL;

		if (!NT_SUCCESS(Status))
			__leave;

		SECTION_IMAGE_INFORMATION ImageInfo;

		Status = ZwQuerySection (
			hSection,
			SectionImageInformation,
			&ImageInfo,
			sizeof(ImageInfo),
			NULL
			);

		KdPrint(("ZwQuerySection = %08x\n", Status));

		if (!NT_SUCCESS(Status))
			__leave;

		PVOID EntryPoint = ImageInfo.EntryPoint;

		KdPrint(("EntryPoint = %08x\n", EntryPoint));

		InitializeObjectAttributes (&Oa, 0, 0, 0, 0);

		Status = ZwCreateProcess (
			&hProcess,
			PROCESS_ALL_ACCESS,
			&Oa,
			NtCurrentProcess(),
			FALSE,
			hSection,
			NULL,
			NULL
			);

		KdPrint(("ZwCreateProcess = %08x\n", Status));

		if (!NT_SUCCESS(Status))
			__leave;

		PROCESS_BASIC_INFORMATION Proc;

		Status = ZwQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&Proc,
			sizeof (Proc),
			NULL
			);

		KdPrint(("ZwQueryInformationProcess = %08x, PEB %08x\n", Status, Proc.PebBaseAddress));

		if (!NT_SUCCESS(Status))
			__leave;

		PVOID Peb = Proc.PebBaseAddress;

		// PUSH some parameters in PEB


		//
		// Create the thread.
		//

		INITIAL_TEB Teb = {0};
		CONTEXT Context = {0};
		ULONG AllocSize = PAGE_SIZE * 4;
		PVOID p;
		ULONG OldProtect;
		CLIENT_ID Cid;
		PVOID Stack = NULL;

		Status = ZwAllocateVirtualMemory (
			hProcess,
			&Stack,
			0,
			&AllocSize,
			MEM_RESERVE|MEM_COMMIT,
			PAGE_READWRITE
			);

		KdPrint(("ZwAllocateVirtualMemory = %08x, * = %08x\n", Status, Stack));

		if (NT_SUCCESS(Status))
		{
			Teb.StackAllocationBase = Stack;
			Teb.StackBase = (PCHAR) Stack + AllocSize;

			{
				AllocSize = PAGE_SIZE;
				Status = ZwProtectVirtualMemory (
					hProcess,
					&Stack,
					&AllocSize,
					PAGE_READWRITE | PAGE_GUARD,
					&OldProtect
					);

				KdPrint(("ZwProtectVirtualMemory = %08x\n", Status));

				if (NT_SUCCESS(Status))
				{
					Context.ContextFlags = CONTEXT_FULL;
					Context.SegCs = 0x1b;
					Context.SegFs = 0x3b;
					Context.SegEs = 0x23;
					Context.SegDs = 0x23;
					Context.SegSs = 0x23;
					Context.SegGs = 0x00;
					Context.EFlags = 0x202;

					Context.Esp = (ULONG)Teb.StackBase - 4;
					Context.Eip = (ULONG) EntryPoint;
					
					InitializeObjectAttributes (&Oa, 0, 0, 0, 0);

					Status = ZwCreateThread (
						&hThread,
						THREAD_ALL_ACCESS,
						&Oa,
						hProcess,
						&Cid,
						&Context,
						(PINITIAL_TEB) &Teb,
						TRUE
						);

					KdPrint(("ZwCreateThread = %08x, hThread %08x\n", Status, hThread));

					if (NT_SUCCESS(Status))
					{
						Status = ZwResumeThread (hThread, NULL);

						KdPrint(("ZwResumeThread = %08x\n", Status));

						if (NT_SUCCESS(Status))
						{
							*ClientId = Cid;
							Succeeded = TRUE;
							__leave;
						}

						ZwTerminateThread (hThread, Status);
						ZwClose (hThread);
					}
				}
			}

			AllocSize = 0;

			ZwFreeVirtualMemory (
				hProcess,
				&p,
				&AllocSize,
				MEM_RELEASE
				);
		}
		
		AllocSize = PAGE_SIZE * 2;

		ZwFreeVirtualMemory (
			hProcess,
			&Teb.StackAllocationBase,
			&AllocSize,
			MEM_DECOMMIT
			);
	}
	__finally
	{
		if (!Succeeded)
		{
			if (hProcess)
				ZwClose (hProcess);
			if (hSection)
				ZwClose (hSection);
			if (hFile)
				ZwClose (hFile);
		}
	}

	*/

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

		SIZE_T Size = 0;

		Status = ZwFreeVirtualMemory (
			NtCurrentProcess(),
			(PVOID*) &Params,
			&Size,
			MEM_DECOMMIT | MEM_RELEASE
			);

		if (!NT_SUCCESS(Status))
		{
			Print("ZwFreeVirtualMemory[%08x] = %08x\n", Params, Status);
		}
	}
	else
	{
		Print("RtlCreateProcessParameters = %08x\n", Status);
	}

	return Succeeded;
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
