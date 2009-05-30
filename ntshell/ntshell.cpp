#define SET_ENTRY
#define WAIT_N_SECONDS
#define FAIL_ON_EXCEPTION
#define _CRTIMP
#include "ntwrappr.h"
#include "pe_image.h"
#include "sprtapi.h"

struct USER
{
	char *username;
	char *password;
	char *homedir;
};

USER userdb[] = {
	{ "root", "123", "/" },
	{ "user", "456", "/" },
	{ NULL },
};


int logged_id = -1;
char prompt[1024];

extern "C" int _cdecl sprintf (char *, const char *, ...);

char PassChar = '*';

void logon()
{
	char user[1024];
	char pass[1024];

	for (;;)
	{
		bool bUserFound = false;

		ReadString (GetDefaultKeyboard(), "login: ", user, sizeof(user)-1, 0);
		ReadString (GetDefaultKeyboard(), "password: ", pass, sizeof(pass)-1, PassChar);

		for (int i=0; userdb[i].username; i++)
		{
			if (!stricmp(userdb[i].username, user) &&
				!strcmp (userdb[i].password, pass))

			{
				Print ("Logged in\n");
				logged_id = i;
				return;
			}
		}

		Print ("Username or password incorrect\n");
	}
}

typedef struct PROC
{
    PROC* Childs[1024];
    wchar_t ProcessName[256];
    ULONG ProcessID;
} *PPROC;

// Recursive search
PPROC TreeFind (PPROC Head, ULONG PID)
{
    PPROC p = NULL;

    if (Head->ProcessID == PID)
        return Head;

    for (ULONG i=0; i<1024; i++)
    {
        if (Head->Childs[i])
        {
            p = TreeFind (Head->Childs[i], PID);
            if (p)
                return p;
        }
    }

    return NULL;
}

void DumpTree (PPROC Head, int offset = 0)
{
    if (Head->ProcessID != -1)
    {
        for (int j=0; j<offset; j++) Print("  ");
        Print ("%S [PID %x]\n", Head->ProcessName, Head->ProcessID);
    }

    for (ULONG i=0; i<1024; i++)
    {
        if (Head->Childs[i])
            DumpTree (Head->Childs[i], offset + 1);
    }
}

void FreeTree (PPROC Head)
{
    for (ULONG i=0; i<1024; i++)
    {
        if (Head->Childs[i])
            FreeTree (Head->Childs[i]);
    }

    hfree (Head);
}

void AppendChild (PPROC Parent, PPROC Child)
{
    for (ULONG i=0; i<1024; i++)
    {
        if (Parent->Childs[i] == NULL)
        {
            Parent->Childs[i] = Child;
            return;
        }
    }

    Print ("No free space to add child PID %x [%S] to PPID %x [%S] !!\n",
        Child->ProcessID,
        Child->ProcessName,
        Parent->ProcessID,
        Parent->ProcessName
        );
}

void PTree()
{
    PPROC TreeHead;
    PTASKLIST_CONTEXT Context;

    if (ProcessFirst (&Context))
    {
        TreeHead = (PPROC) halloc (sizeof(PROC));
        memset (TreeHead, 0, sizeof(PROC));
        TreeHead->ProcessID = -1;

        ULONG ProcCount = 0;

        do
        {
            PPROC Proc = TreeFind (TreeHead, Context->Proc->ProcessId);
            if (Proc == NULL)
            {
                Proc = (PPROC) halloc (sizeof(PROC));
                memset (Proc, 0, sizeof(PROC));
                Proc->ProcessID = Context->Proc->ProcessId;
                memcpy (Proc->ProcessName, Context->Proc->ProcessName.Buffer,  Context->Proc->ProcessName.Length);
                if (Proc->ProcessID == 0)
                    wcscpy (Proc->ProcessName, L"Idle");

                PPROC Parent = TreeFind (TreeHead, Context->Proc->InheritedFromProcessId);
                if (!Parent)
                    Parent = TreeHead;
                AppendChild (Parent, Proc);
            }
            else
            {
                Print ("Process PID %x [%S] already exists !!\n", Proc->ProcessID, Proc->ProcessName);
            }

            ProcCount++;
        }
        while (ProcessNext (&Context));

        DumpTree (TreeHead, -1);
        FreeTree (TreeHead);

        Print ("\nTotal:  %d processes\n", ProcCount);
    }
    else
    {
        Print ("ProcessFirst failed!\n");
    }
}

PHANDLE
FindCsrPortHandle(
    )
{
    PVOID CsrClientCallServer = (PVOID) GetProcedureAddress (FindDll (L"ntdll.dll"), "CsrClientCallServer");
    ULONG_PTR ZwRequestWaitReplyPort = (ULONG_PTR) GetProcedureAddress (FindDll (L"ntdll.dll"), "ZwRequestWaitReplyPort");
    
    if (CsrClientCallServer)
    {
        for (PUCHAR p = (PUCHAR)CsrClientCallServer; p < (PUCHAR)CsrClientCallServer + 0x1000; p++)
        {
            if (
                // PUSH DWORD PTR DS:[CsrPortHandle]
                p[0] == 0xFF &&
                p[1] == 0x35 &&
                // 2,3,4,5 - port handle

                // CALL ZwRequestWaitReplyPort
                p[6] == 0xE8
                // 7,8,9,10 - call arg
                )
            {
                ULONG_PTR CallArg = (ULONG_PTR)&p[11] + *(ULONG_PTR*)&p[7];
                PHANDLE CsrPortHandle = *(PHANDLE*)&p[2];

                if (CallArg == ZwRequestWaitReplyPort)
                {
                    Print("CsrPortHandle found %p : %lx\n", CsrPortHandle, *CsrPortHandle);
                    return CsrPortHandle;
                }
            }
        }
    }

    return NULL;
}

void ProcessCommand (int argc, char **argv, char *fullremain)
{
	if (!stricmp (argv[0], "id"))
	{
		Print ("id=%d (%s)\n", logged_id, userdb[logged_id].username);
		return;
	}

	if (!stricmp (argv[0], "help"))
	{
		Print (
			"nts shell 0.1 by Great\n"
			"\n"
			"Supported commands:\n"
			"id				display user id\n"
			"tasklist		display process list\n"
			"run <CMD>		start native process\n"
			"runsys <CMD>	start native from \\SystemRoot\\System32\n"
			"help			display this help\n"
			"\n"
			"Coded by Great, [C] 2008-2009. (gr8@cih.ms)\n"
			"http://code.google.com/p/ntwrappr\n"
			);
		return;
	}

	if (!stricmp (argv[0], "tasklist"))
	{
		Print ("PID    PPID   Image\n");

		PTASKLIST_CONTEXT c;

		if (ProcessFirst (&c))
		{
			do
			{
				Print ("%6d %6d %S\n", 
					c->Proc->ProcessId,
					c->Proc->InheritedFromProcessId, 
					c->Proc->ProcessName.Buffer
					);
			}
			while (ProcessNext (&c));
		}
        else
        {
            Print ("ProcessFirst failed!\n");
        }

		return;
	}

    if (!stricmp (argv[0], "ptree"))
    {
        PTree();
        return;
    }

	if (!stricmp (argv[0], "echo"))
	{
		Print("%s\n", fullremain);
		return;
	}

    if (!stricmp (argv[0], "csrport"))
    {
        PHANDLE CsrPortHandle;

        CsrPortHandle = FindCsrPortHandle ();
     
        return;
    }

    if (!stricmp (argv[0], "patchpeb"))
    {
        PPEB Peb = NtCurrentPeb ();
        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS) RtlImageNtHeader (Peb->ImageBaseAddress);

        NtHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;

        Print("patched\n");

        return;
    }

    if (!stricmp (argv[0], "load"))
    {
		UNICODE_STRING us;
		ANSI_STRING as;
		NTSTATUS st;
        char *dllname = "C:\\Windows\\System32\\kernel32.dll";
        ULONG Chars = 0;

		if (argc == 2)
		{
            if (argv[1][0] == '-')
            {
                if (argv[1][1] == 'r')
                {
                    Chars = IMAGE_FILE_EXECUTABLE_IMAGE;
                }
            }
            else
            {
                dllname = argv[1];
            }
		}

        if (argc == 3)
        {
            if (argv[2][0] == '-')
            {
                if (argv[2][1] == 'r')
                {
                    Chars = IMAGE_FILE_EXECUTABLE_IMAGE;
                }
            }
        }

        RtlInitAnsiString (&as, dllname);
		st = RtlAnsiStringToUnicodeString (&us, &as, TRUE);

		if (NT_SUCCESS(st))
		{
			Print("Loading '%S' (%lx) ...\n", us.Buffer, Chars);

			PVOID hDll = LoadDll (us.Buffer, Chars);

            Print("hDll = %p, LastStatus = %lx\n", hDll, GetLastStatus());

			RtlFreeUnicodeString (&us);
		}
		else
		{
			Print("RtlAnsiStringToUnicodeString failed with status %08x\n", st);
		}

        return;
    }

	if (!stricmp (argv[0], "run"))
	{
		UNICODE_STRING us;
		ANSI_STRING as;
		NTSTATUS st;
		CLIENT_ID ClientId;
		BOOLEAN Wait = FALSE;

		if (argc < 2)
		{
			Print("usage: run <CMD> [wait]\n");
			return;
		}

		if (argc == 3)
		{
			if (!stricmp (argv[2], "wait"))
				Wait = TRUE;
		}

		Print("Wait = %s\n", Wait ? "true" : "false");

		RtlInitAnsiString (&as, argv[1]);
		st = RtlAnsiStringToUnicodeString (&us, &as, TRUE);

		if (NT_SUCCESS(st))
		{
			Print("Starting '%S' ...\n", us.Buffer);

			BOOLEAN b = CreateProcess (us.Buffer, L"Command Line", &ClientId, Wait);

			if (b)
			{
				Print("Started, PID %x TID %x\n", ClientId.UniqueProcess, ClientId.UniqueThread);
			}
			else
			{
				Print("CreateProcess failed\n");
			}

			RtlFreeUnicodeString (&us);
		}
		else
		{
			Print("RtlAnsiStringToUnicodeString failed with status %08x\n", st);
		}

		return;
	}

	if (!stricmp (argv[0], "args"))
	{
		PUNICODE_STRING Args = GetCommandLine ();
//		ANSI_STRING as;

		Print("CommandLine: '%S'\n", Args->Buffer);
		return;
	}

    if (!stricmp (argv[0], "shutdown"))
    {
        SHUTDOWN_ACTION Action;
        NTSTATUS Status;
        BOOLEAN Enabled;

        if (argc < 2)
        {
            Print (
                "usage: shutdown -r|-h\n"
                "  -r    reboot\n"
                "  -h    halt\n"
                "  -s    stop\n"
                );
            return;
        }

        Status = RtlAdjustPrivilege (SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &Enabled);

        if (!NT_SUCCESS(Status))
        {
            Print("RtlAdjustPrivilege failed for shutdown privilege with status %08x\n", Status);
            return;
        }

        if (!strcmp (argv[1], "-r"))
            Action = ShutdownReboot;
        else if (!strcmp (argv[1], "-h"))
            Action = ShutdownPowerOff;
        else if (!strcmp (argv[1], "-s"))
            Action = ShutdownNoReboot;
        else
        {
            Print ("unknown option %s\n", argv[1]);
            return;
        }

        Status = ZwShutdownSystem (Action);
        if (!NT_SUCCESS(Status))
        {
            Print ("ZwShutdownSystem failed with status %08x\n", Status);
        }
        else
        {
            Print ("System is going down...\n");
        }

        return;
    }

	if (!stricmp (argv[0], "runsys"))
	{
		UNICODE_STRING us;
		UNICODE_STRING ImagePath;
		ANSI_STRING as;
		NTSTATUS st;
		CLIENT_ID ClientId;
		wchar_t Buffer[1024] = L"\\SystemRoot\\System32\\";
		BOOLEAN Wait = FALSE;

		if (argc < 2)
		{
			Print("usage: runsys <CMD> [wait]\n");
			return;
		}

		if (argc == 3)
		{
			if (!stricmp (argv[2], "wait"))
				Wait = TRUE;
		}

		Print("Wait = %s\n", Wait ? "true" : "false");

		RtlInitAnsiString (&as, argv[1]);
		st = RtlAnsiStringToUnicodeString (&us, &as, TRUE);

		if (NT_SUCCESS(st))
		{
			RtlInitUnicodeString (&ImagePath, Buffer);
			ImagePath.MaximumLength = sizeof(Buffer)*2;

			RtlAppendUnicodeStringToString (&ImagePath, &us);

			Print("Starting '%S' ...\n", ImagePath.Buffer);

			BOOLEAN b = CreateProcess (ImagePath.Buffer, L"Command Line", &ClientId, Wait);

			if (b)
			{
				Print("Started, PID %x TID %x\n", ClientId.UniqueProcess, ClientId.UniqueThread);
			}
			else
			{
				Print("CreateProcess failed\n");
			}

			RtlFreeUnicodeString (&us);
		}
		else
		{
			Print("RtlAnsiStringToUnicodeString failed with status %08x\n", st);
		}

		return;
	}

	if (!stricmp(argv[0], "pwd"))
	{
		wchar_t buffer[1024];

		RtlGetCurrentDirectory_U (sizeof(buffer)/2-2, buffer);

		Print("CurrentDirectory: '%S'\n", buffer);

		return;
	}

	if (!stricmp(argv[0], "cwd"))
	{
		ANSI_STRING as; RtlInitAnsiString (&as, fullremain);
		UNICODE_STRING wFullRemain;
		if (NT_SUCCESS(RtlAnsiStringToUnicodeString (&wFullRemain, &as, TRUE)))
		{
			RtlSetCurrentDirectory_U (&wFullRemain);
			RtlFreeUnicodeString (&wFullRemain);
		}

		return;
	}

	PWSTR TryParts[] = {
		L"",
		L".exe",
		L".com"
	};
	int nParts = sizeof(TryParts)/sizeof(TryParts[0]);

	for (int i=0; i<nParts; i++)
	{
		ANSI_STRING aCommand;
		UNICODE_STRING Command;
		RtlInitAnsiString (&aCommand, argv[0]);
		RtlAnsiStringToUnicodeString (&Command, &aCommand, TRUE);

		UNICODE_STRING NtPath;
		UNICODE_STRING CurrentDirectory;

		AllocateUnicodeString (&NtPath, 1024);
		AllocateUnicodeString (&CurrentDirectory, 1024);
		GetCurrentDirectory (&CurrentDirectory);

		RtlAppendUnicodeToString (&NtPath, L"\\??\\");
		RtlAppendUnicodeStringToString (&NtPath, &CurrentDirectory);
		RtlAppendUnicodeToString (&NtPath, L"\\");
		RtlAppendUnicodeStringToString (&NtPath, &Command);
		RtlAppendUnicodeToString (&NtPath, TryParts[i]);
		
		HANDLE hFile = OpenFile (
			NtPath.Buffer,
			FILE_READ_ATTRIBUTES, 
			FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, 
			FILE_NON_DIRECTORY_FILE
			);
		if (hFile)
		{
			// File exists.
	//		Print("%S exists\n", NtPath.Buffer);

			wchar_t commandline[512] = L"";
			if (fullremain)
				mbstowcs (commandline, fullremain, sizeof(commandline)/2 - 2);


			if (!CreateProcess (NtPath.Buffer, commandline, NULL, TRUE))
			{
				Print("CreateProcess failed for '%S' '%S'\n", NtPath.Buffer, commandline);
			}

			CloseHandle (hFile);
			return;
		}

		RtlFreeUnicodeString (&NtPath);
		RtlFreeUnicodeString (&CurrentDirectory);
		RtlFreeUnicodeString (&Command);
	}

	Print ("%s: Command not found\n", argv[0]);
}

wchar_t curdir[1024];

VOID
NTAPI
PrintMessage(
	PLPC_MESSAGE lpc
	)
{
	char *MessageTypes[] = {
		"LPC_NEW_MESSAGE",
		"LPC_REQUEST",
		"LPC_REPLY",
		"LPC_DATAGRAM",
		"LPC_LOST_REPLY",
		"LPC_PORT_CLOSED",
		"LPC_CLIENT_DIED",
		"LPC_EXCEPTION",
		"LPC_DEBUG_EVENT",
		"LPC_ERROR_EVENT",
		"LPC_CONNECTION_REQUEST"
	};

	Print("LPC_MESSAGE %08x:\n", lpc);
	Print(" DataSize = %08x\n", lpc->DataSize);
	Print(" MessageSize = %08x\n", lpc->MessageSize);
	Print(" MessageType = %s [%08x]\n", lpc->MessageType > 10 ? "LPC_UNKNOWN" : MessageTypes[lpc->MessageType], lpc->MessageType);
	Print(" VirtualRangesOffset = %08x\n", lpc->VirtualRangesOffset);
	Print(" ClientId.UniqueThread = %08x\n", lpc->ClientId.UniqueThread);
	Print(" ClientId.UniqueProcess = %08x\n", lpc->ClientId.UniqueProcess);
	Print(" MessageId = %08x\n", lpc->MessageId);
	Print(" SectionSize = %08x\n", lpc->SectionSize);

	for( int i=0; i<lpc->DataSize; i++ ) 
	{
		Print(" %02x", lpc->Data[i]);
	}

	Print("\n\n");
}

VOID
NTAPI
HardErrorThread(
	PVOID Parameter
	)
{
	HANDLE hHardErrorPort;
	NTSTATUS Status;

	hHardErrorPort = CreatePort (NULL, 0);
	if (hHardErrorPort == NULL)
	{
		Status = GetLastStatus();
		Print("HARDERR: CreatePort failed with status %08x\n", Status);
		RtlExitUserThread (Status);
	}

	Status = ZwSetDefaultHardErrorPort (hHardErrorPort);

	if (!NT_SUCCESS(Status))
	{
		Print("HARDERR: ZwSetDefaultHardErrorPort failed with status %08x\n", Status);
		CloseHandle (hHardErrorPort);
		RtlExitUserThread (Status);
	}

	UCHAR MessageBuffer [0x148];
	LPC_MESSAGE *Message = (LPC_MESSAGE*) MessageBuffer;

	for (;;)
	{
		if (!WaitReceivePort (hHardErrorPort, Message))
		{
			Print("HARDERR: WaitReceivePort failed with st %08x\n", GetLastStatus());
		}

		switch (Message->MessageType)
		{
		case LPC_ERROR_EVENT:
			{
				PHARDERROR_MSG h = (PHARDERROR_MSG) Message;

				Print(
					"**************************************************************\n"
					"*               Hard Error Port got a message                *\n"
					"**************************************************************\n"
                    "     ===  PID 08x  TID %08x ===\n"
					" ErrorStatus = %08x          ResponseOption = %08x\n"
					" NumberOfParameters = %08x   ParametersMask = %08x\n"
					" Parameters [%08x %08x %08x %08x]\n"
					"**************************************************************\n"
					,
                    Message->ClientId.UniqueProcess,Message->ClientId.UniqueThread,
					h->ErrorStatus,
					h->ResponseOption,
					h->NumberOfParameters,
					h->UnicodeStringParameterMask,
					h->Parameters[0], h->Parameters[1], 
					h->Parameters[2], h->Parameters[3]
				);

                if (h->ErrorStatus == 0x17e8)
                {
                    // Application initialization exception
                    PTASKLIST_CONTEXT Context;
                    wchar_t procName[256] = L"(unknown process)";

                    if (ProcessFirst (&Context))
                    {
                        do
                        {
                            if (Context->Proc->ProcessId == (ULONG)Message->ClientId.UniqueProcess)
                            {
                                memcpy (procName, 
                                    Context->Proc->ProcessName.Buffer, 
                                    Context->Proc->ProcessName.MaximumLength);
                                break;
                            }
                        }
                        while (ProcessNext (&Context));
                    }

                    Print("Process %S failed to initialize with status %08x\n", procName, h->Parameters[0]);
                    
                    if (h->Parameters[0] == STATUS_DLL_INIT_FAILED)
                    {
                        Print("STATUS_DLL_INIT_FAILED: Initialization of the dynamic link \n"
                              " library failed. The process is terminating abnormally.\n");
                    }

                    Print ("**************************************************************\n");
                }

				h->Response = ResponseNotHandled;

				switch (h->ResponseOption)
				{
				case OptionAbortRetryIgnore:

					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Abort/Retry/Ignore (ARI)? ", str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'A' &&
							   str[0] != 'R' &&
							   str[0] != 'I');

						switch (str[0])
						{
						case 'A': h->Response = ResponseAbort; break;
						case 'R': h->Response = ResponseRetry; break;
						case 'I': h->Response = ResponseIgnore; break;
						}
					}
					break;

				case OptionOk:
					{
						h->Response = ResponseOk;
						break;
					}

				case OptionOkCancel:
					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Ok/Cancel (OC)? ",
								str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'O' &&
							   str[0] != 'C');

						switch (str[0])
						{
						case 'O': h->Response = ResponseOk; break;
						case 'C': h->Response = ResponseCancel; break;
						}
					}
					break;

				case OptionRetryCancel:
					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Retry/Cancel (RC)? ", 
								str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'R' &&
							   str[0] != 'C');

						switch (str[0])
						{
						case 'R': h->Response = ResponseRetry; break;
						case 'C': h->Response = ResponseCancel; break;
						}
					}
					break;
				
				case OptionYesNo:
					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Yes/No (YN)? ", 
								str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'Y' &&
							   str[0] != 'N');

						switch (str[0])
						{
						case 'Y': h->Response = ResponseYes; break;
						case 'N': h->Response = ResponseNo; break;
						}
					}
					break;

				case OptionYesNoCancel:

					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Yes/No/Cancel (YNC)? ", str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'Y' &&
							   str[0] != 'N' &&
							   str[0] != 'C');

						switch (str[0])
						{
						case 'Y': h->Response = ResponseYes; break;
						case 'N': h->Response = ResponseNo; break;
						case 'C': h->Response = ResponseCancel; break;
						}
					} // case
					break;
				} // switch

				ReplyPort (hHardErrorPort, &h->LpcMessageHeader);

			} // case
			break;

		default:

			PrintMessage (Message);

		} // switch
			
	} // for (;;)

	RtlExitUserThread (STATUS_SUCCESS);
}

BOOLEAN bHardErrThreadRunning = FALSE;

NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	)
{
	Print("NT Shell 0.1\n");
	Print("Press ESC to continue loading Windows.\n");

logoff:
	logon();

    if (bHardErrThreadRunning == FALSE)
    {
	    if(!CreateThread (NtCurrentProcess(), 
		    FALSE, 
		    HardErrorThread,
		    NULL,
		    NULL,
		    NULL
		    ))
	    {
		    Print("CreateThread failed for harderror thread with status %08x\n", GetLastStatus());
	    }
        else
        {
            bHardErrThreadRunning = TRUE;
            DisableExitOnEsc ();
        }
    }

    for (;;)
	{
		char cmd[1024];

		curdir[0] = 0;
		RtlGetCurrentDirectory_U (sizeof(curdir), curdir);
		sprintf (prompt, "[%s$%S]# ", userdb[logged_id].username, curdir);

		ReadString (GetDefaultKeyboard(), prompt, cmd, sizeof(cmd)-1, 0);

		char *ptr;
		char *args[20] = {0};

		for (ptr = cmd; isspace(*ptr); ptr++);

		ULONG l = strlen(ptr);
		while (isspace(ptr[l-1]))
		{
			l --;
			ptr[l] = 0;
		}

		if (strlen(ptr) == 0)
			continue;

		int arg=0;
		char *prev = ptr;
		char *fullremain = NULL;

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

				if (arg == 1)
				{
					// first argument..
					fullremain = strdup (sp);

				}

				prev = sp;
			}
		}

		if (!stricmp (args[0], "exit"))
        {
		//	break;
            Print("Exit is not supported due to harderror port.\n");
        }
		
		if (!stricmp (args[0], "logoff"))
		{
			logged_id = -1;
			prompt[0] = 0;
			goto logoff;
		}

		ProcessCommand (arg, args, fullremain);

		hfree (fullremain);
	}

	Print("[+] NTSample exit\n");
	return STATUS_SUCCESS;
}
