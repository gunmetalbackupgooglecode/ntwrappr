#define SET_ENTRY
#define WAIT_N_SECONDS
#define FAIL_ON_EXCEPTION
#define _CRTIMP
#include "ntwrappr.h"
#include "pe_image.h"


HANDLE hSuccessfulLogonEvent;
HANDLE hReturnToWindowsEvent;

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



struct THREAD_INFO
{
    HANDLE hThread;
    CLIENT_ID id;
};

struct CSRSS_MESSAGE
{
    ULONG Unknown1;
    ULONG Opcode;
    ULONG Status;
    ULONG Unknown2;
};

/*
struct PORT_MESSAGE
{
    ULONG u1;
    ULONG u2;

    union
    {
        CLIENT_ID ClientId;
        float DoNotUseThisField;
    };

    ULONG MessageId;

    union
    {
        ULONG ClientViewSize;
        ULONG CallbackId;
    };
};
*/

extern "C"
NTSTATUS
NTAPI
CsrClientCallServer (
    PVOID CsrMsg,
    ULONG Something,
    ULONG ApiNumber,
    ULONG MessageSize
    );

VOID SelfNotifyCsrss()
{
    NTSTATUS Status;
    HANDLE hThread = 0;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES Oa;

    ClientId = NtCurrentTeb()->Cid;
    
    InitializeObjectAttributes (&Oa, 0, 0, 0, 0);
    Status = ZwOpenThread (&hThread,
        THREAD_ALL_ACCESS,
        &Oa,
        &ClientId
        );

    Print ("ZwOpenThread = %lx, hThread = %lx\n", Status, hThread);

    struct
    {
        PORT_MESSAGE    PortMessage;
        CSRSS_MESSAGE    CsrssMessage;
        THREAD_INFO        ThreadInfo;
    }
    csrmsg = {
        {0},
        {0},
        {hThread, ClientId}};

    Status = CsrClientCallServer ( 
        &csrmsg,
        0,
        0x10001,
        0x0C);

    Print ("CsrClientCallServer = %lx\n", Status);
    Print ("Status = %lx\n", csrmsg.CsrssMessage.Status);
}



char *DbgStates[] = {
    "DbgIdle",
    "DbgReplyPending",
    "DbgCreateThreadStateChange",
    "DbgCreateProcessStateChange",
    "DbgExitThreadStateChange",
    "DbgExitProcessStateChange",
    "DbgExceptionStateChange",
    "DbgBreakpointStateChange",
    "DbgSingleStepStateChange",
    "DbgLoadDllStateChange",
    "DbgUnloadDllStateChange"
};

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

    if (!stricmp (argv[0], "testport"))
    {
        SelfNotifyCsrss();

        return;
    }

    if (!stricmp (argv[0], "patchpeb"))
    {
        PPEB Peb = NtCurrentPeb ();
        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS) RtlImageNtHeader (Peb->ImageBaseAddress);
		ULONG OldProtect;
		NTSTATUS Status;
        PVOID VirtualAddress = NtHeaders;
        SIZE_T VirtualSize = FIELD_OFFSET (IMAGE_NT_HEADERS, OptionalHeader.Subsystem);

		Status = ZwProtectVirtualMemory (
			NtCurrentProcess(),
			&VirtualAddress,
			&VirtualSize,
			PAGE_READWRITE,
			&OldProtect
			);

        KdPrint(("ZwProtectVirtualMemory %lx\n", Status));

        if (NT_SUCCESS(Status))
        {
            NtHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;

		    Status = ZwProtectVirtualMemory (
			    NtCurrentProcess(),
			    &VirtualAddress,
			    &VirtualSize,
			    OldProtect,
			    &OldProtect
			    );

            KdPrint(("ZwProtectVirtualMemory %lx\n", Status));
        }

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

			BOOLEAN b = CreateProcess (us.Buffer, L"Command Line", &ClientId, Wait, FALSE, NULL);

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
        BOOLEAN Debug = FALSE;

		if (argc < 2)
		{
			Print("usage: runsys <CMD> [wait] [debug]\n");
			return;
		}

		if (argc == 3)
		{
			if (!stricmp (argv[2], "wait"))
				Wait = TRUE;

			if (!stricmp (argv[2], "debug"))
				Debug = TRUE;
        }
        
        if (argc == 4)
        {
			if (!stricmp (argv[3], "wait"))
				Debug = TRUE;
        }

		Print("Wait = %d, Debug = %d\n", Wait, Debug);

		RtlInitAnsiString (&as, argv[1]);
		st = RtlAnsiStringToUnicodeString (&us, &as, TRUE);

		if (NT_SUCCESS(st))
		{
			RtlInitUnicodeString (&ImagePath, Buffer);
			ImagePath.MaximumLength = sizeof(Buffer)*2;

			RtlAppendUnicodeStringToString (&ImagePath, &us);

			Print("Starting '%S' ...\n", ImagePath.Buffer);

            RTL_USER_PROCESS_INFORMATION Info;
			BOOLEAN b = CreateProcess (ImagePath.Buffer, L"Command Line", &ClientId, Wait, Debug, &Info);

			if (b)
			{
				Print("Started, PID %x TID %x\n", ClientId.UniqueProcess, ClientId.UniqueThread);

                if (Debug)
                {
                    do
                    {
                        st = DbgUiConnectToDbg ();
                        Print ("DbgUiConnectToDbg = %lx\n", st);
                        if (!NT_SUCCESS(st)) break;

                        st = DbgUiDebugActiveProcess (Info.ProcessHandle);
                        Print("DbgUiDebugActiveProcess = %lx\n", st);
                        if (!NT_SUCCESS(st)) break;

                        st = ZwResumeThread (Info.ThreadHandle, NULL);
                        Print("ZwResumeThread = %lx\n", st);
                        if (!NT_SUCCESS(st)) break;

                        DBGUI_WAIT_STATE_CHANGE StateChange;
                        memset (&StateChange, 0, sizeof(StateChange));
                        do
                        {
                            do
                            {
                                st = DbgUiWaitStateChange (&StateChange, NULL);
                            }
                            while (st == STATUS_ALERTED || st == STATUS_USER_APC);
                            Print ("DbgUiWaitStateChange = %lx\n", st);
                            if (!NT_SUCCESS(st)) break;

                            Print ("NewState %lx (%s)\n", StateChange.NewState,
                                DbgStates[StateChange.NewState]);

                            if (StateChange.NewState != DbgBreakpointStateChange)
                            {
                                st = DbgUiContinue (&StateChange.AppClientId, DBG_CONTINUE);
                                Print ("DbgUiContinue = %lx\n", st);
                                if (!NT_SUCCESS(st)) break;
                            }
                        }
                        while (StateChange.NewState != DbgBreakpointStateChange);

                        Print("end-of-debugging\n");
                    }
                    while (FALSE);
                }
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

			if (!CreateProcess (NtPath.Buffer, commandline, NULL, TRUE, FALSE, NULL))
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


BOOLEAN bShellInitialized = FALSE;

NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	)
{
	Print("Native Shell " NTWRAPPER_VERSION_A "\n");
	Print("Press ESC to continue loading Windows.\n");

    hSuccessfulLogonEvent = OpenEvent (EVENT_ALL_ACCESS, L"\\SuccessfulLogon");
    if (!hSuccessfulLogonEvent)
    {
        Print ("OpenEvent (successful logon) failed with status %lx\n", GetLastStatus());
        return GetLastStatus();
    }

    hReturnToWindowsEvent = OpenEvent (EVENT_ALL_ACCESS, L"\\ReturnToWindows");
    if (!hReturnToWindowsEvent)
    {
        Print ("OpenEvent (return to windows) failed with status %lx\n", GetLastStatus());
        return GetLastStatus();
    }

logoff:

    __try
    {
        logon();
    }
    __except ( GetExceptionCode() == MANUALLY_INITIATED_CRASH ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH )
    {
        Print ("Returning to windows\n");
        SetEvent (hReturnToWindowsEvent);
        CloseHandle (hReturnToWindowsEvent);
        CloseHandle (hSuccessfulLogonEvent);
        return STATUS_SUCCESS;
    }

    if (hSuccessfulLogonEvent)
    {
        SetEvent (hSuccessfulLogonEvent);
        CloseHandle (hSuccessfulLogonEvent);
        CloseHandle (hReturnToWindowsEvent);
        hSuccessfulLogonEvent = NULL;
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
		    TryExit();
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

	return STATUS_SUCCESS;
}
