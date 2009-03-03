#define SET_ENTRY
#define _CRTIMP
#include "../ntwrappr.h"
#include "../sprtapi.h"

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
				Print ("Logged on\n");
				logged_id = i;
				sprintf (prompt, "%s# ", userdb[i].username);
				return;
			}
		}

		Print ("Username or password incorrect\n");
	}
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
		return;
	}

	if (!stricmp (argv[0], "echo"))
	{
		Print("%s\n", fullremain);
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
		ANSI_STRING as;

		Print("CommandLine: '%S'\n", Args->Buffer);
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

	Print ("%s: Command not found\n", argv[0]);
}

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

	for (;;)
	{
		char cmd[1024];
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
			break;
		
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
