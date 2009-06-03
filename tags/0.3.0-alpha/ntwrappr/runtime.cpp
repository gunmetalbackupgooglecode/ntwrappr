/**
 * NT Wrapper project.
 *
 * Runtime routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"

/* Convert command line to array of argument values */
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
    {
       *pArgc = 0;
		return FALSE;
    }

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

/* Convert command line to array of argument values (Unicode) */
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

/* Check if Windows path is relative. */
static
BOOLEAN
IsWinPathRelative(
    IN PUNICODE_STRING WinPath
    )
{

}

/* Ûet last NTSTATUS */
VOID
NTAPI
SetLastStatus(
	NTSTATUS Status
	)
{
	// Use this place to store NTSTATUS.
	RtlSetLastWin32Error (Status);
}

/* Get last NTSTATUS */
NTSTATUS
NTAPI
GetLastStatus(
	)
{
	return RtlGetLastWin32Error ();
}

/* Convert Win32 path to Native path */
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

/* Allocate unicode string */
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

/* Get current directory */
VOID
NTAPI
GetCurrentDirectory(
	OUT PUNICODE_STRING Path
	)
{
	Path->Length = RtlGetCurrentDirectory_U (Path->MaximumLength, Path->Buffer);
}

/* Set current directory */
VOID
NTAPI
SetCurrentDirectory(
    IN PUNICODE_STRING Path
    )
{
    RtlSetCurrentDirectory_U (Path);
}
