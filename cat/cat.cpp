#define SET_ENTRY
#define _CRTIMP
#include "ntwrappr.h"
#include <fcntl.h>
#include <io.h>

UCHAR Buffer[1024];

NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	)
{
	ULONG Bytes;
	HANDLE hFile;

	CommandLine = GetCommandLine ();
	Print("cat '%S'\n", CommandLine->Buffer);

	hFile = OpenFile (CommandLine->Buffer, GENERIC_READ, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	if (hFile == NULL)
	{
		Print("OpenFile failed with status %08x\n", GetLastStatus());
		return GetLastStatus();
	}

	ULONG Position = 0;

	do
	{
		Bytes = ReadFile (
			hFile, 
			&Buffer, 
			sizeof(Buffer)-1, 
			Position
			//-1
			);

		if (Bytes >= 0)
		{
			Buffer[Bytes] = 0;

			Print("block offset %08x, sizeof %08x : '%s'\n", Position, Bytes, Buffer);

			Position += Bytes;
		}
	}
	while (((LONG)Bytes) >= 0);

	CloseHandle (hFile);

	return STATUS_SUCCESS;
}
