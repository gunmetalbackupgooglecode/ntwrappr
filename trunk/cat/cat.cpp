#define SET_ENTRY
#define _CRTIMP
#include "../ntwrappr.h"

NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	)
{
	CommandLine = GetCommandLine ();

	Print("cat %S\n", CommandLine->Buffer);

	return STATUS_SUCCESS;
}
