#define SET_ENTRY
#include "ntwrappr.h"

int _cdecl main(int argc, char** argv);

NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	)
{
    ANSI_STRING cmdline;

    int argc;
    char *argv[245];
    NTSTATUS Status;
    int code = -1;

    Status = RtlUnicodeStringToAnsiString (&cmdline, CommandLine, TRUE);

    if (NT_SUCCESS(Status))
    {
        CommandLineToArgv (cmdline.Buffer, &argc, argv);
        code = main (argc, argv);

        Status = (code == 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);

        RtlFreeAnsiString (&cmdline);
    }
    else
    {
        Print("RtlUnicodeStringToAnsiString failed for command line with status %08x\n", Status);
    }

    return Status;
}
