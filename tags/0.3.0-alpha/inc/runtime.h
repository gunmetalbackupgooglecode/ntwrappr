#pragma once

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN
NTAPI
CommandLineToArgv(
	PSTR CommandLine,
	int *pArgc,
	PSTR *pArgv
	);

BOOLEAN
NTAPI
CommandLineToArgvW(
	PWSTR CommandLine,
	int *pArgc,
	PWSTR *pArgv
	);

VOID
NTAPI
SetLastStatus(
	NTSTATUS Status
	);

NTSTATUS
NTAPI
GetLastStatus(
	);

NTSTATUS
NTAPI
WinPathToNtPath(
	OUT PUNICODE_STRING NtPath,
	IN PUNICODE_STRING WinPath
	);

NTSTATUS
NTAPI
AllocateUnicodeString(
	OUT PUNICODE_STRING String,
	IN USHORT MaximumLength
	);

VOID
NTAPI
GetCurrentDirectory(
	OUT PUNICODE_STRING Path
	);

VOID
NTAPI
SetCurrentDirectory(
    IN PUNICODE_STRING Path
    );


#ifdef __cplusplus
}
#endif
