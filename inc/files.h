#pragma once

#ifdef __cplusplus
extern "C" {
#endif

HANDLE
NTAPI
CreateFile (
	PWSTR FileName, 
	ULONG AccessMode, 
	ULONG ShareMode, 
	ULONG Disposition, 
	ULONG Options,
	ULONG Attributes
	);

HANDLE
NTAPI
OpenFile (
	PWSTR FileName,
	ULONG AccessMode,
	ULONG ShareAccess,
	ULONG OpenOptions
	);

ULONG 
NTAPI
ReadFile (
	HANDLE hFile, 
	PVOID Buffer, 
	ULONG MaxLen, 
	ULONG Position
	);

typedef const void *PCVOID;

ULONG 
NTAPI
WriteFile (
	HANDLE hFile, 
	PCVOID Buffer, 
	ULONG Length, 
	ULONG Position
	);

BOOLEAN
NTAPI
CloseHandle (
	HANDLE hObject
	);

BOOLEAN
NTAPI
QueryDirectory (
	HANDLE hDir, 
	BOOLEAN RestartScan,
	PFILE_BOTH_DIR_INFORMATION Buffer,
	ULONG MaxLen
	);

#ifdef __cplusplus
}
#endif
