#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _TASKLIST_CONTEXT
{
	PSYSTEM_PROCESSES_INFORMATION Buffer;
	PSYSTEM_PROCESSES_INFORMATION Proc;
} TASKLIST_CONTEXT, *PTASKLIST_CONTEXT;


BOOLEAN
NTAPI
ProcessFirst (
	PTASKLIST_CONTEXT *pContext
	);

BOOLEAN
NTAPI
ProcessNext (
	PTASKLIST_CONTEXT *Context
	);

BOOLEAN
NTAPI
CreateProcess(
	PWSTR ApplicationName,
	PWSTR CommandLine,
	PCLIENT_ID ClientId,
	BOOLEAN WaitForProcess,
    BOOLEAN CreateSuspended,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation OPTIONAL
	);

BOOLEAN
NTAPI
CreateThread(
	HANDLE ProcessHandle,
	BOOLEAN CreateSuspended,
	PVOID StartAddress,
	PVOID Parameter OPTIONAL,
	PHANDLE ThreadHandle OPTIONAL,
	PCLIENT_ID ClientId OPTIONAL
	);


#ifdef __cplusplus
}
#endif
