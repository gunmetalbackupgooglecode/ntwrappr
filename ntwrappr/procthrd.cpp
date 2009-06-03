/**
 * NT Wrapper project.
 *
 * Processes and threads routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"


BOOLEAN
NTAPI
ProcessFirst (
	PTASKLIST_CONTEXT *pContext
	)
{
	PTASKLIST_CONTEXT Context;

	Context = (PTASKLIST_CONTEXT) halloc (sizeof(TASKLIST_CONTEXT));
	if (Context)
	{
		Context->Buffer = (PSYSTEM_PROCESSES_INFORMATION)
			GetSystemInformation (SystemProcessesAndThreadsInformation);

		if (Context->Buffer)
		{
			Context->Proc = Context->Buffer;

			*pContext = Context;

			return TRUE;
		}

		hfree (Context);
	}

	return FALSE;
}

BOOLEAN
NTAPI
ProcessNext (
	PTASKLIST_CONTEXT *Context
	)
{
	if ((*Context)->Proc->NextEntryDelta)
	{
		*(ULONG*)&(*Context)->Proc += (*Context)->Proc->NextEntryDelta;
		return TRUE;
	}


	hfree ((*Context)->Buffer);
	hfree (*Context);
	*Context = NULL;
	
	return FALSE;
}

BOOLEAN
NTAPI
CreateProcess(
	PWSTR ApplicationName,
	PWSTR CommandLine,
	PCLIENT_ID ClientId OPTIONAL,
	BOOLEAN WaitForProcess,
    BOOLEAN CreateSuspended,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation OPTIONAL
	)
{
	BOOLEAN Succeeded = FALSE;
	UNICODE_STRING ImagePath, CmdLine;
	RTL_USER_PROCESS_INFORMATION Info = {0};
	PRTL_USER_PROCESS_PARAMETERS Params = NULL;
	NTSTATUS Status;

	RtlInitUnicodeString (&ImagePath, ApplicationName);
	RtlInitUnicodeString (&CmdLine, CommandLine);

	Status = RtlCreateProcessParameters (
		&Params,
		&ImagePath,
		NULL,
		NULL,
		&CmdLine,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
		);

	if (NT_SUCCESS(Status))
	{
		Status = RtlCreateUserProcess (
			&ImagePath,
			OBJ_CASE_INSENSITIVE,
			Params,
			NULL,
			NULL,
			NtCurrentProcess (),
			FALSE,
			NULL,
			NULL,
			&Info
			);

		if (NT_SUCCESS(Status))
		{
            if (ARGUMENT_PRESENT (ProcessInformation))
            {
                *ProcessInformation = Info;
            }

            if (CreateSuspended)
                Status = STATUS_SUCCESS;
            else
			    Status = ZwResumeThread (Info.ThreadHandle, NULL);

			if (!NT_SUCCESS(Status))
			{
				Print("ZwResumeThread = %08x\n", Status);
			}
			else
			{
				Succeeded = TRUE;

				if (ClientId)
					*ClientId = Info.ClientId;

				if (WaitForProcess && !CreateSuspended)
				{
					Status = ZwWaitForSingleObject (
						Info.ProcessHandle,
						FALSE,
						NULL
						);

					if (!NT_SUCCESS(Status))
					{
						Print("ZwWaitForSingleObject = %08x\n", Status);
					}
				}
			}
		}
		else
		{
			Print("RtlCreateUserProcess = %08x\n", Status);
		}

		RtlDestroyProcessParameters (Params);
	}
	else
	{
		Print("RtlCreateProcessParameters = %08x\n", Status);
	}

	return Succeeded;
}

BOOLEAN
NTAPI
CreateThread(
	HANDLE ProcessHandle,
	BOOLEAN CreateSuspended,
	PVOID StartAddress,
	PVOID Parameter OPTIONAL,
	PHANDLE ThreadHandle OPTIONAL,
	PCLIENT_ID ClientId OPTIONAL
	)
{
	NTSTATUS Status;
	HANDLE hThread;
	CLIENT_ID Cid;

	Status = RtlCreateUserThread (
		ProcessHandle,
		NULL,
		CreateSuspended,
		0,
		0,
		PAGE_SIZE,
		StartAddress,
		Parameter,
		&hThread,
		&Cid
		);

	if (NT_SUCCESS(Status))
	{
		if (ThreadHandle)
			*ThreadHandle = hThread;
		else
			CloseHandle (hThread);

		if (ClientId)
			*ClientId = Cid;

		return TRUE;
	}

	KdPrint(("RtlUserCreateProcess failed with status %08x\n", Status));

	return FALSE;
}

