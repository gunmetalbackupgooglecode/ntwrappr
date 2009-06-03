/**
 * NT Wrapper project.
 *
 * LPC routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"


HANDLE
NTAPI
CreatePort(
	PWSTR PortName OPTIONAL,
	ULONG MaximumDataLength
	)
{
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING Name;
	NTSTATUS Status;
	HANDLE hPort = NULL;

	if (PortName)
	{
		RtlInitUnicodeString (&Name, PortName);
		InitializeObjectAttributes (&Oa, &Name, OBJ_CASE_INSENSITIVE, 0, 0);
	}
	else
	{
		InitializeObjectAttributes (&Oa, 0, 0, 0, 0);
	}

	if (MaximumDataLength == 0)
		MaximumDataLength = 0x130;

	Status = ZwCreatePort(
		&hPort,
		&Oa,
		0,
		MaximumDataLength,
		NULL
		);

	return NT_SUCCESS(Status) ? hPort : NULL;
}

BOOLEAN
NTAPI
WaitReceivePort(
	HANDLE hPort,
	PLPC_MESSAGE Msg
	)
{
	NTSTATUS Status;

	Status = ZwReplyWaitReceivePort (
		hPort,
		NULL,
		NULL,
		Msg
		);

	return NT_SUCCESS(Status);
}

BOOLEAN
NTAPI
ReplyPort(
	HANDLE hPort,
	PLPC_MESSAGE Msg
	)
{
	NTSTATUS Status;

	Status = ZwReplyPort (hPort, Msg);

	return NT_SUCCESS(Status);
}

BOOLEAN
NTAPI
AcceptPort(
	PLPC_MESSAGE Msg,
	PHANDLE AcceptedHandle
	)
{
	NTSTATUS Status;

	Status = ZwAcceptConnectPort (
		AcceptedHandle,
		NULL,
		Msg,
		TRUE,
		NULL,
		NULL
		);

	if (NT_SUCCESS(Status))
	{
		Status = ZwCompleteConnectPort (*AcceptedHandle);
	}

    SetLastStatus (Status);

	return NT_SUCCESS(Status);
}
