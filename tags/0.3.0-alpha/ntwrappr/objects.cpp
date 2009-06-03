/**
 * NT Wrapper project.
 *
 * Object routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"

/* Close object handle */
BOOLEAN
NTAPI
CloseHandle (
	HANDLE hObject
	)
{
	return NT_SUCCESS (ZwClose (hObject));
}

/* Create an event */
HANDLE
NTAPI
CreateEvent(
    ULONG AccessMask,
    PWSTR wEventName OPTIONAL,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING EventName, *pEventName = NULL;
    HANDLE EventHandle;

    if (ARGUMENT_PRESENT(wEventName))
    {
        RtlInitUnicodeString (&EventName, wEventName);
        pEventName = &EventName;
    }

    InitializeObjectAttributes (&Oa, pEventName, 0, 0, 0);

    Status = ZwCreateEvent (
        &EventHandle,
        AccessMask,
        &Oa,
        EventType,
        InitialState);

    if (!NT_SUCCESS(Status))
    {
        EventHandle = NULL;
    }

    return EventHandle;
}

/* Open an event */
HANDLE
NTAPI
OpenEvent(
    ULONG AccessMask,
    PWSTR Name
    )
{
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING EventName;
    NTSTATUS Status;
    HANDLE EventHandle;

    RtlInitUnicodeString (&EventName, Name);
    InitializeObjectAttributes (&Oa, &EventName, OBJ_CASE_INSENSITIVE, 0, 0);

    Status = ZwOpenEvent (
        &EventHandle,
        AccessMask,
        &Oa);

    if (!NT_SUCCESS(Status))
    {
        EventHandle = NULL;
    }

    return EventHandle;
}

/* Set event */
ULONG
NTAPI
SetEvent(
    HANDLE hEvent
    )
{
    ULONG PreviousState;
    NTSTATUS Status;

    Status = ZwSetEvent (hEvent, &PreviousState);
    if (!NT_SUCCESS(Status))
    {
        PreviousState = EVENT_STATE_ERROR;
    }

    return PreviousState;
}

/* Create object directory */
HANDLE
NTAPI
CreateDirectory(
	PWSTR Path
	)
{
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING us;
	HANDLE hDir;
	NTSTATUS Status;

	RtlInitUnicodeString (&us, Path);
	InitializeObjectAttributes (&Oa, &us, 0, 0, 0);

	Status = ZwCreateDirectoryObject (
		&hDir,
		DIRECTORY_ALL_ACCESS,
		&Oa
		);

	if (!NT_SUCCESS(Status))
		hDir = NULL;

	return hDir;
}

/* Create symbolic link */
HANDLE
NTAPI
CreateSymbolicLink(
	PWSTR Name,
	PWSTR Target
	)
{
	NTSTATUS Status;
	HANDLE hLink;
	OBJECT_ATTRIBUTES Oa;
	UNICODE_STRING Src, Dst;

	RtlInitUnicodeString (&Src, Name);
	RtlInitUnicodeString (&Dst, Target);
	InitializeObjectAttributes (&Oa, &Src, 0, 0, 0);

	Status = ZwCreateSymbolicLinkObject (
		&hLink,
		FILE_READ_ATTRIBUTES,
	  	&Oa,
		&Dst
		);

	if (!NT_SUCCESS(Status))
		hLink = NULL;

	return hLink;
}
