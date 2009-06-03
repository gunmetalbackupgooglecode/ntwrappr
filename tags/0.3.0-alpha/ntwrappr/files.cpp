/**
 * NT Wrapper project.
 *
 * File routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"


/* Open a file */
HANDLE
NTAPI
OpenFile (
	PWSTR FileName,
	ULONG AccessMode,
	ULONG ShareAccess,
	ULONG OpenOptions
	)
{
	UNICODE_STRING Name;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	HANDLE Handle;
	OBJECT_ATTRIBUTES Oa;

	RtlInitUnicodeString (&Name, FileName);
	InitializeObjectAttributes (&Oa, &Name, OBJ_CASE_INSENSITIVE, 0, 0);

	Status = ZwOpenFile (
		&Handle,
		AccessMode,
		&Oa,
		&IoStatus,
		ShareAccess,
		OpenOptions
		);

	if (NT_SUCCESS(Status))
		return Handle;

//	KdPrint (( "ZwOpenFile for [%S] returned ntstatus %08x\n", FileName, Status ));
	return NULL;

}

/* Create new or open existing file */
HANDLE
NTAPI
CreateFile (
	PWSTR FileName, 
	ULONG AccessMode, 
	ULONG ShareMode, 
	ULONG Disposition, 
	ULONG Options,
	ULONG Attributes
	)
{
	UNICODE_STRING Name;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	HANDLE Handle;
	OBJECT_ATTRIBUTES Oa;

	RtlInitUnicodeString (&Name, FileName);
	InitializeObjectAttributes (&Oa, &Name, OBJ_CASE_INSENSITIVE, 0, 0);

	Status = ZwCreateFile (
		&Handle,
		AccessMode,
		&Oa,
		&IoStatus,
		NULL,
		Attributes,
		ShareMode,
		Disposition,
		Options,
		0,
		0);

	if (NT_SUCCESS(Status))
		return Handle;

	KdPrint (( "ZwCreateFile for [%S] returned ntstatus %08x\n", FileName, Status ));
	return NULL;
}

/* Read the file */
ULONG 
NTAPI
ReadFile (
	HANDLE hFile, 
	PVOID Buffer, 
	ULONG MaxLen, 
	ULONG Position
	)
{
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	LARGE_INTEGER Pos = {0};
	HANDLE hEvent;
	OBJECT_ATTRIBUTES EventAttributes;

	Pos.LowPart = Position;

	InitializeObjectAttributes (
		&EventAttributes,
		0, 0, 0, 0 );

	Status = ZwCreateEvent (
		&hEvent,
		EVENT_ALL_ACCESS,
		&EventAttributes,
		SynchronizationEvent,
		0 );

	if (!NT_SUCCESS(Status))
	{
		KdPrint (("ZwCreatEvent failed with status %08x\n", Status));
		return -1;
	}

	Status = ZwReadFile (
		hFile,
		hEvent,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		MaxLen,
		Position == -1 ? NULL : &Pos,
		NULL );
	
	if (Status == STATUS_PENDING)
	{
		Status = ZwWaitForSingleObject (hEvent, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if (NT_SUCCESS(Status))
	{
		ZwClose (hEvent);
		return IoStatus.Information;
	}

	if (Status != STATUS_END_OF_FILE)
	{
        KdPrint (("hFile %x hEvent %x Buffer %p MaxLen %x Pos %x\n",
            hFile, hEvent, Buffer, MaxLen, Position));
		KdPrint (("ZwReadFile failed with status %08x\n", Status));
		ZwClose (hEvent);
		return -1;
	}
	
	ZwClose (hEvent);
	return -2;
}

/* Write the file */
ULONG 
NTAPI
WriteFile (
	HANDLE hFile, 
	PCVOID Buffer, 
	ULONG Length, 
	ULONG Position
	)
{
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	LARGE_INTEGER Pos = {0};
	HANDLE hEvent;
	OBJECT_ATTRIBUTES EventAttributes;

	Pos.LowPart = Position;

	InitializeObjectAttributes (
		&EventAttributes,
		0, 0, 0, 0 );

	Status = ZwCreateEvent (
		&hEvent,
		EVENT_ALL_ACCESS,
		&EventAttributes,
		SynchronizationEvent,
		0 );

	if (!NT_SUCCESS(Status))
	{
		KdPrint (("ZwCreatEvent failed with status %08x\n", Status));
		return -1;
	}

	Status = ZwWriteFile (
		hFile,
		hEvent,
		NULL,
		NULL,
		&IoStatus,
		(PVOID) Buffer,
		Length,
		Position == -1 ? NULL : &Pos,
		NULL );
	
	if (Status == STATUS_PENDING)
	{
		Status = ZwWaitForSingleObject (hEvent, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if (NT_SUCCESS(Status))
	{
		ZwClose (hEvent);
		return IoStatus.Information;
	}

	KdPrint (("ZwWriteFile failed with status %08x\n", Status));
	return -1;
}

/* Query directory contents */
BOOLEAN
NTAPI
QueryDirectory (
	HANDLE hDir, 
	BOOLEAN RestartScan,
	PFILE_BOTH_DIR_INFORMATION Buffer,
	ULONG MaxLen
	)
{
	HANDLE hEvent;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Oa = {sizeof(Oa)};
	IO_STATUS_BLOCK IoStatus;
	
	Status = ZwCreateEvent (&hEvent, EVENT_ALL_ACCESS, &Oa,
		SynchronizationEvent, FALSE);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("ZwCreateEvent failed with status %08x\n", Status));
		return NULL;
	}

	Status = ZwQueryDirectoryFile (
		hDir,
		hEvent,
		NULL,
		NULL,
		&IoStatus,
		Buffer,
		MaxLen,
		FileBothDirectoryInformation,
		TRUE,
		NULL,
		RestartScan
		);

	ZwClose (hEvent);
	return NT_SUCCESS(Status);
}
