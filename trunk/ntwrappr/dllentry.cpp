#include "ntwrappr.h"

BOOLEAN NTAPI DllEntry (PVOID Base, ULONG Reason, PVOID Unknown)
{
	if (Reason == 1)
	{
		PUCHAR NtHeaders = ((PUCHAR)Base + *(ULONG*)((PUCHAR)Base + 0x3c));
		ULONG ImageSize = *(ULONG*)(NtHeaders + 0x50);
		PVOID ImageBase = Base;
		ULONG OldProtect;
		NTSTATUS Status;

		Status = ZwProtectVirtualMemory (
			NtCurrentProcess(),
			&ImageBase,
			&ImageSize,
			PAGE_EXECUTE_READWRITE,
			&OldProtect
			);

		if (!NT_SUCCESS(Status))
			Print("ZwProtectVirtualMemory = %08x\n", Status);
	}

	return TRUE;
}
