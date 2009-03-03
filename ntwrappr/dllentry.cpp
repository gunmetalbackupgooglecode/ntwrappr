#include "../ntwrappr.h"

BOOLEAN NTAPI DllEntry (PVOID Base, ULONG Reason, PVOID Unknown)
{
	Print("DllEntry(%08x,%08x,%08x)\n", Base, Reason, Unknown);

	if (Reason == 1)
	{
		PUCHAR NtHeaders = ((PUCHAR)Base + *(ULONG*)((PUCHAR)Base + 0x3c));
		ULONG ImageSize = *(ULONG*)(NtHeaders + 0x50);
		PVOID ImageBase = Base;
		ULONG OldProtect;
		NTSTATUS Status;

		Print("SizeOfImage %08x\n", ImageSize);

		Status = ZwProtectVirtualMemory (
			NtCurrentProcess(),
			&ImageBase,
			&ImageSize,
			PAGE_EXECUTE_READWRITE,
			&OldProtect
			);

		Print("ZwProtectVirtualMemory = %08x\n", Status);
	}

	return TRUE;
}
