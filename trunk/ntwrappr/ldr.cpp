/**
 * NT Wrapper project.
 *
 * Loader routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"


PVOID
NTAPI
LoadDll(
    PWSTR ImagePath,
    ULONG Chars
    )
{
    UNICODE_STRING ImagePathString;
    NTSTATUS Status;
    PVOID ModuleHandle;
    ULONG DllCharacteristics = Chars;

    RtlInitUnicodeString (&ImagePathString, ImagePath);
    Status = LdrLoadDll (NULL, &DllCharacteristics, &ImagePathString, &ModuleHandle);

    SetLastStatus (Status);
    if (!NT_SUCCESS(Status))
    {
        ModuleHandle = NULL;
    }

    return ModuleHandle;
}

PVOID
NTAPI
FindDll(
    PWSTR ImagePath
    )
{
    UNICODE_STRING ImagePathString;
    NTSTATUS Status;
    PVOID ModuleHandle;
    ULONG DllCharacteristics;

    RtlInitUnicodeString (&ImagePathString, ImagePath);
    Status = LdrGetDllHandle (NULL, &DllCharacteristics, &ImagePathString, &ModuleHandle);

    SetLastStatus (Status);
    if (!NT_SUCCESS(Status))
    {
        ModuleHandle = NULL;
    }

    return ModuleHandle;
}

PVOID
NTAPI
GetProcedureAddress(
    PVOID ImageBase,
    PCHAR ProcedureName
    )
{
    PVOID ProcAddress;
    ANSI_STRING ProcedureNameString;
    PANSI_STRING pProcString = NULL;
    ULONG Ordinal = 0;
    NTSTATUS Status;

    if ((ULONG_PTR)ProcedureName & 0xFFFF0000)
    {
        RtlInitAnsiString (&ProcedureNameString, ProcedureName);
        pProcString = &ProcedureNameString;
    }
    else
    {
        Ordinal = (ULONG) ProcedureName;
    }

    Status = LdrGetProcedureAddress (ImageBase,
        pProcString,
        Ordinal,
        &ProcAddress);

    SetLastStatus (Status);

    if (!NT_SUCCESS(Status))
    {
        ProcAddress = NULL;
    }

    return ProcAddress;
}
