/**
 * NT Wrapper project.
 *
 * Memory routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"


#define HEAP_ZERO_MEMORY                0x00000008      

HANDLE heap;

typedef struct MEM_PROTECTED_SECTION
{
    MEM_PROTECTED_SECTION *Next;
    PVOID Allocs[65536];
    ULONG Sizes[65536];
    int offset;
} *PMEM_PROTECTED_SECTION;

PMEM_PROTECTED_SECTION GlobMemProtection;

VOID
_ProtectAddAllocation(
    PVOID Ptr,
    ULONG Size
    )
{
    PMEM_PROTECTED_SECTION p = GlobMemProtection;
    //for ( ; p != NULL; p = p->Next)
    {
        bool bAdded = false;
        for (ULONG i=0; i<65536; i++)
        {
            if (p->Allocs[i] == NULL)
            {
                p->Allocs[i] = Ptr;
                p->Sizes[i] = Size;
                bAdded = true;
                break;
            }
        }
        if (!bAdded)
            Print("Could not add allocation [p %08x size %08x] to protected section %08x: no free space\n", 
                Ptr,
                Size,
                p
                );
    }
}

VOID
_ProtectDeleteAllocation(
    PVOID Ptr
    )
{
    PMEM_PROTECTED_SECTION p = GlobMemProtection;
    //for ( ; p != NULL; p = p->Next)
    {
        for (ULONG i=0; i<65536; i++)
        {
            if (p->Allocs[i] == Ptr)
            {
                p->Allocs[i] = NULL;
                p->Sizes[i] = 0;
                break;
            }
        }
    }
}

VOID
_ProtectCheckLeaks(
    PMEM_PROTECTED_SECTION Sect
    )
{
    int nLeaks = 0;

    for (ULONG i=0; i<65536; i++)
    {
        if (Sect->Allocs[i])
        {
            PUCHAR p = (PUCHAR)Sect->Allocs[i];

            for (int j=0; j<Sect->offset; j++) Print("  ");

            Print("MEMORY LEAK FOUND: Ptr = %08x [%02x %02x %02x %2x ... %c%c%c%c], Size = %08x (%d)\n",
                p,
                p[0], p[1], p[2], p[3],
                p[0], p[1], p[2], p[3],
                Sect->Sizes[i],
                Sect->Sizes[i]
            );

            hfree (p);

            nLeaks ++;
        }
    }

    for (int j=0; j<Sect->offset; j++) Print("  ");
    if (nLeaks)
        Print("%d LEAK(S) FOUND!\n", nLeaks);
    else
        Print("No leaks found\n");
}

VOID
NTAPI
hfree (
	PVOID Ptr
	)
{
    if (GlobMemProtection)
        _ProtectDeleteAllocation (Ptr);

	RtlFreeHeap (heap, 0, Ptr);
}

PVOID
NTAPI
halloc (
	SIZE_T Size
	)
{
	PVOID p = RtlAllocateHeap (heap, HEAP_ZERO_MEMORY, Size);

    if (p && GlobMemProtection)
        _ProtectAddAllocation (p, Size);

    return p;
}

BOOLEAN
NTAPI
MemoryEnterProtectedSection(
    )
{
    PMEM_PROTECTED_SECTION p = (PMEM_PROTECTED_SECTION) halloc (sizeof(MEM_PROTECTED_SECTION));
    if (!p)
        return Print("Could not allocate memory for protected section!\n"), FALSE;

    memset (p, 0, sizeof(MEM_PROTECTED_SECTION));
    p->Next = GlobMemProtection;
    GlobMemProtection = p;

    if (p->Next)
        p->offset = p->Next->offset + 1;
    else
        p->offset = 0;

//    for (int j=0; j<p->offset; j++) Print("  ");
//    Print("Entered protected section %08x\n", p);

    return TRUE;
}

VOID
NTAPI
MemoryLeaveProtectedSection(
    )
{
    PMEM_PROTECTED_SECTION p = GlobMemProtection;
    GlobMemProtection = GlobMemProtection->Next;
    
    _ProtectCheckLeaks (p);

//    for (int j=0; j<p->offset; j++) Print("  ");
//    Print("Left protected section %08x\n", p);

    hfree (p);
}

VOID
NTAPI
SetProcessHeap(
	HANDLE hHeap
	)
{
	NtCurrentTeb()->Peb->ProcessHeap = hHeap;
    heap = hHeap;
}

#ifndef NTTEST
HANDLE
NTAPI
GetProcessHeap(
	)
{
	return NtCurrentTeb()->Peb->ProcessHeap;
}
#endif

