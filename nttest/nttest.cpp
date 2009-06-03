#define _CRTIMP
#include "../ntwrappr.h"
#include <stdio.h>

#define Print printf

typedef struct PROC
{
    PROC* Childs[1024];
    wchar_t ProcessName[256];
    ULONG ProcessID;
} *PPROC;

// Recursive search
PPROC TreeFind (PPROC Head, ULONG PID)
{
    PPROC p = NULL;

    if (Head->ProcessID == PID)
        return Head;

    for (ULONG i=0; i<1024; i++)
    {
        if (Head->Childs[i])
        {
            p = TreeFind (Head->Childs[i], PID);
            if (p)
                return p;
        }
    }

    return NULL;
}

void DumpTree (PPROC Head, int offset = 0)
{
    if (Head->ProcessID != -1)
    {
        for (int j=0; j<offset; j++) Print("  ");
        Print ("%S [PID %x]\n", Head->ProcessName, Head->ProcessID);
    }

    for (ULONG i=0; i<1024; i++)
    {
        if (Head->Childs[i])
            DumpTree (Head->Childs[i], offset + 1);
    }
}

void FreeTree (PPROC Head)
{
    for (ULONG i=0; i<1024; i++)
    {
        if (Head->Childs[i])
            FreeTree (Head->Childs[i]);
    }

    hfree (Head);
}

void AppendChild (PPROC Parent, PPROC Child)
{
    for (ULONG i=0; i<1024; i++)
    {
        if (Parent->Childs[i] == NULL)
        {
            Parent->Childs[i] = Child;
            return;
        }
    }

    Print ("No free space to add child PID %x [%S] to PPID %x [%S] !!\n",
        Child->ProcessID,
        Child->ProcessName,
        Parent->ProcessID,
        Parent->ProcessName
        );
}

void PTree()
{
    PPROC TreeHead;
    PTASKLIST_CONTEXT Context;

    if (ProcessFirst (&Context))
    {
        TreeHead = (PPROC) halloc (sizeof(PROC));
        memset (TreeHead, 0, sizeof(PROC));
        TreeHead->ProcessID = -1;

        ULONG ProcCount = 0;

        do
        {
            PPROC Proc = TreeFind (TreeHead, Context->Proc->ProcessId);
            if (Proc == NULL)
            {
                Proc = (PPROC) halloc (sizeof(PROC));
                memset (Proc, 0, sizeof(PROC));
                Proc->ProcessID = Context->Proc->ProcessId;
                memcpy (Proc->ProcessName, Context->Proc->ProcessName.Buffer,  Context->Proc->ProcessName.Length);
                if (Proc->ProcessID == 0)
                    wcscpy (Proc->ProcessName, L"Idle");

                PPROC Parent = TreeFind (TreeHead, Context->Proc->InheritedFromProcessId);
                if (!Parent)
                    Parent = TreeHead;
                AppendChild (Parent, Proc);
            }
            else
            {
                Print ("Process PID %x [%S] already exists !!\n", Proc->ProcessID, Proc->ProcessName);
            }

            ProcCount++;
        }
        while (ProcessNext (&Context));

        DumpTree (TreeHead, -1);
        FreeTree (TreeHead);

        Print ("\nTotal:  %d processes\n", ProcCount);
    }
    else
    {
        Print ("ProcessFirst failed!\n");
    }
}

int main()
{
    //
    // INIT
    //;
    SetProcessHeap (GetProcessHeap());


    //
    // ACTION
    //

    FILE *fp = fopen("c:\\boot.ini", "rb");
    if (fp)
    {
        char buffer[1000];
        size_t items = fread (buffer, 10, 100, fp);

        printf("%d items read\n", items);

        fclose (fp);
    }

    fp = fdopen (1, "w");
    if (fp)
    {
        size_t items;

        items = fwrite ("hello\n", 6, 1, fp);

        fclose (fp);
    }

    Sleep (-1);

    /////

    if (!MemoryEnterProtectedSection ())
        return printf("MemoryEnterProtectedSection failed\n");

    PTree();

    MemoryLeaveProtectedSection ();

    if (0)
    {
        if (!MemoryEnterProtectedSection ())
            return printf("MemoryEnterProtectedSection failed\n");

        PCHAR p = (PCHAR) halloc (10);
        strcpy (p, "hello");

        {
            if (!MemoryEnterProtectedSection ())
                return printf("MemoryEnterProtectedSection failed\n");

            for (int i=0; i<10; i++)
            {
                PCHAR p = (PCHAR) halloc (10);
                strcpy (p, "warwar");
            }

            MemoryLeaveProtectedSection ();
        }

        MemoryLeaveProtectedSection ();
    }

    //
    // SLEEP
    //

    Sleep (-1);
}
