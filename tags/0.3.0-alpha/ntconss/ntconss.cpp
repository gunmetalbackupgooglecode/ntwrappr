/**
 * NT Console Subsystem process.
 *
 * This is a part of nt wrapper library
 *
 * [C] Great, 2009
 */

#define SET_ENTRY
#define WAIT_N_SECONDS
#define FAIL_ON_EXCEPTION
#define _CRTIMP
#include "ntwrappr.h"
#include "pe_image.h"

struct THREAD_INFO
{
    HANDLE hThread;
    CLIENT_ID id;
};

struct CSRSS_MESSAGE
{
    ULONG Unknown1;
    ULONG Opcode;
    ULONG Status;
    ULONG Unknown2;
};

PHANDLE
FindCsrPortHandle(
    )
{
    PVOID CsrClientCallServer = (PVOID) GetProcedureAddress (FindDll (L"ntdll.dll"), "CsrClientCallServer");
    ULONG_PTR ZwRequestWaitReplyPort = (ULONG_PTR) GetProcedureAddress (FindDll (L"ntdll.dll"), "ZwRequestWaitReplyPort");
    
    if (CsrClientCallServer)
    {
        for (PUCHAR p = (PUCHAR)CsrClientCallServer; p < (PUCHAR)CsrClientCallServer + 0x1000; p++)
        {
            if (
                // PUSH DWORD PTR DS:[CsrPortHandle]
                p[0] == 0xFF &&
                p[1] == 0x35 &&
                // 2,3,4,5 - port handle

                // CALL ZwRequestWaitReplyPort
                p[6] == 0xE8
                // 7,8,9,10 - call arg
                )
            {
                ULONG_PTR CallArg = (ULONG_PTR)&p[11] + *(ULONG_PTR*)&p[7];
                PHANDLE CsrPortHandle = *(PHANDLE*)&p[2];

                if (CallArg == ZwRequestWaitReplyPort)
                {
                    return CsrPortHandle;
                }
            }
        }
    }

    return NULL;
}

VOID
NTAPI
PrintMessage(
	PLPC_MESSAGE lpc
	)
{
	char *MessageTypes[] = {
		"LPC_NEW_MESSAGE",
		"LPC_REQUEST",
		"LPC_REPLY",
		"LPC_DATAGRAM",
		"LPC_LOST_REPLY",
		"LPC_PORT_CLOSED",
		"LPC_CLIENT_DIED",
		"LPC_EXCEPTION",
		"LPC_DEBUG_EVENT",
		"LPC_ERROR_EVENT",
		"LPC_CONNECTION_REQUEST"
	};

	Print("LPC_MESSAGE %08x:\n", lpc);
	Print(" DataSize = %08x\n", lpc->DataSize);
	Print(" MessageSize = %08x\n", lpc->MessageSize);
	Print(" MessageType = %s [%08x]\n", lpc->MessageType > 10 ? "LPC_UNKNOWN" : MessageTypes[lpc->MessageType], lpc->MessageType);
	Print(" VirtualRangesOffset = %08x\n", lpc->VirtualRangesOffset);
	Print(" ClientId.UniqueThread = %08x\n", lpc->ClientId.UniqueThread);
	Print(" ClientId.UniqueProcess = %08x\n", lpc->ClientId.UniqueProcess);
	Print(" MessageId = %08x\n", lpc->MessageId);
	Print(" SectionSize = %08x\n", lpc->SectionSize);

	for( int i=0; i<lpc->DataSize; i++ ) 
	{
		Print(" %02x", lpc->Data[i]);
	}

	Print("\n\n");
}

VOID
NTAPI
HardErrorThread(
	PVOID Parameter
	)
{
	HANDLE hHardErrorPort;
	NTSTATUS Status;

	hHardErrorPort = CreatePort (NULL, 0);
	if (hHardErrorPort == NULL)
	{
		Status = GetLastStatus();
		Print("HARDERR: CreatePort failed with status %08x\n", Status);
		RtlExitUserThread (Status);
	}

	Status = ZwSetDefaultHardErrorPort (hHardErrorPort);

	if (!NT_SUCCESS(Status))
	{
		Print("HARDERR: ZwSetDefaultHardErrorPort failed with status %08x\n", Status);
		CloseHandle (hHardErrorPort);
		RtlExitUserThread (Status);
	}

    DisableExitOnEsc ();

    UCHAR MessageBuffer [0x148];
	LPC_MESSAGE *Message = (LPC_MESSAGE*) MessageBuffer;

	for (;;)
	{
		if (!WaitReceivePort (hHardErrorPort, Message))
		{
			Print("HARDERR: WaitReceivePort failed with st %08x\n", GetLastStatus());
		}

		switch (Message->MessageType)
		{
		case LPC_ERROR_EVENT:
			{
				PHARDERROR_MSG h = (PHARDERROR_MSG) Message;

				Print(
					"**************************************************************\n"
					"*               Hard Error Port got a message                *\n"
					"**************************************************************\n"
                    "     ===  PID %08x  TID %08x ===\n"
					" ErrorStatus = %08x          ResponseOption = %08x\n"
					" NumberOfParameters = %08x   ParametersMask = %08x\n"
					" Parameters [%08x %08x %08x %08x]\n"
					"**************************************************************\n"
					,
                    Message->ClientId.UniqueProcess,Message->ClientId.UniqueThread,
					h->ErrorStatus,
					h->ResponseOption,
					h->NumberOfParameters,
					h->UnicodeStringParameterMask,
					h->Parameters[0], h->Parameters[1], 
					h->Parameters[2], h->Parameters[3]
				);

                if (h->ErrorStatus == 0x17e8)
                {
                    // Application initialization exception
                    PTASKLIST_CONTEXT Context;
                    wchar_t procName[256] = L"(unknown process)";

                    if (ProcessFirst (&Context))
                    {
                        do
                        {
                            if (Context->Proc->ProcessId == (ULONG)Message->ClientId.UniqueProcess)
                            {
                                memcpy (procName, 
                                    Context->Proc->ProcessName.Buffer, 
                                    Context->Proc->ProcessName.MaximumLength);
                                break;
                            }
                        }
                        while (ProcessNext (&Context));
                    }

                    Print("Process %S failed to initialize with status %08x\n", procName, h->Parameters[0]);
                    
                    if (h->Parameters[0] == STATUS_DLL_INIT_FAILED)
                    {
                        Print("STATUS_DLL_INIT_FAILED: Initialization of the dynamic link \n"
                              " library failed. The process is terminating abnormally.\n");
                    }

                    Print ("**************************************************************\n");
                }

				h->Response = ResponseNotHandled;

				switch (h->ResponseOption)
				{
				case OptionAbortRetryIgnore:

					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Abort/Retry/Ignore (ARI)? ", str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'A' &&
							   str[0] != 'R' &&
							   str[0] != 'I');

						switch (str[0])
						{
						case 'A': h->Response = ResponseAbort; break;
						case 'R': h->Response = ResponseRetry; break;
						case 'I': h->Response = ResponseIgnore; break;
						}
					}
					break;

				case OptionOk:
					{
						h->Response = ResponseOk;
						break;
					}

				case OptionOkCancel:
					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Ok/Cancel (OC)? ",
								str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'O' &&
							   str[0] != 'C');

						switch (str[0])
						{
						case 'O': h->Response = ResponseOk; break;
						case 'C': h->Response = ResponseCancel; break;
						}
					}
					break;

				case OptionRetryCancel:
					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Retry/Cancel (RC)? ", 
								str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'R' &&
							   str[0] != 'C');

						switch (str[0])
						{
						case 'R': h->Response = ResponseRetry; break;
						case 'C': h->Response = ResponseCancel; break;
						}
					}
					break;
				
				case OptionYesNo:
					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Yes/No (YN)? ", 
								str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'Y' &&
							   str[0] != 'N');

						switch (str[0])
						{
						case 'Y': h->Response = ResponseYes; break;
						case 'N': h->Response = ResponseNo; break;
						}
					}
					break;

				case OptionYesNoCancel:

					{
						char str[10];

						do
						{
							ReadString (GetDefaultKeyboard(), 
								"Yes/No/Cancel (YNC)? ", str, sizeof(str)-1, 0);

							str[0] = toupper (str[0]);
						}
						while (str[0] != 'Y' &&
							   str[0] != 'N' &&
							   str[0] != 'C');

						switch (str[0])
						{
						case 'Y': h->Response = ResponseYes; break;
						case 'N': h->Response = ResponseNo; break;
						case 'C': h->Response = ResponseCancel; break;
						}
					} // case
					break;
				} // switch

				ReplyPort (hHardErrorPort, &h->LpcMessageHeader);

			} // case
			break;

		default:

			PrintMessage (Message);

		} // switch
			
	} // for (;;)

	RtlExitUserThread (STATUS_SUCCESS);
}

VOID
NTAPI
ApiPortServer(
	PVOID Parameter
	)
{
	HANDLE hApiPort;
	NTSTATUS Status;

    hApiPort = CreatePort (L"\\Windows\\ApiPort", 0);
	if (hApiPort == NULL)
	{
		Status = GetLastStatus();
		Print("APIPORT: CreatePort failed with status %08x\n", Status);
		RtlExitUserThread (Status);
	}

    PHANDLE CsrPortHandle = FindCsrPortHandle ();
    if (CsrPortHandle)
    {
        *CsrPortHandle = hApiPort;
    }
    else
    {
        Print("APIPORT: Could not find CsrPortHandle address\n");
        RtlExitUserThread (STATUS_UNSUCCESSFUL);
    }

    UCHAR MessageBuffer [0x148];
	LPC_MESSAGE *Message = (LPC_MESSAGE*) MessageBuffer;

	for (;;)
	{
		if (!WaitReceivePort (hApiPort, Message))
		{
			Print("APIPORT: WaitReceivePort failed with st %08x\n", GetLastStatus());
		}

		switch (Message->MessageType)
		{
        case LPC_CONNECTION_REQUEST:
        {
            HANDLE AcceptedHandle;

            Print ("APIPORT: Connection request from PID %x TID %x\n", Message->ClientId.UniqueProcess, Message->ClientId.UniqueThread);

            if (AcceptPort (Message, &AcceptedHandle))
            {
                Print ("APIPORT: AcceptedHandle = %lx\n", AcceptedHandle);

                //
                // Map base shared memory
                //


            }
            else
            {
                Print ("APIPORT: AcceptPort failed with status %lx\n", GetLastStatus());
            }

            break;
        }

        case LPC_PORT_CLOSED:
        {
            Print ("APIPORT: Port closed: PID %x TID %x\n", Message->ClientId.UniqueProcess, Message->ClientId.UniqueThread);
            break;
        }

        case LPC_REQUEST:
        {
            CSRSS_MESSAGE* csrss = (CSRSS_MESSAGE*)&Message->Data[0];

            Print("APIPORT: CSRSS message OpCode=%lx\n", csrss->Opcode);

            csrss->Status = STATUS_INVALID_PARAMETER;

            switch (csrss->Opcode)
            {
            case 0x10001:
                // new thread
            {
                THREAD_INFO *thread = (THREAD_INFO*)(csrss+1);
                Print ("APIPORT: New thread (hThread = %lx, TID %lx PID %lx)\n",
                    thread->hThread,
                    thread->id.UniqueThread,
                    thread->id.UniqueProcess);
                csrss->Status = STATUS_SUCCESS;
                break;
            }
            }

            if(!ReplyPort (hApiPort, Message))
            {
                Print ("APIPORT: ReplyPort failed with st %lx\n", GetLastStatus());
            }

            break;
        }

		default:

			PrintMessage (Message);

		} // switch
			
	} // for (;;)

	RtlExitUserThread (STATUS_SUCCESS);
}

HANDLE hReadOnlySharedSection;
PVOID ReadOnlySharedBase;
PVOID ReadWriteSharedBase;

ULONG SharedDataInfoOffset = 0x1000;

HANDLE hReturnToWindowsEvent;
HANDLE hSuccessfulLogonEvent;

#pragma pack (push, 2)
typedef struct _BASE_SHARED_DATA
{
    UNICODE_STRING WindowsRoot;
    UNICODE_STRING SystemRoot;
    UNICODE_STRING BaseNamedObjects;
    USHORT Unknown[5];
    WCHAR ServicePack[30];
} BASE_SHARED_DATA, *PBASE_SHARED_DATA;

VOID
CreateBaseShared(
    )
{
    //
    // Initialize BaseSharedServerData
    //

    do
    {
        NTSTATUS Status;
        LARGE_INTEGER MaximumSize = {PAGE_SIZE*7, 0};

        Print("Initializing shared server data\n");

        Status = ZwCreateSection (
            &hReadOnlySharedSection,
            SECTION_ALL_ACCESS,
            NULL,
            &MaximumSize,
            PAGE_READWRITE,
            MEM_COMMIT,
            NULL);
        
        if (!NT_SUCCESS(Status))
        {
            Print("ZwCreateSection failed with status %lx\n", Status);
            break;
        }

        LARGE_INTEGER Offset = {0};
        SIZE_T ViewSize = MaximumSize.LowPart;

        ReadOnlySharedBase = NULL;
        ReadWriteSharedBase = NULL;

        Status = ZwMapViewOfSection (
            hReadOnlySharedSection,
            NtCurrentProcess(),
            &ReadOnlySharedBase,
            0,
            ViewSize,
            &Offset,
            &ViewSize,
            ViewShare,
            SEC_COMMIT,
            PAGE_READONLY);

        if (!NT_SUCCESS(Status))
        {
            Print("ZwMapViewOfSection failed with status %lx\n", Status);
            ZwClose (hReadOnlySharedSection);
            break;
        }

        Print("Section (r/o) mapped at %p\n", ReadOnlySharedBase);

        ViewSize = MaximumSize.LowPart;

        Status = ZwMapViewOfSection (
            hReadOnlySharedSection,
            NtCurrentProcess(),
            &ReadWriteSharedBase,
            0,
            ViewSize,
            &Offset,
            &ViewSize,
            ViewUnmap,
            SEC_COMMIT,
            PAGE_READWRITE);

        if (!NT_SUCCESS(Status))
        {
            Print("ZwMapViewOfSection failed with status %lx\n", Status);
            ZwClose (hReadOnlySharedSection);
            break;
        }

        Print("Section (r/w) mapped at %p\n", ReadWriteSharedBase);

        PPEB Peb = NtCurrentPeb();
        Peb->ReadOnlySharedMemoryBase = ReadOnlySharedBase;
        Peb->ReadOnlySharedMemoryHeap = ReadOnlySharedBase;
        Peb->ReadOnlyStaticServerData = (PUCHAR)ReadOnlySharedBase + SharedDataInfoOffset;

        wcscpy ((PWSTR)((PUCHAR) ReadWriteSharedBase + 0x2000), L"C:\\WINDOWS");
        wcscpy ((PWSTR)((PUCHAR) ReadWriteSharedBase + 0x2100), L"C:\\WINDOWS\\System32");
        wcscpy ((PWSTR)((PUCHAR) ReadWriteSharedBase + 0x2200), L"\\BaseNamedObjects");

        PBASE_SHARED_DATA SharedData = (PBASE_SHARED_DATA)
            ((PUCHAR)ReadWriteSharedBase + SharedDataInfoOffset);

        RtlInitUnicodeString (&SharedData->WindowsRoot, (PWSTR)((PUCHAR) ReadWriteSharedBase + 0x2000));
        RtlInitUnicodeString (&SharedData->SystemRoot, (PWSTR)((PUCHAR) ReadWriteSharedBase + 0x2100));
        RtlInitUnicodeString (&SharedData->BaseNamedObjects, (PWSTR)((PUCHAR) ReadWriteSharedBase + 0x2200));

        wcscpy (SharedData->ServicePack, L"Service Pack 1");

    }
    while (FALSE);
}

NTSTATUS
NTAPI
NativeEntry(
	IN PUNICODE_STRING ImageFile, 
	IN PUNICODE_STRING CommandLine
	)
{
    Print("NTCOSS: Native Console Subsystem " NTWRAPPER_VERSION_A " initialization\n");

    hReturnToWindowsEvent = CreateEvent (EVENT_ALL_ACCESS, L"\\ReturnToWindows", SynchronizationEvent, FALSE);

    if (hReturnToWindowsEvent == NULL)
    {
        Print ("NTCOSS: CreateEvent failed with status %lx\n", GetLastStatus());
        return GetLastStatus();
    }

    hSuccessfulLogonEvent = CreateEvent (EVENT_ALL_ACCESS, L"\\SuccessfulLogon", SynchronizationEvent, FALSE);

    if (hSuccessfulLogonEvent == NULL)
    {
        Print ("NTCOSS: CreateEvent failed with status %lx\n", GetLastStatus());
        return GetLastStatus();
    }

//    Print ("NTCOSS: events: %lx %lx\n", hSuccessfulLogonEvent, hReturnToWindowsEvent);

    if(!CreateThread (NtCurrentProcess(), 
        FALSE, 
        ApiPortServer,
        NULL,
        NULL,
        NULL
        ))
    {
        Print("NTCOSS: CreateThread failed for ApiPort server with status %08x\n", GetLastStatus());
        return GetLastStatus();
    }

//    Print ("NTCOSS: Api port running\n");

    //
    // It is unacceptable to allow our subsystem process to terminate.
    //

    NTSTATUS Status;
    ULONG IsCritical = TRUE;
    BOOLEAN Enabled;

    Status = RtlAdjustPrivilege (SE_DEBUG_PRIVILEGE, TRUE, FALSE, &Enabled);
    if (!NT_SUCCESS(Status))
    {
        Print("NTCOSS: Failed to set up SE_DEBUG_PRIVILEGE with status %lx\n", Status);
        return GetLastStatus();
    }
    else
    {
        Status = ZwSetInformationProcess (NtCurrentProcess(), ProcessBreakOnTermination, &IsCritical, sizeof(IsCritical));
        if (NT_SUCCESS(Status))
        {
//            Print("NTCOSS: Set break-on-termination\n");
        }
        else
        {
            Print("NTCOSS: ZwSetInformationProcess(ProcessBreakOnTermination) failed with status %lx\n", Status);
            return Status;
        }
    }

    //
    // Start shell.
    //
    RTL_USER_PROCESS_INFORMATION ProcessInformation;
    CLIENT_ID ClientId;

    if (CreateProcess (L"\\SystemRoot\\system32\\ntshell.exe", L"", &ClientId, FALSE, FALSE, &ProcessInformation))
    {
        // Shell invoked.

        HANDLE Handles[2] = { hSuccessfulLogonEvent, hReturnToWindowsEvent };

        do
        {
//            Print ("NTCOSS: Shell invoked\n");

            // Wait for one of two events.
            Status = ZwWaitForMultipleObjects (2, Handles, WaitAny, FALSE, NULL);

            if (!NT_SUCCESS(Status))
            {
                Print ("NTCOSS: ZwWaitForSingleObject failed with status %lx\n", Status);
                Print ("NTCOSS: Falling thru infinite loop\n");

                LARGE_INTEGER Interval = {-1,-1};
                ZwDelayExecution (FALSE, &Interval);
                for(;;) ZwYieldExecution();

                // Should never reach here
                Print ("NTCOSS: Should never reach here\n");
                return Status;
            }

            if (Status == STATUS_WAIT_0)
            {
                // Successful logon event signaled.
                KdPrint (("NTCOSS: Successful logon.\n"));

                //
                // Close event handles.
                // When last handle is closed, events will be deleted.
                //

                CloseHandle (hSuccessfulLogonEvent);
                CloseHandle (hReturnToWindowsEvent);

                // Start hard error thread.
                // We cannot ever return to Windows loading until reboot.
                if(!CreateThread (NtCurrentProcess(), 
                    FALSE, 
                    HardErrorThread,
                    NULL,
                    NULL,
                    NULL
                    ))
                {
                    Print("NTCOSS: CreateThread failed for harderror thread with status %08x\n", GetLastStatus());

                    return GetLastStatus(); // BSoD
                }

                // Sleep infinitely               
                LARGE_INTEGER Interval = {-1,-1};
                ZwDelayExecution (FALSE, &Interval);
                for(;;) ZwYieldExecution();

                // Should never reach here
                Print ("NTCOSS: Should never reach here\n");
                return Status;
            }
            else if (Status == STATUS_WAIT_1)
            {
                // ReturnToWindows event signaled.
                KdPrint (("NTCOSS: ReturnToWindows event signaled\n"));
                
                //
                // Close event handles.
                // When last handle is closed, events will be deleted.
                //

                CloseHandle (hSuccessfulLogonEvent);
                CloseHandle (hReturnToWindowsEvent);

                // Unprotect process
                IsCritical = FALSE;
                Status = ZwSetInformationProcess (NtCurrentProcess(), ProcessBreakOnTermination, &IsCritical, sizeof(IsCritical));
                if (NT_SUCCESS(Status))
                {
                    // Success. Return to Windows loading.
                    return STATUS_SUCCESS;
                }
                else
                {
                    // Something failed.
                    // The following return will immediately cause BSoD
                    Print("NTCOSS: ZwSetInformationProcess(ProcessBreakOnTermination) failed with status %lx\n", Status);
                    return Status;
                }
            }

            Print("NTCOSS: ZwWaitForMultipleObjects: unexpected status %lx, repeating\n", Status);
        }
        while (TRUE);
    }

    //
    // CreateProcess failed for shell.
    // Return to windows.
    //

    Print ("NTCOSS: Could not invoke shell, status %lx\n", GetLastStatus());

	for (int i=7; i>0; i--)
	{
		Print ("NTCOSS: Returning to Windows in %2d seconds...\n", i);

		LARGE_INTEGER second = {-1000*10000, -1};
		ZwDelayExecution (FALSE, &second);
	}
    
    return GetLastStatus();
}
