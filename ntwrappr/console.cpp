/**
 * NT Wrapper project.
 *
 * Console routines.
 *
 * [C] Great, 2009.
 */

#include "ntwrappr.h"

#define VK_BACKSPACE 8

char ascii_codes[] =
{
	0,0,'1','2','3','4','5','6','7','8','9','0','-','=',VK_BACKSPACE,0,
	'q','w','e','r','t','y','u','i','o','p','[',']','\n',0,
	'a','s','d','f','g','h','j','k','l',';','\'', '`',0,
	'\\','z','x','c','v','b','n','m',',','.','/',0,'*',0,
	' ',0, 0,0,0,0,0,0,0,0,0,0, 0,0, '7','8','9','-','4','5',
	'6','+','1','2','3','0','.', 0,0
};

char ascii_codes_shifted[] =
{
	0,0,'!','@','#','$','%','^','&','*','(',')','_','+',VK_BACKSPACE,0,
	'Q','W','E','R','T','Y','U','I','O','P','{','}','\n',0,
	'A','S','D','F','G','H','J','K','L',':','"', '~',0,
	'|','Z','X','C','V','B','N','M','<','>','?',0,'*',0,
	' ',0, 0,0,0,0,0,0,0,0,0,0, 0,0, '7','8','9','-','4','5',
	'6','+','1','2','3','0','.', 0,0
};

BOOLEAN Shifted = FALSE;
BOOLEAN CapsLock = FALSE;


//
// Open keyboard device & return its handle
//

HANDLE 
NTAPI
OpenKeyboard (
	int nClass
	)
{
	wchar_t buff[32];

	_snwprintf (buff, sizeof(buff)-1, L"\\Device\\KeyboardClass%d", nClass);

	return CreateFile (buff, 
		GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES, 
		0,
		FILE_OPEN,
		1,
		FILE_ATTRIBUTE_NORMAL);
}


BOOLEAN bExitOnEscEnabled = TRUE;

//
// Disable exit on ESC
//

VOID
NTAPI
DisableExitOnEsc(
    )
{
    bExitOnEscEnabled = FALSE;
}

BOOLEAN
NTAPI
TryExit(
    )
{
    if (bExitOnEscEnabled)
    {
	    RtlRaiseStatus (MANUALLY_INITIATED_CRASH);
    }
    else
    {
        Print("Exit is not supported due to harderror port.\n");
    }

    return FALSE;
}

//
// ReadChar() - read character from keyboard with ascii translation
//

UCHAR
NTAPI
ReadChar (
	HANDLE hKeyboard, 
	char* Buffer
	)
{
	KEYBOARD_INPUT_DATA InputData[1];
	UCHAR Ret = ReadCharFailure;
	ULONG BytesRead = 0;

	//
	// Read from keyboard
	//

	memset (&InputData, 0, sizeof(InputData));

	BytesRead = ReadFile (hKeyboard, &InputData, sizeof(InputData), 0);

	if (BytesRead != -1)
	{
		if (!BytesRead || (BytesRead % sizeof(KEYBOARD_INPUT_DATA)))
		{
			KdPrint (("ZwReadFile returned %d bytes - INVALID SIZE\n",BytesRead));
			goto _exit;
		}

		//
		// Get scan-code and other values
		//

		USHORT  ScanCode = InputData->MakeCode;
		BOOLEAN Extended = InputData->Flags & KEY_E0;
		BOOLEAN Up = InputData->Flags & KEY_BREAK;

		char ascii;
		
		if (Shifted)
			ascii = ascii_codes_shifted[ScanCode];
		else
			ascii = ascii_codes [ScanCode];

		if (ascii)
		{
			//
			// If user released ascii key, skip this.
			//

			if (Up)
			{
				Ret = ReadCharSystemKey;
			}
			else
			{
				//
				// Else write ascii code to buffer
				//

				Ret = ReadCharSuccess;
				*Buffer = ascii;
			}
		}
		else
		{
			//
			// User pressed/released system key
			//

			Ret = ReadCharSystemKey;
			
			switch (ScanCode)
			{
			case 0x2A:	// Left shift
			case 0x36:	// Right shift
				
				if (Up == 0)
					Shifted = !CapsLock;
				else
					Shifted = CapsLock;
				break;

			case 0x3A:	// Caps lock

				if (Up == 0)
					CapsLock = !CapsLock;

				break;

			case 1: // Escape

                TryExit();

				break;

			}
		}
	}

_exit:
	return Ret;
}

//
// Read null-terminated string from keyboard.
// User presses some keys and finishes with ENTER
//
ULONG
NTAPI
ReadString (
	HANDLE hKeyboard, 
	char *prompt,
	char *Buffer, 
	int MaxLen,
	char ReplaceChar
	)
{
	int i;

	Print("%s", prompt);

	for (i=0; i<MaxLen; i++)
	{
		UCHAR Status;

		do
		{
			Status = ReadChar (hKeyboard, &Buffer[i]);
			//DisplayString(L".");
		}
		while (Status == ReadCharSystemKey);

		if (Buffer[i] == VK_BACKSPACE)
		{
			if (i == 0)
			{
				i--;
				continue;
			}

			i-=2;

			Buffer[i+1] = ' ';

			int j;

			Print("\r%s", prompt);
			for (j=0; j<=i; j++)
			{
				Print("%c", ReplaceChar ? ReplaceChar : Buffer[j]);
			}

			Print(" \r%s", prompt);
			for (j=0; j<=i; j++)
			{
				Print("%c", ReplaceChar ? ReplaceChar : Buffer[j]);
			}

			continue;
		}

		if (Buffer[i] == '\n')
		{
			Print("\n");
			break;
		}

		Print("%c", ReplaceChar ? ReplaceChar : Buffer[i]);
	}

	Buffer[i] = 0;
	return i;
}

HANDLE hKeyboard;

HANDLE
NTAPI
GetDefaultKeyboard(
	)
{
	return hKeyboard;
}
