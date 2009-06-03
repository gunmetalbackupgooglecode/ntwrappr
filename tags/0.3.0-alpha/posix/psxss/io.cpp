#define _CRTIMP
#include "ntwrappr.h"
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>
#include <stdlib.h>
#define printf Print
#define malloc halloc
#define free hfree

#define STD_OUTPUT ((HANDLE)0xFEFEFEFE)

// Pseudohandles for 0,1,2
HANDLE hStdHandles[3] = { 0, STD_OUTPUT, STD_OUTPUT };

static int _cdecl console_write (const void *buffer, int length)
{
    char *strbuf = (char*) malloc (length+1);
    int res = -1;

    if (strbuf)
    {
        memcpy (strbuf, buffer, length);
        strbuf[length] = 0;

        res = printf("%s", strbuf);

        free (strbuf);
    }
    
    return res;
}

static HANDLE _cdecl psx_translate_handle (int fd)
{
    HANDLE hFile = (HANDLE)fd;

    if (fd >= 0 && fd <= 2)
    {
        hFile = hStdHandles[fd];
    }

    return hFile;
}

static int _cdecl psx_output_close (int fd)
{
    hStdHandles[fd] = NULL;
    return 0;
}

int _cdecl _io_init()
{
    hStdHandles[0] = GetDefaultKeyboard ();
    printf("_io_init: kbd %lx\n", hStdHandles[0]);
    return 0;
}

int __cdecl access(const char *, int);
int __cdecl chmod(const char *, int);
int __cdecl chsize(int, long);

int __cdecl close(int fd)
{
    HANDLE hFile = psx_translate_handle(fd);

    if (hFile == STD_OUTPUT)
    {
        return psx_output_close (fd);
    }

    return  CloseHandle ((HANDLE)fd) ? 0 : -1;
}

int __cdecl commit(int);
int __cdecl creat(const char *, int);
int __cdecl dup(int);
int __cdecl dup2(int, int);
int __cdecl eof(int);
long __cdecl filelength(int);
intptr_t __cdecl findfirst(const char *, struct _finddata_t *);
int __cdecl findnext(intptr_t, struct _finddata_t *);
int __cdecl findclose(intptr_t);
int __cdecl isatty(int);
int __cdecl locking(int, int, long);
long __cdecl lseek(int, long, int);
char * __cdecl mktemp(char *);

static char* __psxname_to_winname (const char *psxname, char *winname, size_t maxwinname)
{
    char *ret = winname;
    strncpy (winname, psxname, min(maxwinname,strlen(psxname)+1));
    str_replace_char (winname, '/', '\\');

    if (!_strnicmp (psxname, "/glob/", 6))
    {
        winname[0] = 0;         //  was '/'
        winname[1] = 0;         //  was 'g'
        winname[2] = '\\';      //  was 'l'
        winname[3] = '?';       //  was 'o'
        winname[4] = '?';       //  was 'b'
        ret = &winname[2];
    }

    return ret;
}

int __cdecl open(const char * fname, int mode, ...)
{
    UNICODE_STRING us;
    ANSI_STRING as;
    ULONG AccessMode = SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    ULONG Disposition = 0;
    NTSTATUS Status;
    HANDLE hFile;
    char WinName[1024];
    char *pWinName;

    pWinName = __psxname_to_winname (fname, WinName, sizeof(WinName)-1);

    printf ("_winname = %s\n", pWinName);

    RtlInitAnsiString (&as, pWinName);
    Status = RtlAnsiStringToUnicodeString (&us, &as, TRUE);

    if (NT_SUCCESS(Status))
    {
        if (mode == O_RDONLY)
        {
            printf ("GENERIC_READ ");
            AccessMode |= GENERIC_READ;
        }

        if (mode & O_WRONLY)
        {
            printf ("GENERIC_WRITE ");
            AccessMode |= GENERIC_WRITE;
        }

        if (mode & O_RDWR)
        {
            printf("GENERIC_READ|GENERIC_WRITE ");
            AccessMode |= GENERIC_READ|GENERIC_WRITE;
        }

        Disposition = FILE_OPEN_IF;

        if (mode & O_CREAT)
        {
            printf("FILE_CREATE ");
            Disposition = FILE_CREATE;
        }

        if (mode & O_TRUNC)
        {
            if (mode & O_CREAT)
            {
                printf("FILE_OVERWRITE ");
                Disposition = FILE_OVERWRITE;
            }
            else
            {
                printf("FILE_OVERWRITE_IF ");
                Disposition = FILE_OVERWRITE_IF;
            }
        }

        hFile = CreateFile (
            us.Buffer, 
            AccessMode,
            FILE_SHARE_READ | FILE_SHARE_WRITE, 
            Disposition,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL
            );

        RtlFreeUnicodeString (&us);

        if (hFile == NULL)
        {
            return -1;
        }

        return (int)hFile;
    }

    return -1;
}

int __cdecl pipe(int *, unsigned int, int);

int __cdecl read(int fd, void *buffer, unsigned int length)
{
    return ReadFile (psx_translate_handle(fd), buffer, length, -1);
}

int __cdecl write(int fd, const void *buffer, unsigned int length)
{
    HANDLE hFile = psx_translate_handle(fd);
    if (hFile == STD_OUTPUT)
    {
        return console_write (buffer, length);
    }

    return WriteFile (hFile, buffer, length, -1);
}

int __cdecl remove(const char *);
int __cdecl rename(const char *, const char *);
int __cdecl setmode(int, int);
int __cdecl sopen(const char *, int, int, ...);
long __cdecl tell(int);
int __cdecl umask(int);
int __cdecl unlink(const char *);
