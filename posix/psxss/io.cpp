#define _CRTIMP
#include "ntwrappr.h"
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>


int __cdecl access(const char *, int);
int __cdecl chmod(const char *, int);
int __cdecl chsize(int, long);

int __cdecl close(int fd)
{
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

char* __psxname_to_winname (const char *psxname, char *winname, int maxwinname)
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
    ULONG AccessMode = 0;
    ULONG Disposition = 0;
    NTSTATUS Status;
    HANDLE hFile;
    char WinName[1024];
    char *pWinName;

    pWinName = __psxname_to_winname (fname, WinName, sizeof(WinName)-1);

    Print ("_winname = %s\n", pWinName);

    RtlInitAnsiString (&as, pWinName);
    Status = RtlAnsiStringToUnicodeString (&us, &as, TRUE);

    if (NT_SUCCESS(Status))
    {
        if (mode & O_RDONLY)
            AccessMode |= GENERIC_READ;

        if (mode & O_WRONLY)
            AccessMode |= GENERIC_WRITE;

        if (mode & O_RDWR)
            AccessMode |= GENERIC_READ|GENERIC_WRITE;

        Disposition = FILE_OPEN_IF;

        if (mode & O_CREAT)
            Disposition = FILE_CREATE;

        if (mode & O_TRUNC)
        {
            if (mode & O_CREAT)
                Disposition = FILE_OVERWRITE;
            else
                Disposition = FILE_OVERWRITE_IF;
        }

        hFile = CreateFile (
            us.Buffer, 
            AccessMode,
            FILE_SHARE_READ | FILE_SHARE_WRITE, 
            Disposition,
            FILE_NON_DIRECTORY_FILE,
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
    return ReadFile ((HANDLE)fd, buffer, length, -1);
}

int __cdecl remove(const char *);
int __cdecl rename(const char *, const char *);
int __cdecl setmode(int, int);
int __cdecl sopen(const char *, int, int, ...);
long __cdecl tell(int);
int __cdecl umask(int);
int __cdecl unlink(const char *);
int __cdecl write(int, const void *, unsigned int);
