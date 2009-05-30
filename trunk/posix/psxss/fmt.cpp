#define _CRTIMP
#include "ntwrappr.h"
#include <fcntl.h>
#define _POSIX_
#include <stdio.h>
#undef _POSIX_
#include <stdarg.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>

FILE _iob[_IOB_ENTRIES];

#define _IO_READ    _IOREAD
#define _IO_WRITE   _IOWRT
#define _IO_APPEND  0x0200
#define _IO_BINARY  0x1000
#define _IO_PLUS    0x2000
#define _IO_EOF     _IOEOF
#define _IO_ERR     _IOERR

static int _cdecl mode_to_flags (const char* mode)
{
    int flag = 0;

    for (const char *sp = mode; *sp; sp++)
    {
        switch (*sp)
        {
        case 'r':
            flag |= _IO_READ;
            break;

        case 'w':
            flag |= _IO_WRITE;
            break;

        case 'a':
            flag |= _IO_APPEND;
            break;

        case '+':
            flag |= _IO_PLUS;
            break;

        case 't':
            flag &= ~_IO_BINARY;
            break;

        case 'b':
            flag |= _IO_BINARY;
            break;
        }
    }

    return flag;
}

static int _cdecl translate_mode (FILE *fp, const char *mode)
{
    int m = 0;
    int flag = mode_to_flags (mode);

    if (flag & _IO_WRITE)
    {
        if (flag & _IO_READ)
        {
            m = O_RDWR;
        }
        else
        {
            m = O_WRONLY;
        }
    }
    else if (flag & _IO_READ)
    {
        m = O_RDONLY;
    }

    if (flag & _IO_BINARY)
    {
        m |= O_BINARY;
    }

    fp->_flag = flag;

    return m;
}

static int _cdecl translate_st_mode (FILE *fp, const char *mode)
{
    int m = 0;
    int flag = mode_to_flags (mode);

    if (flag & _IO_WRITE)
    {
        m |= _S_IWRITE;
    }
    
    if (flag & _IO_READ)
    {
        m |= _S_IREAD;
    }

    fp->_flag = flag;

    return m;
}

static int _cdecl is_mode_allowed (int requested, int st)
{
    if (requested & _S_IREAD)
    {
        if (!(st & _S_IREAD))
            return 0;
    }

    if (requested & _S_IWRITE)
    {
        if(!(st & _S_IWRITE))
            return 0;
    }

    return 1;
}

FILE* _cdecl fopen (const char *fname, const char *mode)
{
    FILE *fp = (FILE*) halloc (sizeof(FILE));
    if (fp)
    {
        memset (fp, 0, sizeof(FILE));

        int m = translate_mode (fp, mode);
        fp->_file = open (fname, m);

        if (fp->_file == -1)
        {
            hfree(fp);
            return NULL;
        }
    }

    return fp;
}

FILE * __cdecl fdopen(int fd, const char *mode)
{
    /*
    FILE *fp = (FILE*) halloc (sizeof(FILE));
    if (fp)
    {
        memset (fp, 0, sizeof(FILE));

        int m = translate_st_mode (fp, mode);
        
        struct stat s;
        if (fstat (fd, &s) == -1 ||
            !is_mode_allowed(m, s.st_mode))
        {
            hfree(fp);
            return NULL;
        }
    }

    return fp;
    */

    return NULL;
}

int _cdecl fclose (FILE *fp)
{
    int res = close(fp->_file);
    hfree(fp);
    return res;
}

size_t _cdecl fread (void *buffer, size_t size, size_t count, FILE* fp)
{
    size_t length = size*count;
    if (!length)
        return 0;

    PUCHAR pItem = (PUCHAR) buffer;
    size_t i;

    for (i=0; i<count; i++)
    {
        void *buf = pItem + size*i;
        size_t bytes;

        bytes = read (fp->_file, buf, size);
        if (bytes == -1)
        {
            fp->_flag |= _IO_ERR;
            break;
        }
        else if (bytes < size)
        {
            fp->_flag |= _IO_EOF;
            break;
        }
    }

    return i;
}

size_t _cdecl fwrite (const void *buffer, size_t size, size_t count, FILE* fp)
{
    size_t length = size*count;
    if (!length)
        return 0;

    PUCHAR pItem = (PUCHAR) buffer;
    size_t i;

    for (i=0; i<count; i++)
    {
        void *buf = pItem + size*i;
        size_t bytes;

        bytes = write (fp->_file, buf, size);
        if (bytes == -1)
        {
            fp->_flag |= _IO_ERR;
            break;
        }
    }

    return i;
}

int __cdecl fileno(FILE *fp)
{
    return fp->_file;
}
