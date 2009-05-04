#define _CRTIMP
#include "ntwrappr.h"
#include <stdio.h>
#include <stdarg.h>

/*
int _cdecl printf (const char *format, ...)
{
    char buffer[1024];
    int s;
    va_list va;
    va_start (va, format);

    s = _vsnprintf (buffer, sizeof(buffer)-1, format, va);
    return (int) Print (buffer);
}
*/