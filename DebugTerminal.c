#include <stdio.h>
#include "include/DebugTerminal.h"

void PrintError(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    printf(RED);
    vprintf(fmt, args);
    printf(RESET);

    va_end(args);
}

void PrintInfo(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    printf(YELLOW);
    vprintf(fmt, args);
    printf(RESET);

    va_end(args);
}