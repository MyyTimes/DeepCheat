#include <stdio.h>
#include "include/DebugTerminal.h"

void PrintError(const char *message)
{
    printf(RED "%s" RESET, message);
}