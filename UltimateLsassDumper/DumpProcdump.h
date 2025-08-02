/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpProcdump.h                                                                      *
*  Purpose:      Performs lsass.exe dumping using a given external procdump.exe (Sysinternals).      *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPPROCDUMP_DumpToDisk                                                             *
*  Purpose:      Performs an lsass.exe dumping using a given external procdump.exe (SysInternals).   *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPPROCDUMP_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
