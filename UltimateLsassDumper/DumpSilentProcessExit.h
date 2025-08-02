/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpSilentProcessExit.h                                                             *
*  Purpose:      Performs lsass.exe dumping with the SilentProcessExit feature.                      *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPSILENTPROCESSEXIT_DumpToDisk                                                    *
*  Purpose:      Performs lsass.exe dumping with the SilentProcessExit feature.                      *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPSILENTPROCESSEXIT_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
