/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpComsvcs.h                                                                       *
*  Purpose:      Performs lsass.exe dumping with comsvcs.dll and rundll32.exe.                       *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPCOMSVCS_DumpToDisk                                                              *
*  Purpose:      Performs an lsass.exe dumping with comsvcs.dll and rundll32.exe.                    *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPCOMSVCS_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
