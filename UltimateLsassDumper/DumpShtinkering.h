/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpShtinkering.h                                                                   *
*  Purpose:      Performs an lsass.exe Shtinkering (by abusing WER).                                 *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPSHTINKERING_DumpToDisk                                                          *
*  Purpose:      Performs an lsass.exe Shtinkering dump to disk.                                     *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPSHTINKERING_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
