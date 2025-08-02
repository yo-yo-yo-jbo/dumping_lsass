/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpWholeMem.h                                                                      *
*  Purpose:      Performs full dumping of lsass.exe RW memory.                                       *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPWHOLEMEM_DumpToBuffer                                                           *
*  Purpose:      Performs an lsass.exe whole RW memory dump to buffer.                               *
*  Parameters:   - cbInput - not referenced.                                                         *
*                - pcInput - not referenced.                                                         *
*                - pcbOutput - buffer size.                                                          *
*                - ppcOutput - pointer to a buffer with a process dump content.                      *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPWHOLEMEM_DumpToBuffer(
    __in DWORD cbInput,
    __in_bcount(cbInput) __notnull PBYTE pcInput,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPWHOLEMEM_DumpToDisk                                                             *
*  Purpose:      Performs an lsass.exe whole RW memory dump to disk.                                 *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPWHOLEMEM_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);

