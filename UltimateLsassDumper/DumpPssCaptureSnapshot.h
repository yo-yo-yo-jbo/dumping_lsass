/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpPssCaptureSnapshot.h                                                            *
*  Purpose:      Performs dumping of lsass.exe memory with the PssCaptureSnapshot API.               *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPPSSCAPTURESNAPSHOT_DumpToBuffer                                                 *
*  Purpose:      Performs an lsass.exe dump with the PssCaptureSnapshot API to a buffer.             *
*  Parameters:   - cbInput - not referenced.                                                         *
*                - pcInput - not referenced.                                                         *
*                - pcbOutput - buffer size.                                                          *
*                - ppcOutput - pointer to a buffer with a process dump content.                      *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPPSSCAPTURESNAPSHOT_DumpToBuffer(
    __in DWORD cbInput,
    __in_bcount(cbInput) __notnull PBYTE pcInput,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPPSSCAPTURESNAPSHOT_DumpToDisk                                                   *
*  Purpose:      Performs an lsass.exe dump with the PssCaptureSnapshot API to the disk.             *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPPSSCAPTURESNAPSHOT_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
