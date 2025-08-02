/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpMiniDump.h                                                                      *
*  Purpose:      Performs mini dumping of lsass.exe.                                                 *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_PerformMiniDumpToDisk                                                  *
*  Purpose:      Performs an lsass.exe dump with MiniDumpWriteDump using a given handle to disk.     *
*  Parameters:   - hHandle - the handle to either lsass.exe or a snapshot.                           *
*                - bIsProcessHandle - whether the handle is a process handle or a snapshot.          *
*                - dwLsassPid - the lsass.exe process ID.                                            *
*                - pwszDumpPath - the dump file path, supports environment variables.                *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_PerformMiniDumpToDisk(
    __in __notnull HANDLE hHandle,
    __in BOOL bIsProcessHandle,
    __in DWORD dwLsassPid,
    __in __notnull PWSTR pwszDumpPath
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_PerformMiniDumpToBuffer                                                *
*  Purpose:      Performs an lsass.exe dump with MiniDumpWriteDump using a given handle to a buffer. *
*  Parameters:   - hHandle - the handle to either lsass.exe or a snapshot.                           *
*                - bIsProcessHandle - whether the handle is a process handle or a snapshot.          *
*                - dwLsassPid - the lsass.exe process ID.                                            *
*                - pcbOutput - gets the number of bytes in the buffer upon success.                  *
*                - ppcOutput - gets the buffer contents upon success.                                *
*  Returns:      A return status.                                                                    *
*  Remarks:      - Free the returned buffer with HeapFree on the current process heap.               *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_PerformMiniDumpToBuffer(
    __in __notnull HANDLE hHandle,
    __in BOOL bIsProcessHandle,
    __in DWORD dwLsassPid,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_MiniDumpToBuffer                                                       *
*  Purpose:      Performs an lsass.exe dump with MiniDumpWriteDump with a callback function.         *
*  Parameters:   - cbInput - not referenced.                                                         *
*                - pcInput - not referenced.                                                         *
*                - pcbOutput - buffer size.                                                          *
*                - ppcOutput - pointer to a buffer with a process dump content.                      *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_MiniDumpToBuffer(
    __in DWORD cbInput,
    __in_bcount(cbInput) __notnull PBYTE pcInput,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_MiniDumpToDisk                                                         *
*  Purpose:      Performs an lsass.exe dump with MiniDumpWriteDump.                                  *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_MiniDumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
