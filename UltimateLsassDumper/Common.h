/*****************************************************************************************************
*                                                                                                    *
*  File:         Common.h                                                                            *
*  Purpose:      Common functionality.                                                               *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Enum:         ARG_INDEX                                                                           *
*  Purpose:      Describes argument indices for argv-style function prototypes.                      *
*                                                                                                    *
******************************************************************************************************/
typedef enum
{
    ARG_INDEX_DUMP_PATH = 0,
    ARG_INDEX_LSASS_HANDLE_FETCH_TYPE = 1,
    ARG_INDEX_UTILITY_PATH = 2,
    // Must be last
    ARG_INDEX_MAX
} ARG_INDEX;

/*****************************************************************************************************
*                                                                                                    *
*  Enum:         LSASS_HANDLE_FETCH_TYPE                                                             *
*  Purpose:      The type of lsass.exe handle fetch.                                                 *
*                                                                                                    *
******************************************************************************************************/
typedef enum
{
    LSASS_HANDLE_FETCH_TYPE_INVALID = 0,
    LSASS_HANDLE_FETCH_TYPE_DIRECT = 1,
    LSASS_HANDLE_FETCH_TYPE_DUPLICATE,
    // Must be last
    LSASS_HANDLE_FETCH_TYPE_MAX
} LSASS_HANDLE_FETCH_TYPE;

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     OUTPUT_BUFFER_INITIAL_SIZE                                                          *
*  Purpose:      Contains an initial size of an output buffer to be returned to the user, in bytes.  *
*                                                                                                    *
******************************************************************************************************/
#define OUTPUT_BUFFER_INITIAL_SIZE (10 * 1024 * 1024)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_RunProcess                                                                   *
*  Purpose:      Runs the given command-line.                                                        *
*  Parameters:  - pwszCommandLine - the command line to run.                                         *
*               - bHideWindow - whether to hide the window or not.                                   *
*               - bWaitForProcess - whether to wait for the process to exit or not.                  *
*               - phProcess - optionally gets the process handle.                                    *
*               - pdwPid - optionally gets the process ID.                                           *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Free the returning process handle with CloseHandle.                                *
*               - Check the process exit code with the returning process handle.                     *
*               - If phProcess is NULL, the process handle is automatically closed.                  *
*               - Don't forget to wrap paths in quotes to avoid commandline related security issues. *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_RunProcess(
    __in __notnull PWSTR pwszCommandLine,
    __in BOOL bHideWindow,
    __in BOOL bWaitForProcess,
    __out_opt PHANDLE phProcess,
    __out_opt PDWORD pdwPid
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_TouchFile                                                                    *
*  Purpose:      Creates a new file with 0 bytes, similarly to the POSIX "touch" command.            *
*  Parameters:  - pwszPath - the file path.                                                          *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_TouchFile(
    __in __notnull PWSTR pwszPath
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_ResolveProcAddress                                                           *
*  Purpose:      Resolves a procedure from the given module name.                                    *
*  Parameters:  - pwszModuleName - the module name.                                                  *
*               - pszProcName - the procedure name.                                                  *
*               - ppfnProc - gets the procedure address upon success.                                *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Not thread-safe.                                                                   *
*               - If the library is not found - this function will atempt to load it.                *
*                                                                                                    *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_ResolveProcAddress(
    __in __notnull PWSTR pwszModuleName,
    __in __notnull PSTR pszProcName,
    __out FARPROC* ppfnProc
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_ResolveProcAddresses                                                         *
*  Purpose:      Resolves multiple procedures from the given module name.                            *
*  Parameters:  - pwszModuleName - the module name.                                                  *
*               - ppszProcNames - the procedure names.                                               *
*               - pppfnProcs - gets the procedure addresses upon success.                            *
*               - nProcs - the number of procedure names to resolve.                                 *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Not thread-safe.                                                                   *
*               - If the library is not found - this function will atempt to load it.                *
*               - Note the returned procedures might be written with NULLs in case of failure.       *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_ResolveProcAddresses(
    __in __notnull PWSTR pwszModuleName,
    __in_ecount(nProcs) __notnull PSTR* ppszProcNames,
    __out_ecount(nProcs) FARPROC** pppfnProcs,
    __in SIZE_T nProcs
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_SetDebugPrivilege                                                            *
*  Purpose:      Sets debug privileges for it's own process.                                         *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_SetDebugPrivilege(VOID);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetDirectoryFromFullPath                                                     *
*  Purpose:      Gets a directory from a full path (without the last separator).                     *
*  Parameters:  - pwszFullPath - the full path.                                                      *
*               - pwszDirectoryPath - gets the directory path.                                       *
*               - cchDirectoryPath - indicates how many characters the directory path can hold.      *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetDirectoryFromFullPath(
    __in __notnull PWSTR pwszFullPath,
    __out_ecount(cchDirectoryPath) PWSTR pwszDirectoryPath,
    __in SIZE_T cchDirectoryPath
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetRunningServicePid                                                         *
*  Purpose:      Gets an existing running service process ID.                                        *
*  Parameters:  - pdwPid - gets the process ID upon succes.                                          *
*               - pwszServiceName - the service name.                                                *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetRunningServicePid(
    __out PDWORD pdwPid,
    __in __notnull PWSTR pwszServiceName
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetFirstThreadOfProcess                                                      *
*  Purpose:      Gets the first thread of the given  process ID.                                     *
*  Parameters:  - pdwThreadId - gets the thread ID upon succes.                                      *
*               - dwPid - the process ID.                                                            *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetFirstThreadOfProcess(
    __out PDWORD pdwThreadId,
    __in DWORD dwPid
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_IsLocalSystem                                                                *
*  Purpose:      Indicates whether we're running a local system.                                     *
*  Parameters:  - pbIsLocalSystem - indicates whether we're running as the local system.             *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_IsLocalSystem(
    __out PBOOL pbIsLocalSystem
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_FindLsassPid                                                                 *
*  Purpose:      Finds the process ID of lsass.exe.                                                  *
*  Parameters:   - pdwPid - gets the PID upon success.                                               *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_FindLsassPid(
    __out PDWORD pdwPid
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_FetchLsassHandleFromString                                                   *
*  Purpose:      Fetches the lsass.exe handle based on the string fetch type.                        *
*  Parameters:  - pwszLsassHandleFetchType - the fetch type as a string.                             *
*               - phLsassProcess - gets the process handle to lsass.exe upon success.                *
*               - pdwPid - gets the PID upon success. Optional.                                      *
*               - dwDesiredAccess - the desired access for the handle.                               *
*               - bInheritHandles - whether to allow handle inheritence or not.                      *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Free the returning process handle with CloseHandle.                                *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_FetchLsassHandleFromString(
    __in __notnull PWSTR pwszLsassHandleFetchType,
    __out PHANDLE phLsassProcess,
    __out_opt PDWORD pdwPid,
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandles
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_FetchLsassHandle                                                             *
*  Purpose:      Fetches the lsass.exe handle based on the fetch type.                               *
*  Parameters:  - eLsassFetchType - the fetch type.                                                  *
*               - phLsassProcess - gets the process handle to lsass.exe upon success.                *
*               - pdwPid - gets the PID upon success. Optional.                                      *
*               - dwDesiredAccess - the desired access for the handle.                               *
*               - bInheritHandles - whether to allow handle inheritence or not.                      *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Free the returning process handle with CloseHandle.                                *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_FetchLsassHandle(
    __in LSASS_HANDLE_FETCH_TYPE eLsassFetchType,
    __out PHANDLE phLsassProcess,
    __out_opt PDWORD pdwPid,
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandles
);


/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetLsassHandleFetchTypeFromBinaryInput                                       *
*  Purpose:      Gets the lsass.exe handle the fetch type from a binary buffer input.                *
*  Parameters:  - cbBuffer - the buffer's size in bytes.                                             *
*               - pcBuffer - the buffer's bytes.                                                     *
*               - peLsassHandleFetchType - gets the fetch type upon success.                         *
*               - dwDesiredAccess - the desired access for the handle.                               *
*  Returns:      TRUE upon success, FALSE otherwise.                                                 *
*  Remarks:     - Use this function as parsing methodology for buffer-based function prototypes.     *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetLsassHandleFetchTypeFromBinaryInput(
    __in SIZE_T cbBuffer,
    __in_bcount(cbBuffer) __notnull PBYTE pcBuffer,
    __out LSASS_HANDLE_FETCH_TYPE* peLsassHandleFetchType
);
