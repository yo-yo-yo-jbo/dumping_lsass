/****************************************************************************************************
*                                                                                                   *
*  File:         Auxiliary.h                                                                        *
*  Purpose:      Auxiliary functionality.                                                           *
*                                                                                                   *
*****************************************************************************************************/
#pragma once
#include <Windows.h>
#include <stdio.h>
#include <sal.h>

/****************************************************************************************************
*                                                                                                   *
*  Macro:        DEBUG_MSG                                                                          *
*  Purpose:      Creates a debug message.                                                           *
*  Parameters:   - pwszFmt - the format string for the debug message.                               *
*                - ... - arguments for the format string message.                                   *
*                                                                                                   *
*****************************************************************************************************/
#ifdef _DEBUG
#define DEBUG_MSG(pwszFmt, ...)      (VOID)wprintf(L"%S: " pwszFmt L"\n", __FUNCTION__, __VA_ARGS__)
#else
#define DEBUG_MSG(pwszFmt, ...)
#endif

/****************************************************************************************************
*                                                                                                   *
*  Macro:        DEBUG_ASSERT                                                                       *
*  Purpose:      Asserts a runtime condition.                                                       *
*  Parameters:   - cond - the condition.                                                            *
*                                                                                                   *
*****************************************************************************************************/
#ifdef _DEBUG
#define DEBUG_ASSERT(cond)          do                                                          \
                                    {                                                           \
                                        if (!(cond))                                            \
                                        {                                                       \
                                            DebugBreak();                                       \
                                        }                                                       \
                                    } while (FALSE)
#else
#define DEBUG_ASSERT(cond)
#endif

/*****************************************************************************************************
*                                                                                                    *
*  Macro:        COMPILE_TIME_ASSERT                                                                 *
*  Purpose:      Asserts a static condition.                                                         *
*  Parameters:   - cond - the condition.                                                             *
*                                                                                                    *
******************************************************************************************************/
#define COMPILE_TIME_ASSERT(cond)   do                                                          \
                                    {                                                           \
                                        enum { DUMMY = 1/(!!(cond)) };                          \
                                    } while (FALSE)

/****************************************************************************************************
*                                                                                                   *
*  Type:         RETSTATUS                                                                          *
*  Purpose:      Represents a common return status type.                                            *
*                                                                                                   *
*****************************************************************************************************/
typedef LONG RETSTATUS;

/****************************************************************************************************
*                                                                                                   *
*  Macro:        RETSTATUS_FAILED                                                                   *
*  Purpose:      Indicates whether the given status is a failure status or not.                     *
*  Parameters:   - eStatus - the status.                                                            *
*  Returns:      A boolean value indicating the result.                                             *
*                                                                                                   *
*****************************************************************************************************/
#define RETSTATUS_FAILED(eStatus)                       (0 > (eStatus))

/****************************************************************************************************
*                                                                                                   *
*  Macro:        RETSTATUS_SUCCEEDED                                                                *
*  Purpose:      Indicates whether the given status is a success status or not.                     *
*  Parameters:   - status - the status.                                                             *
*  Returns:      A boolean value indicating the result.                                             *
*                                                                                                   *
*****************************************************************************************************/
#define RETSTATUS_SUCCEEDED(eStatus)                    (!(RETSTATUS_FAILED(eStatus)))

/****************************************************************************************************
*                                                                                                   *
*  Constant:     RETSTATUS_UNEXPECTED                                                               *
*  Purpose:      Represents an unexpected return status.                                            *
*                                                                                                   *
*****************************************************************************************************/
#define RETSTATUS_UNEXPECTED ((RETSTATUS)(INT_MIN))

/****************************************************************************************************
*                                                                                                   *
*  Constant:     RETSTATUS_SUCCESS                                                                  *
*  Purpose:      Represents a successful return status.                                             *
*                                                                                                   *
*****************************************************************************************************/
#define RETSTATUS_SUCCESS ((RETSTATUS)0)

/****************************************************************************************************
*                                                                                                   *
*  Macro:        RETSTATUS_FAILURE_MSG                                                              *
*  Purpose:      Returns a failure message and outputs a debug string.                              *
*  Parameters:   - fmt - the format string.                                                         *
*                - <ellipsis> - the parameters for the format string.                               *
*  Returns:      An error status unique to the current file.                                        *
*                                                                                                   *
*****************************************************************************************************/
#define RETSTATUS_FAILURE_MSG(pwszFmt, ...)                -__LINE__; DEBUG_MSG(pwszFmt, __VA_ARGS__)

/****************************************************************************************************
*                                                                                                   *
*  Macro:        CLOSE_HANDLE                                                                       *
*  Purpose:      Closes a handle safely.                                                            *
*  Parameters:   - hObject - the handle to the object.                                              *
*                                                                                                   *
*****************************************************************************************************/
#define CLOSE_HANDLE(hObject)        do                                                         \
                                     {                                                          \
                                          if (NULL != (hObject))                                \
                                          {                                                     \
                                              (VOID)CloseHandle(hObject);                       \
                                              (hObject) = NULL;                                 \
                                          }                                                     \
                                     } while (FALSE)

/****************************************************************************************************
*                                                                                                   *
*  Macro:        CLOSE_REG_KEY                                                                      *
*  Purpose:      Closes a registry key handle safely.                                               *
*  Parameters:   - hKey - the key handle.                                                           *
*                                                                                                   *
*****************************************************************************************************/
#define CLOSE_REG_KEY(hKey)          do                                                         \
                                     {                                                          \
                                          if (NULL != (hKey))                                   \
                                          {                                                     \
                                              (VOID)RegCloseKey(hKey);                          \
                                              (hKey) = NULL;                                    \
                                          }                                                     \
                                     } while (FALSE)


/****************************************************************************************************
*                                                                                                   *
* Macro:        CLOSE_FILE_FIND                                                                     *
* Purpose:      Closes a find handle safely.                                                        *
* Parameters:   - hFind - the find handle.                                                          *
*                                                                                                   *
*****************************************************************************************************/
#define CLOSE_FILE_FIND(hFind)       do                                                         \
                                     {                                                          \
                                          if (INVALID_HANDLE_VALUE != (hFind))                  \
                                          {                                                     \
                                              (VOID)FindClose(hFind);                           \
                                              (hFind) = INVALID_HANDLE_VALUE;                   \
                                          }                                                     \
                                     } while (FALSE)

/****************************************************************************************************
*                                                                                                   *
*  Macro:        CLOSE_SERVICE_HANDLE                                                               *
*  Purpose:      Closes a service handle safely.                                                    *
*  Parameters:   - hSvc - the service handle.                                                       *
*                                                                                                   *
*****************************************************************************************************/
#define CLOSE_SERVICE_HANDLE(hSvc)   do                                                         \
                                     {                                                          \
                                          if (NULL != (hSvc))                                   \
                                          {                                                     \
                                              (VOID)CloseServiceHandle(hSvc);                   \
                                              (hSvc) = NULL;                                    \
                                          }                                                     \
                                     } while (FALSE)

/*****************************************************************************************************
*                                                                                                    *
*  Macro:        UNMAP_VIEW_OF_FILE                                                                  *
*  Purpose:      Closes a view of file mapping safely.                                               *
*  Parameters:   - pvMem - the mapping to close.                                                     *
*  Remarks:      - Unmap a view BEFORE closing the file mapping handle itself.                       *
*                                                                                                    *
******************************************************************************************************/
#define UNMAP_VIEW_OF_FILE(pvMem)    do                                                         \
                                     {                                                          \
                                          if (NULL != (pvMem))                                  \
                                          {                                                     \
                                              (VOID)UnmapViewOfFile(pvMem);                     \
                                              (pvMem) = NULL;                                   \
                                          }                                                     \
                                     } while (FALSE)


/****************************************************************************************************
*                                                                                                   *
*  Macro:        CLOSE_FILE_HANDLE                                                                  *
*  Purpose:      Closes a file handle safely.                                                       *
*  Parameters:   - hFile - the file handle.                                                         *
*                                                                                                   *
*****************************************************************************************************/
#define CLOSE_FILE_HANDLE(hFile)     do                                                         \
                                     {                                                          \
                                          if (INVALID_HANDLE_VALUE != (hFile))                  \
                                          {                                                     \
                                              __pragma(warning(push))                           \
                                              __pragma(warning(disable:6387))                   \
                                              (VOID)CloseHandle(hFile);                         \
                                              __pragma(warning(pop))                            \
                                              (hFile) = INVALID_HANDLE_VALUE;                   \
                                          }                                                     \
                                     } while (FALSE)

/****************************************************************************************************
*                                                                                                   *
*  Macro:        HEAPFREE                                                                           *
*  Purpose:      Frees a previously allocated buffer.                                               *
*  Parameters:   - pvMem - the memory variable.                                                     *
*                                                                                                   *
*****************************************************************************************************/
#define HEAPFREE(pvMem)              do                                                         \
                                     {                                                          \
                                          if (NULL != (pvMem))                                  \
                                          {                                                     \
                                              (VOID)HeapFree(GetProcessHeap(), 0, (pvMem));     \
                                              (pvMem) = NULL;                                   \
                                          }                                                     \
                                     } while (FALSE)

/****************************************************************************************************
*                                                                                                   *
*  Macro:        HEAPALLOCZ                                                                         *
*  Purpose:      Allocates a buffer and zeros its memory.                                           *
*  Parameters:   - cbBytes - the memory size in bytes.                                              *
*  Returns:      The new allocated buffer upon success, NULL upon failure.                          *
*                                                                                                   *
*****************************************************************************************************/
#define HEAPALLOCZ(cbBytes)          (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cbBytes)))
 

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    STATUS_UNSUCCESSFUL                                                                  *
*  Purpose:     A generic unsuccessful NTSTATUS.                                                     *
*  Remarks:     - Done here to avoid including ntstatus.h which includes many type redefinitions.    *
*                                                                                                    *
******************************************************************************************************/
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

/*****************************************************************************************************
*                                                                                                    *
*  Macro:        NT_SUCCESS                                                                          *
*  Purpose:      Indicates whether an NTSTATUS is successful or not.                                 *
*  Parameters:   - eStatus - the status.                                                             *
*  Returns:      TRUE on success, FALSE otherwise.                                                   *
*  Remarks:      - Taken from ntdef.h to avoid include circular dependencies.                        *
*                                                                                                    *
******************************************************************************************************/
#ifndef NT_SUCCESS
#define NT_SUCCESS(eStatus) (((NTSTATUS)(eStatus)) >= 0)
#endif