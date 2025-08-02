/*****************************************************************************************************
*                                                                                                    *
*  File:         DllMain.c                                                                           *
*  Purpose:      Main DLL entry point functionality.                                                 *
*                                                                                                    *
******************************************************************************************************/
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DllMain                                                                             *
*  Purpose:      Main DLL function.                                                                  *
*  Parameters:   - hInstance - the instance.                                                         *
*                - dwReason - reason for the function to be called.                                  *
*                - pvReserved - ignored.                                                             *
*  Returns:      TRUE, always.                                                                       *
*                                                                                                    *
******************************************************************************************************/
BOOL
WINAPI
DllMain(
    HINSTANCE hInstance,
    DWORD dwReason,
    LPVOID pvReserved
)
{
    // Unreferenced
    UNREFERENCED_PARAMETER(pvReserved);

    // Create thread upon attaching
    if (DLL_PROCESS_ATTACH == dwReason)
    {
        // Indicate no further DllMain invocations should be done
        (VOID)DisableThreadLibraryCalls(hInstance);
    }

    // Indicate success
    return TRUE;
}
