/*****************************************************************************************************
*                                                                                                    *
*  File:         DumpTaskManager.h                                                                   *
*  Purpose:      Performs memory dumping of lsass.exe using the Task Manager.                        *
*                                                                                                    *
******************************************************************************************************/
#pragma once
#include "Auxiliary.h"

/*****************************************************************************************************
*                                                                                                    *
*  Function:     DUMPTASKMANAGER_DumpToDisk                                                          *
*  Purpose:      Performs an lsass.exe dump with the Task Manager.                                   *
*  Parameters:   - nArgs - the number of arguments.                                                  *
*                - ppwszArgs - arguments - expects only one argument to specify the dump path.       *
*  Returns:      A return status.                                                                    *
*                                                                                                    *
******************************************************************************************************/
__success(return >= 0)
RETSTATUS
DUMPTASKMANAGER_DumpToDisk(
    __in DWORD nArgs,
    __in_ecount(nArgs) __notnull PWSTR* ppwszArgs
);
