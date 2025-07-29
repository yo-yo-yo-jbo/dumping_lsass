# Different ways of dumping lsass
As part of my "coming back to Windows security" phase, I've decided to write a short blogpost about the significance and methodology of dumping lsass.  
While these are not novel techniques, I think summarizing ideas here would make sense, especially if you're stuck at 2-3 methods that are all monitored.

## What is lsass?
The `Local Security Authority Subsystem Service (LSASS)` is a critical Windows process (`lsass.exe`) responsible for enforcing the system's security policy.  
It handles authentication, password changes, user logins, token creation, and more, runs as SYSTEM and is tightly integrated into Windows’ trust model.  
In `lsass.exe` memory, you can find authentication credentials for users who have logged into the system.  
Those includes NTLM hashes, Kerberos tickets (TGTs, service tickets), and plaintext credentials (in some cases).  
That makes `lsass` act as a treasure trove for lateral movement and privilege escalation.  
Stealing credentials from LSASS allows attackers to:
- Perform `pass-the-hash (PtH)` or `pass-the-ticket (PtT)`.
- Access network resources without cracking passwords.
- Move laterally without triggering brute-force alarms.

## The basics of dumping lsass
There are a few mitigations against dumping lsass memory, but for now - let's discuss a vanilla OS with no mitigations in place.  
We will therefore decibe naive ways of dumping lsass.  
Generally speaking, dumping lsass requires two things:
1. Getting a process `HANDLE`, e.g. via a call to the [OpenProcess API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).
2. Reading the process memory.

In some cases, we might be "lazy" and use other utilities (mostly in the forms of executables or libraries) that'd do the work for us.

### Task manager dumping
While that is probably the least stelthy technique out there, it's quite effective.  
The Windows Task Manager (taskmgr.exe) is a GUI application that allows one to select a process and naively dump it:
![Dumping with task manager, courtesy of hawk-eye.io](taskmgr_dump.png)

The good thing here is that `taskmgr.exe` already runs on a target box ("living-off-the-land"), as well as doing everything for us - it opens a handle to `lsass.exe` and dumps its contents.  
The bad news is that it's a GUI application, but it could be automated:
1. Save the current foreground window for restoration.
2. Run `taskmgr.exe` and get its process ID (available from a call to [CreateProcessW API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).
3. Wait a bit and find the Task Manager window via the [FindWindowW API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindoww). Interestingly, it's quite easy to find since that Window has a class name "TaskManagerWindow".
4. Send keystrokes to the Task Manager window via the [SendInput API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput). We can inject the keystrokes that spell out "Local Security Authority", followed by the special "menu" keyboard input (`VK_APPS`), and then the letter "C", which will dump lsass.
5. Use the [EnumWindows API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows) to get the window that shows the filename of the dump file and fetch its contents. Fetching the contents themselves could be dona via the [SendMessageW API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagew) with the Windows Message `WM_GETTEXT`.
6. Kill `taskmgr.exe` and restore the foreground window from step #1.
7. Use the dump file and delete after use.

This might look similar to an [AutoHotkey](https://www.autohotkey.com) implementation - but this is very stitched to `lsass` dumping.

### Rundll-comsvcs-based minidump
Moving forward, the DLL `comsvcs.dll` exposes a `rundll32` interface for its `MiniDump` export.  
It's as simple as running a commandline:
```
"%WINDIR%\System32\rundll32.exe" "%WINDIR%\System32\comsvcs.dll" MiniDump [PID] [PATH] full
```

Where `PID` is the `lsass.exe` process ID and `PATH` is a placeholder for the dump path.  
One annoying thing I discovered was that you cannot quote the `PATH` placeholder, so it cannot contain spaces.  
This minor annoyance could be avoided by converting the path we want to a `Short Path` - via the [GetShortPathNameW API](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getshortpathnamew).

### Procdump
Another simple technique that requires a child process is using [ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) from the SysInternals suite.  
One can download it directly (from https://download.sysinternals.com/files/Procdump.zip) or dump and and run it.  
I mention procdump specifically because it's used by threat actors, as well as very prevalent.

### Minidump API
This technique mainly focuses on the [MiniDumpWriteDump API](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump).  
Up till this point, we used child processes, but now we're going to use our own code to perform `lsass.exe` dumping.  
To use the `MiniDumpWriteDump` API, we need a `HANDLE` to `lsass.exe`.  
Assuming we got such a handle, we do the following:
1. Create a new file and get its handle.
2. Invoke the [MiniDumpWriteDump API](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) on the `lsass.exe` handle and the file handle.

However, there is a variant that doesn't require writing to disk at all - we can save the entire dump to a memory buffer!  
To achieve that, we:
1. Create a buffer with some initial size.
2. Create a structure of type `MINIDUMP_CALLBACK_INFORMATION` and specify a callback function (and context).
3. Invoke the [MiniDumpWriteDump API](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) on the `lsass.exe` handle and the callback pointer.
4. The callback accumulates the data from the minidump argument upon receivng a `IoWriteAllCallback` callback type. Ths might require us to dynamically enlarge the buffer with the `HeapReAlloc` API.

Now, how do we get a handle to `lsass.exe` to begin with?  
There are two variants that we will consider for now:

#### Using OpenProcess
This is the most direct and "normal" way of fetching the `lsass.exe` process handle:
1. Finding the process ID of `lsass.exe` with [CreateToolhelp32Snapshot API](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), as well as [Process32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw) and [Process32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw) API calls.
2. Use the [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) API. For doing a Minidump, we will require the `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ` access flags.

#### Stealing an existing handle
Since `OpenProcess` is usually heavily monitored by security products, there is a sneakier option - duplicating an existing handle to `lsass.exe` some other process might have.  
Similarly to the `OpenProcess` approach - we fetch the `lsass.exe` PID the usual way (`CreateToolhelp32Snapshot` and friends).  
However, here our approach would be finding an existing handle to `lsass.exe` with sufficient access flags:
1. We call [ntdll!NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) with the information class `SystemHandleInformation` (defined as 16) with a sufficiently large buffer. As of now, that information class is officially undocumented (but can be found [here](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm)).
2. We treat the buffer as a [SYSTEM_HANDLE_INFORMATION](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm) pointer (again officially undocumented).
3. For each handle, we skip if it belongs to the `lsass.exe` process ID itself, to our own process or the SYSTEM process ID (4).
4. We call `ntdll!NtDuplicateObject` to duplicate the handle. In this call we also specify the required access flags.
5. We call `ntdll!NtQueryObject` with type `OBJECT_TYPE_INFORMATION_CLASS` to get the duplicated handle type and make sure it's a `process` handle type.
6. We call the [QueryFullProcessImageNameW API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew) and validate it's indeed `lsass.exe` (note it's a full name so extra parsing is required).
7. If all checks pass - we got a handle to `lsass.exe` that we've just duplicated! Otherwise, we clean up used resources and try a different handle.

Note a running OS is not guaranteed to have an open `lsass.exe` by some process with sufficient access flags - if that's the case we can always revert to running `OpenProcess` as usual.  
However, all the native APIs (and especially the handle duplication) make it way stealtier than calling `OpenProcess` directly.

### PssCaptureSnapshot-based dumping
Similarly to the Minidump approach, we get a handle to `lsass.exe` by means of `OpenProcess` or handle duplication, but this time also with `PROCESS_DUP_HANDLE` access flag.  
Then, we call the [PssCaptureSnapshot API](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot?redirectedfrom=MSDN) which returns us a pseudo-handle of type `HPSS`.  
As the name suggests, that handle captures a "snapshot" of the `lsass.exe` state (includng memory), and then could be used just like a normal handle to `ReadProcessMemory` or `MiniDumpWriteDump`.  
The approach doesn't seem advantageous, but it's very reliable due to how it captures a snapshot (as opposed to direct `ReadProcessMemory` which has an inherent race condition, for example).

### SilentProcessExit-based dumping
This technique relies on a Windows mechanism that can invoke a callback once a process exits, as well as fooling the system into thinking the process indeed exited.
To implement this technique, we do the following:
1. Get an `lsass.exe` handle (either via `OpenProcess` or by handle duplication).
2. Write to the registry under the [Image File Execution Options (IFEO)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/xperf/image-file-execution-options) key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe`. Value name is `GlobalFlag` which is of type `DWORD`, and we set it to the value of `0x200`, which corresponds to enabling the Silent Process Exit monitoring feature.
3. Write to the registry again, this time under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe`, the value is a `DWORD` with the name `ReportingMode` and the value of `2`, which instructs the OS to perform a full memory dump.
4. Set the value `LocalDumpFolder` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe` to point to a folder we'd like to dump the memory to, and set the value `DumpType` (which is a `DWORD`) to be `2` (local memory dump).
5. Call `ntdll!RtlReportSilentProcessExit`, which is an undocumented function that would report that a silent process exit should occur for a given process handle (`lsass.exe` in our case).

At that point, our dump file has been created at the folder we assigned, and we can delete all added registry entries.

### Whole memory dumping with ReadProcessMemory
This very simple technique basically reads all of `lsass.exe` memory via the [ReadProcessMemory API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory).  
To iterate all memory regions, one can use the [VirtualQueryEx API](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) and retrieve a region's size and protections.  
Most juicy stuff (credential material) will be in readable-writable (RW) regions, as it's allocated dynamically.

### Shtinikering
Originally done by [Deep Instinct](https://www.deepinstinct.com), this method requires running as `SYSTEM` (can be validated using the [GetTokenInformation API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) if necessary).  
Just as before, we fetch a handle to `lsass.exe` with either `OpenProcess` or duplication, and then dumps using [Windows Error Reporting (WER)](https://en.wikipedia.org/wiki/Windows_Error_Reporting)!  
To do this, we report an exception to WER via [ALPC](https://en.wikipedia.org/wiki/Local_Inter-Process_Communication):
1. We get some thread of `lsass.exe` (can be done with the `CreateToolhelp32Snapshot` API) - and save its thread ID.
2. We create two events that we will pass to the ALPC message: a "recovery event" and a "completion event".
3. We create a memory-mapped file that will contain a structure that'd maintain exception information (requires writable memory). That structure contains information for WER, including the events that we created, as well as exception information, process ID, the failing thread ID and so on.
4. 

## Summary of techniques
Here is a nice summary of the techniques, including pros and cons:

| Method                     | Doesn't require child process | Doesn't Require further tooling | Can avoid touching disk | Remarks                              |
| -------------------------- | ----------------------------- | ------------------------------- | ----------------------- | ------------------------------------ |
| Task manager               | ❌                            | ✅                              | ❌                     | Might have reliability issues (GUI)  |
| Rundll32-comsvcs minidump  | ❌                            | ✅                              | ❌                     | ---                                  |
| Procdump                   | ❌                            | ❌                              | ❌                     | Might write to registry (EULA)       |
| Minidump API               | ✅                            | ✅                              | ✅                     | ---                                  |
| PssCaptureSnapshot API     | ✅                            | ✅                              | ✅                     | ---                                  |
| Shtinikering               | ✅                            | ✅                              | ❌                     | Requires running as SYSTEM           |
| SilentProcessExit          | ✅                            | ✅                              | ❌                     | Writes to registry                   |
| Whole memory dump          | ✅                            | ✅                              | ✅                     | Might have reliability issues (racy) |
