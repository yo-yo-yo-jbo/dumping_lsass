# Different ways of dumping lsass
As part of my "coming back to Windows security" phase, I've decided to write a short blogpost about the significance and methodology of dumping lsass.  
While these are not novel techniques, I think summarizing ideas here would make sense, especially if you're stuck at 2-3 methods that are all monitored.

## What is lsass
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

### Task manager
While that is probably the least stelthy technique out there, it's quite effective.  
The Windows Task Manager (taskmgr.exe) is a GUI application that allows one to select a process and naively dump it:
