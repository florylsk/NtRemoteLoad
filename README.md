# NtRemoteLoad

Remote shellcode injector, based on HWSyscalls by ShorSec, leveraging undetectable (currently) indirect native syscalls to inject shellcode into another process, creating a thread and executing it.

Probably undetected by many AV/EDR/EPPs, but may change in the future.

## Usage
```powershell
.\NtRemoteLoad.exe <path_to_shellcode_file> <remote_process_pid>
```

## Detection
Testing it against API monitor by Rohitab shows the following detection for Native syscalls:


