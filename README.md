# NtRemoteLoad

Remote shellcode injector, based on HWSyscalls by ShorSec, leveraging undetectable (currently) indirect native syscalls to inject shellcode into another process, creating a thread and executing it.

Disclaimer: The information/files provided in this repository are strictly intended for educational and ethical purposes only. The techniques and tools are intended to be used in a lawful and responsible manner, with the explicit consent of the target system's owner. Any unauthorized or malicious use of these techniques and tools is strictly prohibited and may result in legal consequences. I am not responsible for any damages or legal issues that may arise from the misuse of the information provided.

## Usage
```powershell
.\NtRemoteLoad.exe <path_to_shellcode_file> <remote_process_pid>
```

## Detection
Testing it against API monitor by Rohitab shows the following detection for Native syscalls:


![NtRemoteLoad4](https://github.com/florylsk/NtRemoteLoad/assets/46110263/86cc58e0-e3dd-47f5-9f00-8da8e1d74933)

Which is fairly good, though NtCreateFile could also be hidden but I have not seen a reason to change it yet.

On the other hand, testing it against Defender for Endpoint EDR trial with a Havoc C2 beacon payload yields the following detection:
### Executing the payload
![NtRemoteLoad2](https://github.com/florylsk/NtRemoteLoad/assets/46110263/4c0cbb86-418f-429c-a5ee-8aaab9d115e0)
### Getting the callback
![NtRemoteLoad1](https://github.com/florylsk/NtRemoteLoad/assets/46110263/b79bb767-003d-4469-b71b-15da5528752a)

### Visibility
![NtRemoteLoad3](https://github.com/florylsk/NtRemoteLoad/assets/46110263/1fc73235-88f7-4fdf-bf13-873a1a390824)

Which is also fairly good as these are just events, meaning the blue team would need Threat Hunting or SIEM to actually detect it.
