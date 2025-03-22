# BypassingAVs

Implement techniques learned from MalDevAcademy for building a malware that can bypass AVs as well as sandboxes.

## Implemented Techniques

- **Payload Storage**:
	- **Payload Placement in the `.rsrc` section**: used for placing the shellcode in the `.rsrc` section of the PE file.
	- **Payload Staging**: used for loading the payload from the internet (the current repo) with a fixed and [stack string](https://www.geeksforgeeks.org/storage-for-strings-in-c/) of URL. This is the current technique that is being used in the project.
- **Encryption**: payload is encrypted with [RC4](https://en.wikipedia.org/wiki/RC4) algorithm.
- **Brute-Force Decryption**: the hardcoded key is encrypted with KeyGuard and requires brute-force decrytion with a hint byte for retrieving the original key.
- **(Non-Elevated) Process Enumeration**: used for searching for specific and non-elevated processes in the system by using `NtQuerySystemInformation`, `NtOpenProcessToken`, and `NtQueryInformationToken` functions.
- **PPID Spoofed and Debugged/Suspended Process Creation**: used for creating a process with a spoofed PPID and in a debugged/suspended state that can be utilized by the **Early Bird APC Injection** technique.
- **API Hashing**: used for hiding the malicious API imports in the Import Address Table (IAT) by hashing the API names and resolving them in run-time. This is implemented by using the custom `GetModuleHandle` and `GetProcAddress` functions for resolving the hash values generated by the Hasher project in this repo.
- **Remote Payload Execution**:
	- **Local/Remote Mapping Injection**: used for allocating mapped memory in a local/remote process and injecting shellcode into it.
	- **Eearly Bird APC Injection**: used for injecting shellcode into a APC queue of a remote process. This technique is being used in the project.
- **WhisperHell**: it is a combination of [Hell's Gate](https://github.com/am0nsec/HellsGate) and [SysWhispers3](https://github.com/klezVirus/SysWhispers3) used for bypassing userland hooking by utilizing the SSN searching technique of Hell's Gate and indirect syscall technique of SysWhispers3.
- **Anti-Analysis**: including self-deletion (utilizing [Alternate Data Stream](https://github.com/OWASP/www-community/blob/master/pages/attacks/Windows_DATA_alternate_data_stream.md)), a mouse click counter (utilizing the `SetWindowsHookExW` function) and execution delay (utilizing the `NtDelayExecution` function).
- **Entropy Reduction**: use [EntropyReducer](https://github.com/Maldev-Academy/EntropyReducer) for reducing the entropy of the encrypted payload.
- **IAT Camouflage**: used for creating fake IAT entries by tricking the compiler into thinking that the benign and unused API functions are being used in the code.
- **CRT Library Independent**: totally remove the dependency on the CRT library of Visual Studio by using some custom and intrinsic functions for reducing the size and the entropy of the binary.

## Problems/Lesson Learned When Building the Project (in Vietnamese)

[Problems.pdf](https://github.com/aleister1102/BypassingAVs/blob/cf1ed3288ba7a8d55ba7324551290bfa7be3a9b0/Problems.pdf) or https://insomnia1102.online/002-Cyber-Security/MalDev/MalDev---Bypassing-AVs

## Commands

The command used for signing the binary:

```powershell
.\Signer.ps1 -Password (ConvertTo-SecureString "<password>" -AsPlainText -Force) -BinaryPath ".\x64\Release\BypassingAVs.exe"
```

NOTE: the signed binary sometimes gets detected by AVs, so it is recommended to use the binary without signing it.

## Future Work
- Create Process With `NtCreateUserProcess`
- NTDLL Unhooking
- Communication With C2 Server
