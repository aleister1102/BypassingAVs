# BypassingAVs

Implement techniques learned from MalDevAcademy

Command for signing the binary:

```powershell
.\Signer.ps1 -Password (ConvertTo-SecureString "<password>" -AsPlainText -Force) -BinaryPath ".\x64\Release\BypassingAVs.exe"
```

TODO: add features and roadmap as well as the problems I have solved during the process of learning