# BypassingAVs

Implement techniques learned from MalDevAcademy

Command for signing the binary:

```powershell
.\Signer.ps1 -Password (ConvertTo-SecureString "<password>" -AsPlainText -Force) -BinaryPath ".\BypassingAVs.exe"
```