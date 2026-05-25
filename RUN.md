# Run ShellKnight PowerShell Script

## Steps

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
iwr https://raw.githubusercontent.com/cdburgess75/ShellKnight/refs/heads/main/shellknight.ps1 -OutFile shellknight.ps1
.\shellknight.ps1
