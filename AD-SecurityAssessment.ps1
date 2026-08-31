<#
.SYNOPSIS
    Active Directory Health, Security & Hardening Assessment Script.

.DESCRIPTION
    Performs a READ-ONLY assessment of an Active Directory environment covering:
      1) Number and details of Domain Controllers
      2) AD weaknesses & configuration gaps
      3) Known AD vulnerability indicators
      4) Recommended configuration comparison (current vs. recommended)
      5) Open ports on each Domain Controller
      6) AD replication status (when multiple DCs exist)
      7) AD default configuration overview
      8) AD hardening best-practice checklist

    This script makes NO changes to Active Directory. It only queries AD via
    the ActiveDirectory PowerShell module and standard Windows tools
    (Test-NetConnection, Get-Service, repadmin, etc.) and produces a console
    report plus an HTML report file for record-keeping.

.PARAMETER OutputPath
    Folder to save the HTML report. Default: current directory.

.PARAMETER StaleDays
    Number of days of inactivity used to flag user/computer accounts as stale.
    Default: 90.

.EXAMPLE
    .\AD-SecurityAssessment.ps1

.EXAMPLE
    .\AD-SecurityAssessment.ps1 -OutputPath "C:\Reports" -StaleDays 60

.NOTES
    - Run with Domain Admin (or equivalent read) rights from a machine with
      RSAT: Active Directory PowerShell module and AD DS Tools installed,
      ideally on/near a Domain Controller.
    - Requires: ActiveDirectory module; repadmin.exe (RSAT AD DS Tools) for
      section 6; WinRM enabled on DCs for remote service checks in section 3
      (these individual checks are skipped gracefully if unavailable).
    - This script is READ-ONLY - it does not modify any AD or server settings.

    Credit: ITKB Consultant by Nadeem Muhammad Ali Meer
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]$StaleDays = 90
)

#region Setup ---------------------------------------------------------------

$reportSections = [ordered]@{}

function Write-Section {
    param([string]$Title)
    Write-Host "`n==================== $Title ====================" -ForegroundColor Cyan
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "The ActiveDirectory PowerShell module is not available. Install RSAT: Active Directory Domain Services and LDAP tools, then re-run this script."
    return
}

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
} catch {
    Write-Error "Unable to contact Active Directory. Make sure you are domain-joined and have network access to a Domain Controller."
    return
}

#endregion

#region 1) Domain Controllers ------------------------------------------------

Write-Section "1) Domain Controllers"

$dcs = Get-ADDomainController -Filter * |
    Select-Object Name, Site, OperatingSystem, IPv4Address, IsGlobalCatalog, IsReadOnly, OperationMasterRoles

Write-Host "Total Domain Controllers found: $($dcs.Count)" -ForegroundColor Green
$dcs | Format-Table Name, Site, OperatingSystem, IPv4Address, IsGlobalCatalog, IsReadOnly -AutoSize

$reportSections['1. Domain Controllers'] = $dcs

#endregion

#region 2) AD Weaknesses & Gaps -----------------------------------------------

Write-Section "2) AD Weaknesses & Gaps"

$weaknesses = @()

# AD Recycle Bin
$recycleBin = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
$recycleBinEnabled = $recycleBin.EnabledScopes.Count -gt 0
$weaknesses += [PSCustomObject]@{ Check = "AD Recycle Bin"; Status = if ($recycleBinEnabled) {"Enabled"} else {"Disabled"}; Risk = if (-not $recycleBinEnabled) {"Gap: object recovery is harder without it"} else {"OK"} }

# Functional levels
$weaknesses += [PSCustomObject]@{ Check = "Domain Functional Level"; Status = $domain.DomainMode; Risk = if ($domain.DomainMode -match '2000|2003|2008$') {"Weak: outdated functional level, missing modern security features"} else {"OK"} }
$weaknesses += [PSCustomObject]@{ Check = "Forest Functional Level"; Status = $forest.ForestMode; Risk = if ($forest.ForestMode -match '2000|2003|2008$') {"Weak: outdated functional level"} else {"OK"} }

# Default password policy
$pwdPolicy = Get-ADDefaultDomainPasswordPolicy
$weaknesses += [PSCustomObject]@{ Check = "Min Password Length"; Status = $pwdPolicy.MinPasswordLength; Risk = if ($pwdPolicy.MinPasswordLength -lt 14) {"Weak: below recommended 14 characters"} else {"OK"} }
$weaknesses += [PSCustomObject]@{ Check = "Password Complexity"; Status = $pwdPolicy.ComplexityEnabled; Risk = if (-not $pwdPolicy.ComplexityEnabled) {"Weak: complexity disabled"} else {"OK"} }

# Fine-grained password policies
$fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
$weaknesses += [PSCustomObject]@{ Check = "Fine-Grained Password Policies"; Status = "$($fgpp.Count) defined"; Risk = if ($fgpp.Count -eq 0) {"Gap: no tiered password policy for privileged accounts"} else {"OK"} }

# Guest account
$guest = Get-ADUser -Filter "Name -eq 'Guest'" -Properties Enabled
$weaknesses += [PSCustomObject]@{ Check = "Guest Account"; Status = if ($guest.Enabled) {"Enabled"} else {"Disabled"}; Risk = if ($guest.Enabled) {"Weak: Guest account should be disabled"} else {"OK"} }

# krbtgt password age
$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
$krbtgtAgeDays = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
$weaknesses += [PSCustomObject]@{ Check = "krbtgt Password Age"; Status = "$krbtgtAgeDays days"; Risk = if ($krbtgtAgeDays -gt 180) {"Weak: should be rotated (twice) periodically, e.g. every 6 months"} else {"OK"} }

# Password Never Expires
$pwdNeverExpires = Get-ADUser -Filter "PasswordNeverExpires -eq `$true -and Enabled -eq `$true"
$weaknesses += [PSCustomObject]@{ Check = "Enabled Accounts - Password Never Expires"; Status = $pwdNeverExpires.Count; Risk = if ($pwdNeverExpires.Count -gt 0) {"Gap: review these accounts, especially service/admin accounts"} else {"OK"} }

# Password Not Required
$pwdNotRequired = Get-ADUser -Filter "PasswordNotRequired -eq `$true -and Enabled -eq `$true"
$weaknesses += [PSCustomObject]@{ Check = "Enabled Accounts - Password Not Required"; Status = $pwdNotRequired.Count; Risk = if ($pwdNotRequired.Count -gt 0) {"Weak: accounts that can have a blank password"} else {"OK"} }

# Stale accounts
$cutoff = (Get-Date).AddDays(-$StaleDays)
$cutoffFileTime = $cutoff.ToFileTime()
$staleUsers = Get-ADUser -Filter "LastLogonTimestamp -lt $cutoffFileTime -and Enabled -eq `$true" -Properties LastLogonTimestamp -ErrorAction SilentlyContinue
$staleComputers = Get-ADComputer -Filter "LastLogonTimestamp -lt $cutoffFileTime -and Enabled -eq `$true" -Properties LastLogonTimestamp -ErrorAction SilentlyContinue
$weaknesses += [PSCustomObject]@{ Check = "Stale Enabled User Accounts (> $StaleDays days inactive)"; Status = $staleUsers.Count; Risk = if ($staleUsers.Count -gt 0) {"Gap: increases attack surface, should be reviewed/disabled"} else {"OK"} }
$weaknesses += [PSCustomObject]@{ Check = "Stale Enabled Computer Accounts (> $StaleDays days inactive)"; Status = $staleComputers.Count; Risk = if ($staleComputers.Count -gt 0) {"Gap: stale computer objects should be disabled/removed"} else {"OK"} }

$weaknesses | Format-Table -Wrap -AutoSize

# Privileged group membership counts (informational)
$privGroups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators'
$privGroupCounts = foreach ($g in $privGroups) {
    $members = Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Group = $g; MemberCount = $members.Count }
}
Write-Host "`nPrivileged group membership counts:" -ForegroundColor Yellow
$privGroupCounts | Format-Table -AutoSize

$reportSections['2. AD Weaknesses & Gaps'] = $weaknesses
$reportSections['2b. Privileged Group Membership'] = $privGroupCounts

#endregion

#region 3) AD Vulnerabilities --------------------------------------------------

Write-Section "3) AD Vulnerabilities"

$vulns = @()

# Unconstrained delegation (excluding DCs, which legitimately have it)
$unconstrained = Get-ADComputer -Filter "TrustedForDelegation -eq `$true" -Properties TrustedForDelegation |
    Where-Object { $_.Name -notin $dcs.Name }
$vulns += [PSCustomObject]@{ Check = "Unconstrained Delegation (non-DC computers)"; Status = $unconstrained.Count; Explanation = "Systems with unconstrained delegation can be abused to harvest Domain Admin tickets if compromised." }

# Kerberoasting exposure
$spnAccounts = Get-ADUser -Filter "ServicePrincipalName -like '*' -and Enabled -eq `$true" -Properties ServicePrincipalName
$vulns += [PSCustomObject]@{ Check = "Kerberoastable Accounts (user accounts with SPNs)"; Status = $spnAccounts.Count; Explanation = "Accounts with SPNs can have their Kerberos service ticket requested and cracked offline. Ensure these use long random passwords." }

# AS-REP Roasting exposure
$asrepAccounts = Get-ADUser -Filter "DoesNotRequirePreAuth -eq `$true -and Enabled -eq `$true"
$vulns += [PSCustomObject]@{ Check = "AS-REP Roastable Accounts (pre-auth not required)"; Status = $asrepAccounts.Count; Explanation = "These accounts allow offline password cracking without any authentication attempt." }

# SMBv1 on DCs (best-effort remote check)
$smbv1Results = foreach ($dc in $dcs) {
    try {
        $feature = Invoke-Command -ComputerName $dc.Name -ScriptBlock { Get-WindowsFeature FS-SMB1 } -ErrorAction Stop
        "$($dc.Name): $($feature.InstallState)"
    } catch { "$($dc.Name): unable to check (WinRM/permissions)" }
}
$vulns += [PSCustomObject]@{ Check = "SMBv1 Status on DCs"; Status = ($smbv1Results -join "; "); Explanation = "SMBv1 is legacy and vulnerable to exploits like EternalBlue/WannaCry. Should be removed." }

# Print Spooler on DCs (PetitPotam / PrintNightmare relevance)
$spoolerResults = foreach ($dc in $dcs) {
    try {
        $svc = Get-Service -ComputerName $dc.Name -Name Spooler -ErrorAction Stop
        "$($dc.Name): $($svc.Status)"
    } catch { "$($dc.Name): unable to check" }
}
$vulns += [PSCustomObject]@{ Check = "Print Spooler Service on DCs"; Status = ($spoolerResults -join "; "); Explanation = "Running Spooler on DCs increases risk from PrintNightmare/PetitPotam-class relay attacks. Recommend disabling on DCs." }

# LM hash storage reminder (registry policy varies by GPO, flagged for manual check)
$vulns += [PSCustomObject]@{ Check = "LM Hash Storage Policy"; Status = "Verify manually via GPO/registry on each DC"; Explanation = "Ensure 'Network security: Do not store LAN Manager hash value' is enabled to prevent weak LM hash storage." }

$vulns | Format-Table -Wrap -AutoSize
$reportSections['3. AD Vulnerabilities'] = $vulns

#endregion

#region 4) Recommended Configuration Comparison -------------------------------

Write-Section "4) AD Recommended Configuration"

$protectedUsersCount = (Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue).Count

$recommended = @(
    [PSCustomObject]@{ Setting = "Min Password Length";         Current = $pwdPolicy.MinPasswordLength; Recommended = "14+ characters" }
    [PSCustomObject]@{ Setting = "Password Complexity";         Current = $pwdPolicy.ComplexityEnabled;  Recommended = "Enabled" }
    [PSCustomObject]@{ Setting = "Max Password Age";            Current = $pwdPolicy.MaxPasswordAge;     Recommended = "60-90 days, or passphrase policy + MFA" }
    [PSCustomObject]@{ Setting = "Account Lockout Threshold";   Current = $pwdPolicy.LockoutThreshold;   Recommended = "5-10 attempts" }
    [PSCustomObject]@{ Setting = "AD Recycle Bin";              Current = if ($recycleBinEnabled) {"Enabled"} else {"Disabled"}; Recommended = "Enabled" }
    [PSCustomObject]@{ Setting = "Guest Account";               Current = if ($guest.Enabled) {"Enabled"} else {"Disabled"}; Recommended = "Disabled" }
    [PSCustomObject]@{ Setting = "krbtgt Password Rotation";    Current = "$krbtgtAgeDays days old"; Recommended = "Rotate twice, every ~180 days" }
    [PSCustomObject]@{ Setting = "LAPS (Local Admin Password)"; Current = "Verify manually (ms-Mcs-AdmPwd / Windows LAPS attribute)"; Recommended = "Deployed on all servers/workstations" }
    [PSCustomObject]@{ Setting = "Tiered Admin Model";          Current = "Verify manually"; Recommended = "Implement Tier 0/1/2 separation" }
    [PSCustomObject]@{ Setting = "Protected Users Group";       Current = "$protectedUsersCount members"; Recommended = "All Tier 0 admin accounts added" }
)

$recommended | Format-Table -Wrap -AutoSize
$reportSections['4. Recommended Configuration'] = $recommended

#endregion

#region 5) Open Ports on DCs ---------------------------------------------------

Write-Section "5) Open Ports on Domain Controllers"

$adPorts = @(
    @{ Port = 53;   Service = "DNS" }
    @{ Port = 88;   Service = "Kerberos" }
    @{ Port = 135;  Service = "RPC Endpoint Mapper" }
    @{ Port = 139;  Service = "NetBIOS Session" }
    @{ Port = 389;  Service = "LDAP" }
    @{ Port = 445;  Service = "SMB" }
    @{ Port = 464;  Service = "Kerberos Password Change" }
    @{ Port = 636;  Service = "LDAPS" }
    @{ Port = 3268; Service = "Global Catalog" }
    @{ Port = 3269; Service = "Global Catalog SSL" }
    @{ Port = 3389; Service = "RDP" }
    @{ Port = 5985; Service = "WinRM HTTP" }
    @{ Port = 5986; Service = "WinRM HTTPS" }
    @{ Port = 9389; Service = "AD Web Services" }
)

$portResults = foreach ($dc in $dcs) {
    foreach ($p in $adPorts) {
        $test = Test-NetConnection -ComputerName $dc.IPv4Address -Port $p.Port -WarningAction SilentlyContinue
        [PSCustomObject]@{ DC = $dc.Name; Port = $p.Port; Service = $p.Service; Open = $test.TcpTestSucceeded }
    }
}

$portResults | Where-Object { $_.Open } | Format-Table -AutoSize
Write-Host "`n(Only OPEN ports are shown above. Any port outside this AD-standard list being open should be reviewed separately.)" -ForegroundColor Yellow
$reportSections['5. Open Ports on DCs'] = $portResults

#endregion

#region 6) AD Replication Status ------------------------------------------------

Write-Section "6) AD Replication Status"

if ($dcs.Count -gt 1) {
    $replOutput = $null
    try {
        $replOutput = repadmin /replsummary 2>&1
        $replOutput | ForEach-Object { Write-Host $_ }
        $reportSections['6. Replication Status'] = ($replOutput -join "`n")
    } catch {
        Write-Warning "repadmin.exe not available or failed to run. Falling back to Get-ADReplicationPartnerMetadata."
        $replMeta = Get-ADReplicationPartnerMetadata -Target $domain.DNSRoot -Scope Domain -ErrorAction SilentlyContinue |
            Select-Object Server, Partner, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures
        $replMeta | Format-Table -AutoSize
        $reportSections['6. Replication Status'] = $replMeta
    }
} else {
    Write-Host "Only one Domain Controller found - replication status is not applicable." -ForegroundColor Yellow
    $reportSections['6. Replication Status'] = "N/A - single DC environment"
}

#endregion

#region 7) AD Default Configuration ----------------------------------------------

Write-Section "7) AD Default Configuration Overview"

$configNC = (Get-ADRootDSE).configurationNamingContext
$tombstoneLifetime = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -ErrorAction SilentlyContinue).tombstoneLifetime

$defaultConfig = [PSCustomObject]@{
    DomainName            = $domain.DNSRoot
    NetBIOSName           = $domain.NetBIOSName
    DomainFunctionalLevel = $domain.DomainMode
    ForestFunctionalLevel = $forest.ForestMode
    SchemaMaster          = $forest.SchemaMaster
    DomainNamingMaster    = $forest.DomainNamingMaster
    PDCEmulator           = $domain.PDCEmulator
    RIDMaster             = $domain.RIDMaster
    InfrastructureMaster  = $domain.InfrastructureMaster
    DefaultUsersOU        = $domain.UsersContainer
    DefaultComputersOU    = $domain.ComputersContainer
    TombstoneLifetimeDays = $tombstoneLifetime
    Sites                 = (Get-ADReplicationSite -Filter *).Count
    Trusts                = (Get-ADTrust -Filter * -ErrorAction SilentlyContinue).Count
}

$defaultConfig | Format-List
$reportSections['7. Default Configuration'] = $defaultConfig

#endregion

#region 8) AD Hardening Best Practices (checklist) --------------------------------

Write-Section "8) AD Hardening Best Practices Checklist"

$bestPractices = @(
    "Patch DCs promptly - subscribe to Microsoft security advisories for AD/Kerberos CVEs"
    "Implement a tiered administration model (Tier 0/1/2) to contain lateral movement"
    "Deploy LAPS (or Windows LAPS) for unique local admin passwords on every machine"
    "Add all Tier 0 admin accounts to the 'Protected Users' security group"
    "Disable the built-in Guest account and rename/monitor the built-in Administrator account"
    "Enforce a strong password policy (14+ chars) and/or passphrases with MFA for admin accounts"
    "Rotate the krbtgt account password twice, on a regular schedule (e.g. every 180 days)"
    "Remove/limit unconstrained Kerberos delegation; use constrained or resource-based delegation instead"
    "Regularly audit and disable stale user/computer accounts"
    "Disable SMBv1 and enforce SMB signing across the domain"
    "Require LDAP signing and LDAP channel binding on all DCs"
    "Disable NTLMv1 and LM hash storage; restrict NTLM where possible in favor of Kerberos"
    "Disable the Print Spooler service on Domain Controllers"
    "Restrict direct RDP/interactive logon rights for privileged accounts to dedicated admin workstations (PAWs)"
    "Enable Advanced Audit Policy logging (account logon, privilege use, directory service changes) and forward logs to a SIEM"
    "Enable the AD Recycle Bin for faster object recovery"
    "Review and minimize membership of Domain Admins, Enterprise Admins, and Schema Admins"
    "Maintain regular, tested, offline/immutable backups of AD (system state) and test forest recovery"
    "Monitor for Kerberoasting/AS-REP roasting indicators and enforce strong service account passwords"
    "Keep DC time synchronization accurate, since Kerberos is time-sensitive"
)

$bestPractices | ForEach-Object { Write-Host " - $_" }
$reportSections['8. Hardening Best Practices'] = $bestPractices

#endregion

#region Export Report -------------------------------------------------------------

$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path -Path $OutputPath -ChildPath "AD_Assessment_Report_$timestamp.html"

$htmlBody = foreach ($key in $reportSections.Keys) {
    "<h2>$key</h2>"
    $data = $reportSections[$key]
    if ($data -is [string]) {
        "<pre>$data</pre>"
    } elseif ($data -is [array] -and $data.Count -gt 0 -and ($data[0] -is [string])) {
        "<ul>" + (($data | ForEach-Object { "<li>$_</li>" }) -join "") + "</ul>"
    } else {
        $data | ConvertTo-Html -Fragment
    }
}

$htmlHead = "<style>body{font-family:Segoe UI,Arial,sans-serif;} table{border-collapse:collapse;margin-bottom:20px;} th,td{border:1px solid #ccc;padding:6px 10px;} th{background:#2c3e50;color:#fff;} h2{color:#2c3e50;border-bottom:2px solid #2c3e50;}</style>"
$html = ConvertTo-Html -Title "AD Assessment Report - $($domain.DNSRoot) - $timestamp" -Body ($htmlBody -join "`n") -Head $htmlHead

$html | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`nFull assessment report saved to: $reportFile" -ForegroundColor Green

#endregion
