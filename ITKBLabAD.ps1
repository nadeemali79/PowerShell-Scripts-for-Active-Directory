#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds the "ITKB Consultant" OU hierarchy in itkb.lab and populates it with
    sample Users, Groups, and Computer accounts for a training/test lab.

.DESCRIPTION
    Compatible with Windows Server 2016 / 2019 / 2022 / 2025 domain controllers.
    Only uses cmdlets from the standard ActiveDirectory PowerShell module, which
    are consistent across all four OS versions (RSAT-AD-PowerShell feature).

    ===========================================================================
    WHAT THIS SCRIPT DOES, STEP BY STEP
    ===========================================================================
    1. Connects to Active Directory using Get-ADDomain to confirm it can reach
       the domain (itkb.lab) and reads the domain's Distinguished Name (DN)
       and DNS root - it does not hard-code the DN, so it self-adjusts to
       whatever domain it is actually run against.

    2. Reads and prints the local OS version (Get-CimInstance Win32_OperatingSystem)
       purely for logging/troubleshooting - it does not branch its logic based
       on OS version, since the same AD cmdlets work on 2016/2019/2022/2025.

    3. Creates ONE parent OU at the domain root:
            OU=ITKB Consultant

    4. Under that parent OU, creates 10 department OUs:
            HR, Accounts, Finance, Sales, Marketing, Management,
            Admin, IT, Webdev, Critical Server

    5. Under each of the first 9 departments, creates 3 child OUs:
            Users, Groups, Computers
       Under "Critical Server", creates 3 different child OUs instead:
            Email Servers, Web Servers, RDS Server

    6. Sets the Description attribute on every single OU it creates (parent,
       department, and child) to "Created by ITKB Consultant".

    7. Populates each "Users" child OU with sample user accounts:
            - Random first/last name from built-in name lists
            - SamAccountName, UserPrincipalName, GivenName, Surname set
            - Password set from -DefaultPassword, account Enabled = $true
            - Department/Company attributes set, Description tagged
       Count controlled by -UsersPerOU (default 25 per department).

    8. Populates each "Groups" child OU with sample security groups:
            - Global scope, Security category
            - Named <Department>-<Type>-<n>, cycling through
              Managers / Staff / TeamLeads / ReadOnly / FullAccess
       Count controlled by -GroupsPerOU (default 5 per department).

    9. Populates each "Computers" child OU with sample computer ACCOUNTS
       (AD objects only - see limitation #2 below):
            - Named <DEPT-PREFIX>WK<001> style, Enabled = $true
       Count controlled by -ComputersPerOU (default 10 per department).

    10. Populates the Critical Server child OUs with a small fixed number of
        server-style computer accounts instead of the -ComputersPerOU value:
            Email Servers -> MAIL-SRV1..3
            Web Servers   -> WEB-SRV1..3
            RDS Server    -> RDS-SRV1..2

    11. Before creating any OU/user/group/computer, checks whether an object
        with that name already exists in that location and skips it if so -
        so the script is safe to re-run without erroring out or duplicating.

    12. Keeps a running counter of every object actually created and prints
        a summary at the end.

    13. Looks up the live ntds.dit file path from the registry
        (HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters) and reports
        its current on-disk size in GB, with a reminder of how far that is
        from an 8 GB target (see limitation #1).

    ===========================================================================
    IMPORTANT LIMITATIONS (read before running)
    ===========================================================================
      1. Object counts here are intentionally modest ("some" objects per the
         request). Growing ntds.dit to 8 GB realistically needs ~1-2 million
         AD objects (each object adds only a few KB, including replication
         metadata) - that is a dedicated perf/stress-test exercise, not a
         normal OU population task. Use -UsersPerOU / -GroupsPerOU /
         -ComputersPerOU (and re-run the script, changing -RunTag) to scale
         up toward whatever real target size you need. The script prints the
         live ntds.dit size at the end so you can track progress.
      2. New-ADComputer only creates the AD *computer object/account*. It does
         NOT join a physical/virtual machine to the domain. Actual domain
         join must be run ON the client machine itself (Add-Computer, or the
         GUI equivalent).

.PARAMETER UsersPerOU
    Number of user accounts to create in each department's "Users" OU.

.PARAMETER GroupsPerOU
    Number of security groups to create in each department's "Groups" OU.

.PARAMETER ComputersPerOU
    Number of computer accounts to create in each department's "Computers" OU.

.PARAMETER RunTag
    Suffix appended to object names so you can safely re-run the script
    multiple times to add more objects (e.g. for scaling toward a target
    database size) without name collisions.

.PARAMETER DefaultPassword
    Password set on all created user accounts. Change this before running
    in anything other than an isolated lab.

.EXAMPLE
    .\New-ITKBLabAD.ps1

.EXAMPLE
    .\New-ITKBLabAD.ps1 -UsersPerOU 200 -GroupsPerOU 20 -ComputersPerOU 50 -RunTag "batch2"
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ParentOUName      = "ITKB Consultant",
    [int]   $UsersPerOU        = 25,
    [int]   $GroupsPerOU       = 5,
    [int]   $ComputersPerOU    = 10,
    [string]$RunTag            = "",
    [string]$DefaultPassword   = "P@ssw0rd123!"
)

# ---------------------------------------------------------------------------
# 0. Banner - what this script is about to do
# ---------------------------------------------------------------------------
Write-Host @"
===============================================================================
 ITKB Consultant - Lab AD Build Script
===============================================================================
 This script will:
   1. Connect to the current AD domain and read its DN / DNS root.
   2. Create parent OU "$ParentOUName" at the domain root.
   3. Create 10 department OUs under it: HR, Accounts, Finance, Sales,
      Marketing, Management, Admin, IT, Webdev, Critical Server.
   4. Create child OUs under each department:
        - Users / Groups / Computers   (first 9 departments)
        - Email Servers / Web Servers / RDS Server (Critical Server)
   5. Tag every OU's Description as "Created by ITKB Consultant".
   6. Populate each department with:
        - $UsersPerOU user account(s)      in its Users OU
        - $GroupsPerOU security group(s)    in its Groups OU
        - $ComputersPerOU computer account(s) in its Computers OU
   7. Populate Critical Server with fixed server accounts:
        MAIL-SRV(1-3), WEB-SRV(1-3), RDS-SRV(1-2)
   8. Skip anything that already exists (safe to re-run).
   9. Report a count of objects created and the current ntds.dit size.

 NOTE: Computer accounts created here are AD objects only - they do NOT
 domain-join a real machine. That step must be run on the client itself.
===============================================================================
"@ -ForegroundColor White

# ---------------------------------------------------------------------------
# 0a. Pre-flight checks
# ---------------------------------------------------------------------------
Import-Module ActiveDirectory -ErrorAction Stop

try {
    $Domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-Error "Could not contact AD. Run this ON a Domain Controller (or a machine with RSAT-AD-PowerShell) that is a member of itkb.lab."
    return
}

$DomainDN      = $Domain.DistinguishedName
$DomainDNSRoot = $Domain.DNSRoot
$OSCaption     = (Get-CimInstance Win32_OperatingSystem).Caption

Write-Host "Domain             : $DomainDNSRoot ($DomainDN)" -ForegroundColor Cyan
Write-Host "Running on OS      : $OSCaption" -ForegroundColor Cyan
Write-Host "Users/Groups/Comps per OU : $UsersPerOU / $GroupsPerOU / $ComputersPerOU" -ForegroundColor Cyan

if ($DomainDNSRoot -ne "itkb.lab") {
    Write-Warning "Current domain is '$DomainDNSRoot', not 'itkb.lab'. Continuing anyway - objects will be created in the current domain."
}

$OUDescription   = "Created by ITKB Consultant"
$SecurePassword  = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
$Suffix          = if ($RunTag) { "-$RunTag" } else { "" }
$ObjectsCreated  = 0

# ---------------------------------------------------------------------------
# 1. Department / child-OU map
# ---------------------------------------------------------------------------
$Departments = [ordered]@{
    "HR"              = @("Users","Groups","Computers")
    "Accounts"        = @("Users","Groups","Computers")
    "Finance"         = @("Users","Groups","Computers")
    "Sales"           = @("Users","Groups","Computers")
    "Marketing"       = @("Users","Groups","Computers")
    "Management"      = @("Users","Groups","Computers")
    "Admin"           = @("Users","Groups","Computers")
    "IT"              = @("Users","Groups","Computers")
    "Webdev"          = @("Users","Groups","Computers")
    "Critical Server" = @("Email Servers","Web Servers","RDS Server")
}

# ---------------------------------------------------------------------------
# 2. Helper: create OU if missing, return its DN
# ---------------------------------------------------------------------------
function Get-OrNew-OU {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ParentPath
    )
    $existing = Get-ADOrganizationalUnit -SearchBase $ParentPath -SearchScope OneLevel `
        -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue

    if (-not $existing) {
        New-ADOrganizationalUnit -Name $Name -Path $ParentPath `
            -Description $OUDescription -ProtectedFromAccidentalDeletion $true | Out-Null
        Write-Host "  [OU created]  OU=$Name,$ParentPath" -ForegroundColor Green
    } else {
        Write-Host "  [OU exists ]  OU=$Name,$ParentPath" -ForegroundColor DarkYellow
    }
    return "OU=$Name,$ParentPath"
}

# ---------------------------------------------------------------------------
# 3. Sample name pools for users
# ---------------------------------------------------------------------------
$FirstNames = @("James","Mary","John","Patricia","Robert","Jennifer","Michael","Linda",
                "William","Elizabeth","David","Barbara","Richard","Susan","Joseph","Jessica",
                "Thomas","Sarah","Charles","Karen","Ahmed","Sara","Ali","Ayesha","Bilal",
                "Sana","Usman","Hina","Omar","Zainab")
$LastNames  = @("Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis",
                "Rodriguez","Martinez","Khan","Ahmed","Malik","Butt","Chaudhry","Raza",
                "Iqbal","Sheikh","Qureshi","Baig")
$GroupTypes = @("Managers","Staff","TeamLeads","ReadOnly","FullAccess")

# ---------------------------------------------------------------------------
# 4. Build the hierarchy and populate it
# ---------------------------------------------------------------------------
Write-Host "`n=== Creating parent OU ===" -ForegroundColor Magenta
$ParentOUPath = Get-OrNew-OU -Name $ParentOUName -ParentPath $DomainDN

foreach ($Dept in $Departments.Keys) {

    Write-Host "`n=== Department: $Dept ===" -ForegroundColor Magenta
    $DeptOUPath = Get-OrNew-OU -Name $Dept -ParentPath $ParentOUPath

    foreach ($ChildName in $Departments[$Dept]) {

        $ChildOUPath = Get-OrNew-OU -Name $ChildName -ParentPath $DeptOUPath

        switch ($ChildName) {

            "Users" {
                for ($i = 1; $i -le $UsersPerOU; $i++) {
                    $First = Get-Random -InputObject $FirstNames
                    $Last  = Get-Random -InputObject $LastNames
                    $Sam   = ("{0}.{1}{2}{3}" -f $First.Substring(0,1), $Last, $i, $Suffix).ToLower()
                    $Sam   = $Sam.Substring(0, [Math]::Min(20, $Sam.Length))
                    $UPN   = "$Sam@$DomainDNSRoot"

                    if (-not (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue)) {
                        try {
                            New-ADUser -Name "$First $Last $i$Suffix" `
                                -GivenName $First -Surname $Last `
                                -SamAccountName $Sam -UserPrincipalName $UPN `
                                -Path $ChildOUPath -AccountPassword $SecurePassword `
                                -Enabled $true -ChangePasswordAtLogon $false `
                                -Department $Dept -Company "ITKB Lab" `
                                -Description "$Dept department user - $OUDescription" `
                                -ErrorAction Stop | Out-Null
                            $ObjectsCreated++
                        } catch {
                            Write-Warning "User '$Sam' failed: $($_.Exception.Message)"
                        }
                    }
                }
                Write-Host "  -> $UsersPerOU user(s) processed in $Dept/Users" -ForegroundColor Cyan
            }

            "Groups" {
                for ($i = 1; $i -le $GroupsPerOU; $i++) {
                    $GType = $GroupTypes[($i - 1) % $GroupTypes.Count]
                    $GName = "$Dept-$GType-$i$Suffix"
                    if (-not (Get-ADGroup -Filter "Name -eq '$GName'" -ErrorAction SilentlyContinue)) {
                        try {
                            New-ADGroup -Name $GName -GroupScope Global -GroupCategory Security `
                                -Path $ChildOUPath -Description "$Dept group - $OUDescription" `
                                -ErrorAction Stop | Out-Null
                            $ObjectsCreated++
                        } catch {
                            Write-Warning "Group '$GName' failed: $($_.Exception.Message)"
                        }
                    }
                }
                Write-Host "  -> $GroupsPerOU group(s) processed in $Dept/Groups" -ForegroundColor Cyan
            }

            "Computers" {
                $Prefix = ($Dept -replace '[^A-Za-z]', '').Substring(0, [Math]::Min(3, ($Dept -replace '[^A-Za-z]','').Length)).ToUpper()
                for ($i = 1; $i -le $ComputersPerOU; $i++) {
                    $CName = ("{0}WK{1:D3}{2}" -f $Prefix, $i, $Suffix)
                    $CName = ($CName -replace '[^A-Za-z0-9\-]', '').Substring(0, [Math]::Min(15, $CName.Length))
                    if (-not (Get-ADComputer -Filter "Name -eq '$CName'" -ErrorAction SilentlyContinue)) {
                        try {
                            New-ADComputer -Name $CName -Path $ChildOUPath `
                                -Description "$Dept workstation - $OUDescription" `
                                -Enabled $true -ErrorAction Stop | Out-Null
                            $ObjectsCreated++
                        } catch {
                            Write-Warning "Computer '$CName' failed: $($_.Exception.Message)"
                        }
                    }
                }
                Write-Host "  -> $ComputersPerOU computer account(s) processed in $Dept/Computers" -ForegroundColor Cyan
            }

            { $_ -in "Email Servers","Web Servers","RDS Server" } {
                # Critical Server child OUs: small fixed number of server accounts each
                $ServerMap = @{
                    "Email Servers" = @{ Prefix = "MAIL-SRV"; Count = 3 }
                    "Web Servers"   = @{ Prefix = "WEB-SRV";  Count = 3 }
                    "RDS Server"    = @{ Prefix = "RDS-SRV";  Count = 2 }
                }
                $Cfg = $ServerMap[$ChildName]
                for ($i = 1; $i -le $Cfg.Count; $i++) {
                    $CName = ("{0}{1}{2}" -f $Cfg.Prefix, $i, $Suffix)
                    $CName = $CName.Substring(0, [Math]::Min(15, $CName.Length))
                    if (-not (Get-ADComputer -Filter "Name -eq '$CName'" -ErrorAction SilentlyContinue)) {
                        try {
                            New-ADComputer -Name $CName -Path $ChildOUPath `
                                -Description "$ChildName - $OUDescription" `
                                -Enabled $true -ErrorAction Stop | Out-Null
                            $ObjectsCreated++
                        } catch {
                            Write-Warning "Server account '$CName' failed: $($_.Exception.Message)"
                        }
                    }
                }
                Write-Host "  -> $($Cfg.Count) server account(s) processed in Critical Server/$ChildName" -ForegroundColor Cyan
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Summary + ntds.dit size check
# ---------------------------------------------------------------------------
Write-Host "`n================ SUMMARY ================" -ForegroundColor Green
Write-Host "AD objects created this run : $ObjectsCreated"

try {
    $NTDSPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "DSA Database file" -ErrorAction Stop).'DSA Database file'
    if (Test-Path $NTDSPath) {
        $SizeBytes = (Get-Item $NTDSPath).Length
        $SizeGB    = [Math]::Round($SizeBytes / 1GB, 3)
        Write-Host "ntds.dit path                : $NTDSPath"
        Write-Host "ntds.dit current size        : $SizeGB GB"
        if ($SizeGB -lt 8) {
            Write-Host "Note: database is well under 8 GB. Reaching 8 GB literally needs roughly" -ForegroundColor Yellow
            Write-Host "1-2 million objects (each object adds only a few KB). Re-run this script" -ForegroundColor Yellow
            Write-Host "with higher -UsersPerOU/-GroupsPerOU/-ComputersPerOU and a new -RunTag to" -ForegroundColor Yellow
            Write-Host "keep adding objects toward that target, or run an offline defrag" -ForegroundColor Yellow
            Write-Host "(ntdsutil) afterward if you need the on-disk file to reflect current size." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Warning "Could not read ntds.dit size automatically (registry path not found). Check File Explorer under %SystemRoot%\NTDS manually."
}

Write-Host "===========================================" -ForegroundColor Green
