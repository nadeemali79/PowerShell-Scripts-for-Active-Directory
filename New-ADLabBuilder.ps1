#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive AD lab builder - asks you questions and then creates YOUR
    custom OU hierarchy (Users/Groups/Computers) in YOUR domain.

.DESCRIPTION
    This is a generalized version of a fixed "ITKB Consultant" build script.
    It does NOT hard-code any domain name or OU structure - everything is
    gathered by asking questions at runtime (or loaded from a saved JSON
    config), so each student can run the exact same script against their own
    lab domain and their own OU design without editing a single line of code.

    Compatible with Windows Server 2016 / 2019 / 2022 / 2025 domain
    controllers - only standard ActiveDirectory module cmdlets are used.

    ===========================================================================
    WHAT THIS SCRIPT DOES, STEP BY STEP
    ===========================================================================
    1. ASKS you for the domain FQDN to build the hierarchy in (e.g. itkb.lab,
       or your own domain name). It first tries a silent Get-ADDomain purely
       to offer that as a suggested default in the prompt - it never skips
       the question. It then validates the domain you typed with
       Get-ADDomain -Server <name>, and re-prompts if that domain can't be
       contacted (bad spelling, DNS issue, unreachable DC) instead of
       erroring out and stopping. Every AD cmdlet used later in the script
       explicitly targets this confirmed domain via -Server, rather than
       silently relying on ambient domain context - this avoids errors in
       multi-domain forests or when run from a member server.

    2. Either:
         a) Loads a previously-saved plan from -ConfigFile (JSON), or
         b) Interactively asks you:
              - Parent OU name
              - How many department/top-level OUs you want
              - Each department's name
              - Whether each department should use the standard
                Users / Groups / Computers child OUs (with counts), or a
                fully custom set of child OU names
              - For each custom child OU: what it should contain
                (User accounts / Security groups / Computer accounts / nothing)
                and how many objects to create in it

    3. Shows you the FULL plan (every OU and every object count) and asks for
       one final Y/N confirmation before touching AD.

    4. Optionally saves the plan you just built to a JSON file (-SaveConfigFile)
       so you (or your instructor) can re-run the identical structure later,
       or share the config file with classmates who have different domains.

    5. Creates the parent OU, then each department OU, then each child OU,
       tagging every OU's Description with -OUDescription (default:
       "Created by ITKB Consultant").

    6. Populates each child OU with the object type/count you specified:
         - Users     -> New-ADUser (random sample names, enabled, password set)
         - Groups    -> New-ADGroup (Global/Security)
         - Computers -> New-ADComputer (AD computer OBJECTS only - see
                        limitation #2 below)

    7. Skips anything that already exists by name, so the script is safe to
       re-run without erroring out or duplicating objects.

    8. Prints a count of objects created and the current ntds.dit size at
       the end.

    ===========================================================================
    IMPORTANT LIMITATIONS (read before running)
    ===========================================================================
      1. Reaching a specific large database size (e.g. several GB) is NOT
         realistic with "some" sample objects - each AD object typically
         adds only a few KB to ntds.dit. That needs bulk generation at a much
         larger scale, which is a different kind of script (ask if you need
         one). This script is for building a realistic OU/object structure
         for training, not for hitting a target file size.
      2. New-ADComputer only creates the AD *computer object/account*. It does
         NOT join a physical/virtual machine to the domain. Actual domain
         join must be run ON the client machine itself (Add-Computer, or the
         GUI equivalent).
      3. Run this in an isolated lab/training domain. It creates real
         accounts with a password you choose - don't point it at production.

.PARAMETER DomainName
    The FQDN of the domain to build the OU/object hierarchy in (e.g.
    itkb.lab). If omitted interactively, you'll be prompted for it (with an
    auto-detected suggestion as the default). Required when -NonInteractive
    is used, since there is nothing to prompt for in that mode.

.PARAMETER ConfigFile
    Path to a previously saved JSON plan. If supplied and the file exists,
    the script skips ALL interactive questions and builds exactly that plan.

.PARAMETER SaveConfigFile
    Path to save the plan you build interactively, as JSON, for reuse later.

.PARAMETER OUDescription
    Text written into the Description attribute of every OU created.

.PARAMETER DefaultPassword
    Password set on all created user accounts. You will be asked to confirm
    or change this interactively unless -NonInteractive is used.

.PARAMETER RunTag
    Suffix appended to generated object names so the script can be safely
    re-run multiple times without name collisions.

.PARAMETER NonInteractive
    Suppresses all prompts. Requires -ConfigFile. Uses -DefaultPassword and
    -RunTag as passed (or their defaults) with no further questions.

.EXAMPLE
    .\New-ADLabBuilder.ps1
    Fully interactive - asks every question, then builds the plan.

.EXAMPLE
    .\New-ADLabBuilder.ps1 -SaveConfigFile C:\Lab\MyPlan.json
    Interactive, and also saves your answers so you/others can reuse them.

.EXAMPLE
    .\New-ADLabBuilder.ps1 -ConfigFile C:\Lab\MyPlan.json -NonInteractive
    Silently rebuilds a previously saved plan - useful for classmates who
    want the same structure applied to their own (different) domain.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DomainName      = "",
    [string]$ConfigFile      = "",
    [string]$SaveConfigFile  = "",
    [string]$OUDescription   = "Created by ITKB Consultant",
    [string]$DefaultPassword = "P@ssw0rd123!",
    [string]$RunTag          = "",
    [switch]$NonInteractive
)

# ===========================================================================
# Helper: prompt functions (skipped entirely in -NonInteractive mode)
# ===========================================================================
function Read-HostDefault {
    param([string]$Prompt, [string]$Default)
    if ($NonInteractive) { return $Default }
    $val = Read-Host "$Prompt [default: $Default]"
    if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
    return $val
}

function Read-HostInt {
    param([string]$Prompt, [int]$Default)
    if ($NonInteractive) { return $Default }
    do {
        $val = Read-Host "$Prompt [default: $Default]"
        if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
        if ($val -match '^\d+$') { return [int]$val }
        Write-Host "Please enter a whole number." -ForegroundColor Red
    } while ($true)
}

function Read-HostYesNo {
    param([string]$Prompt, [bool]$DefaultYes = $true)
    if ($NonInteractive) { return $DefaultYes }
    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    $val = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($val)) { return $DefaultYes }
    return $val -match '^[Yy]'
}

function Read-ChildOUType {
    param([string]$ChildName)
    Write-Host "  What should '$ChildName' contain?"
    Write-Host "    1) User accounts"
    Write-Host "    2) Security groups"
    Write-Host "    3) Computer accounts"
    Write-Host "    4) Nothing (just create the empty OU)"
    do {
        $choice = Read-Host "  Select 1-4"
    } while ($choice -notin '1','2','3','4')
    switch ($choice) {
        '1' { return 'Users' }
        '2' { return 'Groups' }
        '3' { return 'Computers' }
        '4' { return 'None' }
    }
}

# ===========================================================================
# 1. Connect to AD - ASK for the target domain explicitly (with retry)
# ===========================================================================
Import-Module ActiveDirectory -ErrorAction Stop

$OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "`nRunning on OS   : $OSCaption" -ForegroundColor Cyan

# Try a silent auto-detect first, purely to offer as a default suggestion -
# this does NOT skip the question, it only pre-fills it.
$SuggestedDomain = $null
try {
    $SuggestedDomain = (Get-ADDomain -ErrorAction Stop).DNSRoot
} catch {
    $SuggestedDomain = $null
}

if ($NonInteractive) {
    if (-not $DomainName) {
        Write-Error "-NonInteractive requires -DomainName (e.g. -DomainName itkb.lab)."
        return
    }
} elseif (-not $DomainName) {
    $DomainName = $SuggestedDomain
}

$Domain = $null
do {
    if (-not $NonInteractive) {
        $PromptDefault = if ($SuggestedDomain) { $SuggestedDomain } else { "itkb.lab" }
        $DomainInput = Read-Host "Enter the domain FQDN to build this hierarchy in [default: $PromptDefault]"
        if ([string]::IsNullOrWhiteSpace($DomainInput)) { $DomainInput = $PromptDefault }
        $DomainName = $DomainInput
    }

    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        Write-Host "Domain name cannot be blank." -ForegroundColor Red
        continue
    }

    Write-Host "Contacting domain '$DomainName' ..." -ForegroundColor DarkGray
    try {
        $Domain = Get-ADDomain -Server $DomainName -ErrorAction Stop
    } catch {
        Write-Host "Could not contact domain '$DomainName': $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Check: the spelling of the domain FQDN, DNS resolution from this machine, and" -ForegroundColor Yellow
        Write-Host "that this machine can reach a Domain Controller for that domain (port 389/445)." -ForegroundColor Yellow
        $Domain = $null
        if ($NonInteractive) {
            Write-Error "Aborting - -NonInteractive mode cannot retry."
            return
        }
    }
} while (-not $Domain)

$DomainDN      = $Domain.DistinguishedName
$DomainDNSRoot = $Domain.DNSRoot
$DomainServer  = $DomainDNSRoot   # passed as -Server to every AD cmdlet below

Write-Host "`n=================================================================="
Write-Host " Connected to domain : $DomainDNSRoot   ($DomainDN)" -ForegroundColor Cyan
Write-Host " Targeting server    : $DomainServer" -ForegroundColor Cyan
Write-Host "==================================================================`n"

if (-not (Read-HostYesNo "Build the OU/object plan against THIS domain?" $true)) {
    Write-Host "Aborted by user. Re-run the script and enter the correct domain FQDN." -ForegroundColor Yellow
    return
}

# ===========================================================================
# 2. Build the Plan: either load from ConfigFile, or gather interactively
# ===========================================================================
$Plan = $null

if ($ConfigFile -and (Test-Path $ConfigFile)) {
    Write-Host "Loading plan from config file: $ConfigFile" -ForegroundColor Green
    try {
        $Plan = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Failed to parse config file '$ConfigFile': $($_.Exception.Message)"
        return
    }
} elseif ($NonInteractive) {
    Write-Error "-NonInteractive requires a valid -ConfigFile."
    return
} else {
    Write-Host "`nNo config file supplied/found - let's build your plan interactively.`n" -ForegroundColor Green

    $ParentOUName = Read-HostDefault "Parent OU name" "IT Lab"
    $DeptCount    = Read-HostInt "How many top-level department OUs do you want under '$ParentOUName'?" 3

    $Departments = @()
    for ($d = 1; $d -le $DeptCount; $d++) {
        Write-Host "`n--- Department $d of $DeptCount ---" -ForegroundColor Magenta
        $DeptName    = Read-HostDefault "  Department OU name" "Dept$d"
        $UseDefaults = Read-HostYesNo   "  Use standard child OUs (Users / Groups / Computers)?" $true

        $ChildOUs = @()

        if ($UseDefaults) {
            $UserCount  = Read-HostInt "    Number of sample users to create in 'Users'"        25
            $GroupCount = Read-HostInt "    Number of sample groups to create in 'Groups'"       5
            $CompCount  = Read-HostInt "    Number of sample computer accounts in 'Computers'"  10

            $ChildOUs += [pscustomobject]@{ Name = "Users";     Type = "Users";     Count = $UserCount }
            $ChildOUs += [pscustomobject]@{ Name = "Groups";    Type = "Groups";    Count = $GroupCount }
            $ChildOUs += [pscustomobject]@{ Name = "Computers"; Type = "Computers"; Count = $CompCount }
        } else {
            $ChildCount = Read-HostInt "    How many child OUs under '$DeptName'?" 3
            for ($c = 1; $c -le $ChildCount; $c++) {
                $ChildName = Read-HostDefault "    Child OU #$c name (e.g. 'Email Servers')" "Child$c"
                $Type      = Read-ChildOUType -ChildName $ChildName
                $Count     = 0
                if ($Type -ne 'None') {
                    $Count = Read-HostInt "      How many $Type to create in '$ChildName'?" 10
                }
                $ChildOUs += [pscustomobject]@{ Name = $ChildName; Type = $Type; Count = $Count }
            }
        }

        $Departments += [pscustomobject]@{ Name = $DeptName; ChildOUs = $ChildOUs }
    }

    if (-not $RunTag)          { $RunTag          = Read-HostDefault "Run tag (suffix for object names, blank is fine)" "" }
    if ($DefaultPassword -eq "P@ssw0rd123!") {
        $DefaultPassword = Read-HostDefault "Password to set on all created user accounts" $DefaultPassword
    }

    $Plan = [pscustomobject]@{
        ParentOUName    = $ParentOUName
        OUDescription   = $OUDescription
        DefaultPassword = $DefaultPassword
        RunTag          = $RunTag
        Departments     = $Departments
    }
}

# Normalize values coming either from JSON or interactive build
$ParentOUName    = $Plan.ParentOUName
$OUDescription   = $Plan.OUDescription
$DefaultPassword = $Plan.DefaultPassword
$RunTag          = $Plan.RunTag
$Departments     = $Plan.Departments
$Suffix          = if ($RunTag) { "-$RunTag" } else { "" }

# ===========================================================================
# 3. Show the full plan and get final confirmation
# ===========================================================================
Write-Host "`n=================== PLAN SUMMARY ===================" -ForegroundColor Green
Write-Host "Domain         : $DomainDNSRoot"
Write-Host "Parent OU      : $ParentOUName"
Write-Host "OU Description : $OUDescription"
Write-Host "Run tag suffix : $(if ($RunTag) { $RunTag } else { '(none)' })"
foreach ($dept in $Departments) {
    Write-Host "`n  Department: $($dept.Name)" -ForegroundColor Cyan
    foreach ($child in $dept.ChildOUs) {
        $desc = if ($child.Type -eq 'None') { "(empty OU)" } else { "$($child.Count) x $($child.Type)" }
        Write-Host "    - $($child.Name)  ->  $desc"
    }
}
Write-Host "======================================================`n" -ForegroundColor Green

if (-not (Read-HostYesNo "Proceed and create all of the above in AD now?" $true)) {
    Write-Host "Aborted by user - nothing was created." -ForegroundColor Yellow
    return
}

if ($SaveConfigFile) {
    try {
        $Plan | ConvertTo-Json -Depth 6 | Set-Content -Path $SaveConfigFile -Encoding UTF8
        Write-Host "Plan saved to: $SaveConfigFile (share this with classmates - it works on any domain)" -ForegroundColor Green
    } catch {
        Write-Warning "Could not save config file to '$SaveConfigFile': $($_.Exception.Message)"
    }
}

# ===========================================================================
# 4. Helper functions to create OUs and populate objects
# ===========================================================================
$SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
$ObjectsCreated = 0

$FirstNames = @("James","Mary","John","Patricia","Robert","Jennifer","Michael","Linda",
                "William","Elizabeth","David","Barbara","Richard","Susan","Joseph","Jessica",
                "Thomas","Sarah","Charles","Karen","Ahmed","Sara","Ali","Ayesha","Bilal",
                "Sana","Usman","Hina","Omar","Zainab")
$LastNames  = @("Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis",
                "Rodriguez","Martinez","Khan","Ahmed","Malik","Butt","Chaudhry","Raza",
                "Iqbal","Sheikh","Qureshi","Baig")
$GroupTypes = @("Managers","Staff","TeamLeads","ReadOnly","FullAccess")

function Get-OrNew-OU {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ParentPath)
    $existing = Get-ADOrganizationalUnit -Server $script:DomainServer -SearchBase $ParentPath -SearchScope OneLevel `
        -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ADOrganizationalUnit -Server $script:DomainServer -Name $Name -Path $ParentPath `
            -Description $OUDescription -ProtectedFromAccidentalDeletion $true | Out-Null
        Write-Host "  [OU created]  OU=$Name,$ParentPath" -ForegroundColor Green
    } else {
        Write-Host "  [OU exists ]  OU=$Name,$ParentPath" -ForegroundColor DarkYellow
    }
    return "OU=$Name,$ParentPath"
}

function New-SampleUsers {
    param([string]$Path, [string]$DeptName, [int]$Count)
    for ($i = 1; $i -le $Count; $i++) {
        $First = Get-Random -InputObject $FirstNames
        $Last  = Get-Random -InputObject $LastNames
        $Sam   = ("{0}.{1}{2}{3}" -f $First.Substring(0,1), $Last, $i, $Suffix).ToLower()
        $Sam   = ($Sam -replace '[^a-z0-9.\-]', '')
        $Sam   = $Sam.Substring(0, [Math]::Min(20, $Sam.Length))
        $UPN   = "$Sam@$DomainDNSRoot"
        if (-not (Get-ADUser -Server $script:DomainServer -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue)) {
            try {
                New-ADUser -Server $script:DomainServer -Name "$First $Last $i$Suffix" `
                    -GivenName $First -Surname $Last `
                    -SamAccountName $Sam -UserPrincipalName $UPN `
                    -Path $Path -AccountPassword $script:SecurePassword `
                    -Enabled $true -ChangePasswordAtLogon $false `
                    -Department $DeptName -Description "$DeptName department user - $OUDescription" `
                    -ErrorAction Stop | Out-Null
                $script:ObjectsCreated++
            } catch {
                Write-Warning "User '$Sam' failed: $($_.Exception.Message)"
            }
        }
    }
}

function New-SampleGroups {
    param([string]$Path, [string]$DeptName, [int]$Count)
    for ($i = 1; $i -le $Count; $i++) {
        $GType = $GroupTypes[($i - 1) % $GroupTypes.Count]
        $GName = "$DeptName-$GType-$i$Suffix"
        if (-not (Get-ADGroup -Server $script:DomainServer -Filter "Name -eq '$GName'" -ErrorAction SilentlyContinue)) {
            try {
                New-ADGroup -Server $script:DomainServer -Name $GName -GroupScope Global -GroupCategory Security `
                    -Path $Path -Description "$DeptName group - $OUDescription" `
                    -ErrorAction Stop | Out-Null
                $script:ObjectsCreated++
            } catch {
                Write-Warning "Group '$GName' failed: $($_.Exception.Message)"
            }
        }
    }
}

function New-SampleComputers {
    param([string]$Path, [string]$DeptName, [int]$Count)
    $CleanDept = ($DeptName -replace '[^A-Za-z]', '')
    if ($CleanDept.Length -eq 0) { $CleanDept = "PC" }
    $Prefix = $CleanDept.Substring(0, [Math]::Min(3, $CleanDept.Length)).ToUpper()
    for ($i = 1; $i -le $Count; $i++) {
        $CName = ("{0}WK{1:D3}{2}" -f $Prefix, $i, $Suffix)
        $CName = ($CName -replace '[^A-Za-z0-9\-]', '')
        $CName = $CName.Substring(0, [Math]::Min(15, $CName.Length))
        if (-not (Get-ADComputer -Server $script:DomainServer -Filter "Name -eq '$CName'" -ErrorAction SilentlyContinue)) {
            try {
                New-ADComputer -Server $script:DomainServer -Name $CName -Path $Path `
                    -Description "$DeptName computer - $OUDescription" `
                    -Enabled $true -ErrorAction Stop | Out-Null
                $script:ObjectsCreated++
            } catch {
                Write-Warning "Computer '$CName' failed: $($_.Exception.Message)"
            }
        }
    }
}

# ===========================================================================
# 5. Execute the plan
# ===========================================================================
Write-Host "`n=== Creating parent OU ===" -ForegroundColor Magenta
$ParentOUPath = Get-OrNew-OU -Name $ParentOUName -ParentPath $DomainDN

foreach ($dept in $Departments) {
    Write-Host "`n=== Department: $($dept.Name) ===" -ForegroundColor Magenta
    $DeptOUPath = Get-OrNew-OU -Name $dept.Name -ParentPath $ParentOUPath

    foreach ($child in $dept.ChildOUs) {
        $ChildOUPath = Get-OrNew-OU -Name $child.Name -ParentPath $DeptOUPath

        switch ($child.Type) {
            "Users"     { New-SampleUsers     -Path $ChildOUPath -DeptName $dept.Name -Count $child.Count
                          Write-Host "  -> $($child.Count) user(s) processed in $($dept.Name)/$($child.Name)" -ForegroundColor Cyan }
            "Groups"    { New-SampleGroups    -Path $ChildOUPath -DeptName $dept.Name -Count $child.Count
                          Write-Host "  -> $($child.Count) group(s) processed in $($dept.Name)/$($child.Name)" -ForegroundColor Cyan }
            "Computers" { New-SampleComputers -Path $ChildOUPath -DeptName $dept.Name -Count $child.Count
                          Write-Host "  -> $($child.Count) computer account(s) processed in $($dept.Name)/$($child.Name)" -ForegroundColor Cyan }
            "None"      { Write-Host "  -> OU only, no objects requested for $($dept.Name)/$($child.Name)" -ForegroundColor DarkGray }
        }
    }
}

# ===========================================================================
# 6. Summary + ntds.dit size check
# ===========================================================================
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
    }
} catch {
    Write-Warning "Could not read ntds.dit size automatically (registry path not found). Check %SystemRoot%\NTDS manually."
}

Write-Host "===========================================" -ForegroundColor Green
