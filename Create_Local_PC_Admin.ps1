# ============================================================
# Script     : Secure Local Admin Account Replacement
# Purpose    : Removes/disables specified legacy local admin
#              accounts and creates a new local admin account
#              as part of security best practices.
#
# Author     : Nadeem Muhammad Ali Meer
# Contact    : Call/WhatsApp +92 341 2966104
# Email      : nadeemali.gio@gmail.com
# ============================================================

# Requires: run this script as Administrator

# ============================
# Legacy accounts to remove
# Add/remove names in this list as needed
# ============================
$AccountsToRemove = @(
    "Administrator"
    # "Admin"
    # "Admin123"
    # "PCadmin"
)

# ============================
# New account parameters
# ============================
$Name        = "itkblocalpcadmin"
$Password    = "itkbLab@2026!Net"
$Description = "Local PC admin account"

# Check for elevation
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$SecureString = ConvertTo-SecureString -String $Password -AsPlainText -Force

try {
    # ============================
    # Remove legacy accounts
    # ============================
    foreach ($OldName in $AccountsToRemove) {
        if (Get-LocalUser -Name $OldName -ErrorAction SilentlyContinue) {
            Write-Warning "Legacy account '$OldName' found. Removing it."
            Remove-LocalUser -Name $OldName -ErrorAction Stop -Verbose
        } else {
            Write-Host "Legacy account '$OldName' not found. Nothing to remove."
        }
    }

    # ============================
    # Create new account
    # ============================
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
        Write-Warning "User '$Name' already exists. Skipping creation."
    } else {
        $NewUserSwitches = @{
            Name                 = $Name
            Password             = $SecureString
            AccountNeverExpires  = $true
            PasswordNeverExpires = $true
            Description          = $Description
        }
        New-LocalUser @NewUserSwitches -Verbose -ErrorAction Stop
    }

    # Use the well-known SID for Administrators (S-1-5-32-544) - avoids locale issues
    $AdminGroup = Get-LocalGroup -SID "S-1-5-32-544"

    if (Get-LocalGroupMember -Group $AdminGroup -Member $Name -ErrorAction SilentlyContinue) {
        Write-Warning "'$Name' is already a member of $($AdminGroup.Name)."
    } else {
        Add-LocalGroupMember -Group $AdminGroup -Member $Name -ErrorAction Stop -Verbose
    }

    Write-Host "Done. Legacy accounts processed and '$Name' is set up in the local Administrators group." -ForegroundColor Green
}
catch {
    Write-Error "Failed: $_"
}
