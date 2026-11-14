$ErrorActionPreference = 'Stop'
$targetNames = @('Microsoft.MicrosoftEdge.Stable', 'Microsoft.MicrosoftEdge', 'Microsoft.Edge.GameAssist')
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
function Get-TargetPackages {
    @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $targetNames -contains $_.Name })
}
function Get-TargetProvisioned {
    @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object {
        $packageName = [string]$_.PackageName
        $baseName = if ($packageName.Contains('_')) { $packageName.Substring(0, $packageName.IndexOf('_')) } else { $packageName }
        $targetNames -contains $baseName -or $targetNames -contains ([string]$_.DisplayName)
    })
}
function Get-InstalledUsers($package) {
    foreach ($user in @($package.PackageUserInformation)) {
        $sid = [string]$user.UserSecurityId.Sid
        $state = [string]$user.InstallState
        if ($state -match '^(Installed|Staged)' -and $sid -match '^S-1-\d+(-\d+)+$') {
            $user
        }
    }
}
function Invoke-UserRemoval($package) {
    $fullName = [string]$package.PackageFullName
    foreach ($user in @(Get-InstalledUsers $package)) {
        $sid = [string]$user.UserSecurityId.Sid
        try {
            Remove-AppxPackage -Package $fullName -User $sid -ErrorAction Stop
            Write-Output ('User removal requested: ' + $fullName + '; User=' + $sid)
        } catch {
            Write-Output ('User removal failed: ' + $fullName + '; User=' + $sid + '; ' + $_.Exception.Message)
        }
    }
}
function Remove-RegisteredPackage($package, [switch]$Retry) {
    $fullName = [string]$package.PackageFullName
    $createdMarkers = @()
    try {
        if ($Retry) {
            if ($package.NonRemovable -and (Get-Command Set-NonRemovableAppsPolicy -ErrorAction SilentlyContinue)) {
                Set-NonRemovableAppsPolicy -Online -PackageFamilyName $package.PackageFamilyName -NonRemovable 0 -ErrorAction Stop | Out-Null
            }
            foreach ($user in @(Get-InstalledUsers $package)) {
                $sid = [string]$user.UserSecurityId.Sid
                $marker = Join-Path (Join-Path (Join-Path $store 'EndOfLife') $sid) $fullName
                if (-not (Test-Path -LiteralPath $marker)) {
                    New-Item -Path $marker -Force -ErrorAction Stop | Out-Null
                    $createdMarkers += $marker
                }
            }
            [void](Invoke-UserRemoval $package)
        }
        $allUsersFailed = $false
        try {
            Remove-AppxPackage -Package $fullName -AllUsers -ErrorAction Stop
            Write-Output ('All-users removal requested: ' + $fullName + '; Retry=' + $Retry)
        } catch {
            $allUsersFailed = $true
            Write-Output ('All-users removal failed: ' + $fullName + '; Retry=' + $Retry + '; ' + $_.Exception.Message)
        }
        if ($allUsersFailed -and -not $Retry) {
            foreach ($fresh in @(Get-TargetPackages | Where-Object { $_.PackageFullName -eq $fullName })) {
                [void](Invoke-UserRemoval $fresh)
            }
        }
        if ($Retry) {
            foreach ($fresh in @(Get-TargetPackages | Where-Object { $_.PackageFullName -eq $fullName })) {
                [void](Invoke-UserRemoval $fresh)
            }
            try {
                Remove-AppxPackage -Package $fullName -AllUsers -ErrorAction Stop
                Write-Output ('Second all-users removal requested: ' + $fullName)
            } catch {
                Write-Output ('Second all-users removal failed: ' + $fullName + '; ' + $_.Exception.Message)
            }
        }
    } catch {
        Write-Output ('Removal failed: ' + $fullName + '; Retry=' + $Retry + '; ' + $_.Exception.Message)
    } finally {
        $remainingAfter = @()
        $stateUnknown = $false
        try {
            $remainingAfter = @(Get-TargetPackages | Where-Object { $_.PackageFullName -eq $fullName })
        } catch {
            $stateUnknown = $true
            Write-Output ('Remaining state could not be read: ' + $fullName + '; ' + $_.Exception.Message)
        }
        foreach ($marker in $createdMarkers) {
            if (($Retry -and $remainingAfter.Count -gt 0) -or $stateUnknown) {
                Write-Output ('EndOfLife marker retained: ' + $marker)
                continue
            }
            Remove-Item -LiteralPath $marker -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
}
$provisioned = @()
try {
    $provisioned = @(Get-TargetProvisioned)
} catch {
    Write-Output ('Provisioned package query failed: ' + $_.Exception.Message)
}
foreach ($package in $provisioned) {
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop | Out-Null
        Write-Output ('Deprovisioned: ' + $package.PackageName)
    } catch {
        Write-Output ('Deprovisioning failed: ' + $package.PackageName + '; ' + $_.Exception.Message)
    }
}
foreach ($package in @(Get-TargetPackages)) {
    [void](Remove-RegisteredPackage $package)
}
foreach ($package in @(Get-TargetPackages)) {
    [void](Remove-RegisteredPackage $package -Retry)
}
$provisioned = @()
try {
    $provisioned = @(Get-TargetProvisioned)
} catch {
    Write-Output ('Final provisioned package query failed: ' + $_.Exception.Message)
}
foreach ($package in $provisioned) {
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop | Out-Null
    } catch {
        Write-Output ('Final deprovisioning failed: ' + $package.PackageName + '; ' + $_.Exception.Message)
    }
}
try {
    $remaining = @(Get-TargetPackages)
    $provisionedRemaining = @(Get-TargetProvisioned)
} catch {
    Write-Error ('Edge AppX state verification failed: ' + $_.Exception.Message)
    exit 1
}
if ($remaining.Count -gt 0 -or $provisionedRemaining.Count -gt 0) {
    $details = @($remaining | ForEach-Object { $_.PackageFullName }) +
        @($provisionedRemaining | ForEach-Object { $_.PackageName })
    Write-Error ('Edge AppX packages remain: ' + ($details -join '; '))
    exit 1
}
Write-Output 'Edge and Game Assist AppX removal verified.'

