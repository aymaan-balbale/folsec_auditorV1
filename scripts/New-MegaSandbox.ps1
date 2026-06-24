requires -RunAsAdministrator

$SandboxRoot = "C:\FolSec_Mega_Sandbox"

Write-Host "Cleaning up old sandbox if it exists..." -ForegroundColor Cyan
if (Test-Path $SandboxRoot) {
    Remove-Item $SandboxRoot -Recurse -Force
}

Write-Host "Creating 50+ nested directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $SandboxRoot | Out-Null

# Create a realistic corporate folder structure (100 folders total)
$departments = @("Engineering", "HR", "Finance", "Legal", "Marketing")
$projects = @("Project_Alpha", "Project_Beta", "Top_Secret", "Q3_Reports")
$subfolders = @("Drafts", "Final", "Approvals", "Archives", "Raw_Data")

$allPaths = @()

foreach ($dept in $departments) {
    $deptPath = Join-Path $SandboxRoot $dept
    New-Item -ItemType Directory -Path $deptPath | Out-Null
    $allPaths += $deptPath

    foreach ($proj in $projects) {
        $projPath = Join-Path $deptPath $proj
        New-Item -ItemType Directory -Path $projPath | Out-Null
        $allPaths += $projPath

        foreach ($sub in $subfolders) {
            $subPath = Join-Path $projPath $sub
            New-Item -ItemType Directory -Path $subPath | Out-Null
            $allPaths += $subPath
        }
    }
}

Write-Host "Total folders created: $($allPaths.Count)" -ForegroundColor Green
Write-Host "Injecting vulnerabilities randomly..." -ForegroundColor Cyan

foreach ($folder in $allPaths) {
    $acl = Get-Acl -Path $folder
    $modified = $false

    # 1. Inject Broken Inheritance (~20% chance)
    if ((Get-Random -Minimum 1 -Maximum 100) -le 20) {
        $acl.SetAccessRuleProtection($true, $true)
        $modified = $true
        Write-Host "  [+] Broken Inheritance: $folder" -ForegroundColor DarkGray
    }

    # 2. Inject Over-Permissive ACEs (~20% chance)
    if ((Get-Random -Minimum 1 -Maximum 100) -le 20) {
        $target = if ((Get-Random) % 2 -eq 0) { "Everyone" } else { "Authenticated Users" }
        $rights = if ((Get-Random) % 2 -eq 0) { "FullControl" } else { "Modify" }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($target, $rights, "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        $modified = $true
        Write-Host "  [+] Over-Permissive ($target $rights): $folder" -ForegroundColor DarkGray
    }

    # 3. Inject Orphaned SIDs (~15% chance)
    if ((Get-Random -Minimum 1 -Maximum 100) -le 15) {
        $fakeSidString = "S-1-5-21-$((Get-Random -Min 100000000 -Max 999999999))-$((Get-Random -Min 100000000 -Max 999999999))-$((Get-Random -Min 100000000 -Max 999999999))-$((Get-Random -Min 1000 -Max 9999))"
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($fakeSidString)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($rule)
            $modified = $true
            Write-Host "  [+] Orphaned SID ($fakeSidString): $folder" -ForegroundColor DarkGray
        } catch {}
    }

    # Apply changes if any were made
    if ($modified) {
        Set-Acl -Path $folder -AclObject $acl
    }
}

Write-Host "`nMega Sandbox generation complete!" -ForegroundColor Green