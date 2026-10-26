# Generates 1102, 4625 and 7045 events, then exports the logs to .evtx files.
#
# RUN ONLY INSIDE A THROWAWAY WINDOWS VM. It clears the Security log and installs a fake service.
# Run from an elevated (Administrator) PowerShell:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\generate_test_events.ps1

$ErrorActionPreference = "Continue"
$out = Join-Path $PSScriptRoot "..\samples"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Make sure failed logons get audited (off by default on some editions)
auditpol /set /subcategory:"Logon" /failure:enable | Out-Null

# 1102: clear the Security log first, so the clear event is the first record
Write-Host "Clearing Security log (1102)..."
wevtutil cl Security

# 4625 brute force: one account, many failures
Write-Host "Generating brute force (4625)..."
1..15 | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:administrator "wrong$_" 2>$null | Out-Null
}

# 4625 password spray: one password, many accounts
Write-Host "Generating password spray (4625)..."
"alice","bob","carol","dave","erin","frank","grace" | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:$_ "Summer2026!" 2>$null | Out-Null
}
net use \\127.0.0.1\IPC$ /delete 2>$null | Out-Null

# 7045: one boring service and one that looks like persistence
Write-Host "Installing test services (7045)..."
sc.exe create TriageBenign binPath= "C:\Windows\System32\svchost.exe -k netsvcs" | Out-Null
sc.exe create WinUpdateHelper binPath= "C:\Users\Public\updater.exe" | Out-Null
sc.exe delete TriageBenign | Out-Null
sc.exe delete WinUpdateHelper | Out-Null

Start-Sleep -Seconds 2
wevtutil epl Security (Join-Path $out "Security.evtx") /ow:true
wevtutil epl System   (Join-Path $out "System.evtx")   /ow:true
Write-Host "Done. Exported to $out"
