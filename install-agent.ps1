<#  WALLACE Agent installer - NOT run automatically. Brandon runs this himself when ready.
    -Mode UserTask : per-user logon task (no admin/UAC). Everything works except hotspot-device pause (WFP) and restart-AdGuard.
    -Mode Service  : Windows service as LocalSystem (needs ONE elevated PowerShell). Enables WFP pause for hotspot devices.
    -Uninstall     : removes the task/service (files are left in place).
    The agent binds only to 192.168.1.x / Tailscale 100.x on port 8088. Never port-forward 8088 on the router. #>
param([ValidateSet('UserTask','Service')][string]$Mode = 'UserTask', [switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'publish'
$dst = 'C:\Program Files\WALLACE Agent'; if ($Mode -eq 'UserTask') { $dst = "$env:LOCALAPPDATA\Programs\WALLACE Agent" }
$exe = Join-Path $dst 'WallaceAgent.exe'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Uninstall) {
  if ($Mode -eq 'Service') { if (-not $isAdmin) { throw 'Run from an elevated PowerShell.' }; Stop-Service 'WALLACE Agent' -EA SilentlyContinue; sc.exe delete "WALLACE Agent" | Out-Null }
  else { Unregister-ScheduledTask -TaskName 'WALLACE Agent' -Confirm:$false -EA SilentlyContinue; Get-Process WallaceAgent -EA SilentlyContinue | Stop-Process }
  "Removed $Mode. Files left in $dst"; return
}
if (-not (Test-Path "$src\WallaceAgent.exe")) { throw "Build first: dotnet publish src\WallaceAgent.csproj -c Release -o publish" }
if ($Mode -eq 'Service' -and -not $isAdmin) { throw 'Service mode: open PowerShell as administrator and run this again.' }
Get-Process WallaceAgent -EA SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force $dst | Out-Null
Copy-Item "$src\*" $dst -Recurse -Force

if ($Mode -eq 'UserTask') {
  $a = New-ScheduledTaskAction -Execute $exe
  $t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName 'WALLACE Agent' -Action $a -Trigger $t -Settings $s -Description 'WALLACE Admin phone API (port 8088, LAN/Tailscale only)' -Force | Out-Null
  Start-ScheduledTask -TaskName 'WALLACE Agent'
} else {
  if (Get-Service 'WALLACE Agent' -EA SilentlyContinue) { Stop-Service 'WALLACE Agent'; sc.exe delete "WALLACE Agent" | Out-Null; Start-Sleep 2 }
  New-Service -Name 'WALLACE Agent' -BinaryPathName "`"$exe`"" -DisplayName 'WALLACE Agent' -StartupType Automatic -Description 'WALLACE Admin phone API (port 8088, LAN/Tailscale only)' | Out-Null
  sc.exe failure "WALLACE Agent" reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
  # Data folder: only SYSTEM, Administrators and Brandon
  $d = 'C:\ProgramData\WALLACE Agent'; New-Item -ItemType Directory -Force $d | Out-Null
  icacls $d /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "$($env:USERNAME):(OI)(CI)M" | Out-Null
  Start-Service 'WALLACE Agent'
}
# Firewall: the existing 'Local AI PWA 8088' rule (Private) already allows TCP 8088. Add a scoped one if it is missing.
if (-not (Get-NetFirewallRule -DisplayName 'WALLACE Agent 8088' -EA SilentlyContinue) -and $isAdmin) {
  New-NetFirewallRule -DisplayName 'WALLACE Agent 8088' -Direction Inbound -Protocol TCP -LocalPort 8088 -Profile Private -RemoteAddress 192.0.2.20/24,192.0.2.22/10 -Action Allow | Out-Null }
Start-Sleep 3
try { Invoke-RestMethod "http://$((Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -like '192.168.1.*' | select -First 1).IPAddress):8088/v1/ping" -TimeoutSec 5 } catch { "ping failed: $($_.Exception.Message)" }
"Installed ($Mode). Pair the phone: & '$exe' --pair"
