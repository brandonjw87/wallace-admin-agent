# Wallace Network Health probe - READ ONLY. Never reads or prints secret files.
$ErrorActionPreference = 'SilentlyContinue'
$T = 'C:\Users\YOU\Tools'; $V2 = "$T\wallace-roku-v2"
$out = New-Object System.Collections.ArrayList
function Add($layer, $name, $status, $detail, $explain) { [void]$out.Add([ordered]@{ Layer = $layer; Name = $name; Status = $status; Detail = [string]$detail; Explain = $explain }) }
function Red($s) { $s -replace '(?i)(pass\w*|secret\w*|private_key|token|psk)\s*[:=]\s*\S+', '$1=<redacted>' }
$explain = @{
 'Internet'='Can this PC reach the internet at all (Cloudflare/Quad9/Google)?'
 'ActiveUplink'='Which cable/wireless link carries internet. Ethernet is main; Wi-Fi is the backup.'
 'LanIp'='This PC''s address on your home router (.229 on Ethernet, .210 on Wi-Fi).'
 'Tethering'='The WALLACE hotspot that the TVs connect to.'
 'Ssid'='The hotspot network name is correct.'
 'HotspotIp'='The hotspot gateway address 192.0.2.11 exists.'
 'HotspotUplink'='The hotspot is sharing the same link that has internet.'
 'IcsDhcp67'='Windows hands out addresses to hotspot devices.'
 'Dns127:resolve'='AdGuard answers normal websites.'
 'Dns127:block'='AdGuard blocks ad sites (doubleclick.net test).'
 'DnsHotspot:resolve'='Hotspot devices get working DNS.'
 'DnsHotspot:block'='Hotspot devices get ads blocked.'
 'UplinkDnsLoopback'='This PC uses AdGuard (127.0.0.1) for its own DNS.'
 'DhcpIniIp'='Open DHCP Server config has no stale IP.'
}
# 1) Reuse the tested WALLACE health engine
if (Test-Path "$V2\lib.ps1") {
  try {
    . "$V2\lib.ps1"; $C = Get-WRConfig; $h = Get-WRHealth -Config $C -IncludeApps
    foreach ($c in $h.Checks) {
      $st = if ($c.Ok) { 'Green' } elseif ($c.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
      $ex = $explain[$c.Name]; if (-not $ex) { $ex = "Check from the WALLACE watchdog engine ($($c.Component))." }
      Add $c.Component $c.Name $st (Red $c.Detail) $ex
    }
    $cl = @($h.Tethering.Clients)
    Add 'Hotspot' 'Clients' $(if ($cl.Count) { 'Green' } else { 'Yellow' }) (($cl | % { "$($_.Names) [$($_.Mac)]" }) -join '; ') 'Devices connected to the WALLACE hotspot right now.'
    $rk = @($cl | ? { $_.Names -match '(?i)roku' })
    Add 'Devices' 'Roku on hotspot' $(if ($rk.Count) { 'Green' } else { 'Yellow' }) $(if ($rk.Count) { ($rk | % { $_.Names }) -join '; ' } else { 'no Roku seen on 192.168.137.x' }) 'Roku TVs/sticks connected to the hotspot (ads filtered by AdGuard).'
  } catch { Add 'Engine' 'lib.ps1' 'Red' $_.Exception.Message 'The WALLACE health engine failed to run.' }
} else { Add 'Engine' 'lib.ps1' 'Red' "missing $V2\lib.ps1" 'WALLACE hotspot scripts not found.' }
# 2) Ports
$listen = @(Get-NetTCPConnection -State Listen)
foreach ($p in @(@{P=53;N='AdGuard DNS'},@{P=3000;N='AdGuard web'},@{P=3001;N='Uptime Kuma'})) {
  $l = @($listen | ? LocalPort -eq $p.P); $u = if ($p.P -eq 53) { @(Get-NetUDPEndpoint -LocalPort 53 | ? { (Get-Process -Id $_.OwningProcess).Name -eq 'AdGuardHome' }) } else { @() }
  $addr = (($l + $u) | % { "$($_.LocalAddress) ($((Get-Process -Id $_.OwningProcess).Name))" } | Select -Unique) -join ', '
  Add 'Ports' "Port $($p.P)" $(if ($l.Count -or $u.Count) { 'Green' } else { 'Red' }) $(if ($addr) { "listening on $addr" } else { 'NOT listening' }) "$($p.N) must be listening. 0.0.0.0/:: means all adapters - firewall limits it to LAN+hotspot."
}
# 3) Services & apps
foreach ($s in 'AdGuardHome','OpenDHCPServer','SharedAccess','icssvc') { $sv = Get-Service $s; Add 'Services' $s $(if ($sv.Status -eq 'Running') { 'Green' } elseif ($sv) { 'Red' } else { 'Yellow' }) $(if ($sv) { "$($sv.Status) / $($sv.StartType)" } else { 'not installed' }) 'Windows background service needed by the network layers.' }
$sb = Get-Process iSponsorBlockTV
Add 'Apps' 'iSponsorBlockTV' $(if ($sb) { 'Green' } else { 'Red' }) $(if ($sb) { "running since $($sb[0].StartTime)" } else { 'not running' }) 'Skips YouTube sponsor segments/ads on the Roku.'
try { $k = Invoke-WebRequest 'http://127.0.0.1:3001' -UseBasicParsing -TimeoutSec 5; $ks = $k.StatusCode } catch { $ks = 0 }
Add 'Apps' 'Uptime Kuma' $(if ($ks -ge 200 -and $ks -lt 400) { 'Green' } else { 'Red' }) "http 127.0.0.1:3001 -> $ks" 'Your uptime monitor web dashboard.'
$tvIp = '192.0.2.21'; $tj = Get-Content "$T\lgtv\tv.js" -Raw; if ($tj -match "TV_IP\|\|'([\d\.]+)'") { $tvIp = $Matches[1] }
$tv = Test-Connection $tvIp -Count 1 -Quiet
Add 'Devices' 'LG TV' $(if ($tv) { 'Green' } else { 'Yellow' }) "$tvIp ping=$tv" 'LG TV control target (Tools\lgtv). Yellow is normal when the TV is off.'
# 4) Startup items & tasks
$st = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
foreach ($n in 'start-hotspot.cmd','UptimeKuma.lnk','iSponsorBlockTV.lnk') { $e = Test-Path "$st\$n"; Add 'Startup' $n $(if ($e) { 'Green' } else { 'Yellow' }) $(if ($e) { 'present' } else { 'missing' }) 'Starts this layer automatically when you sign in.' }
foreach ($tn in 'WALLACE Watchdog') { $tk = Get-ScheduledTask -TaskName $tn; $ti = Get-ScheduledTaskInfo -TaskName $tn
  Add 'Watchdogs' $tn $(if ($tk -and $tk.State -ne 'Disabled' -and $ti.LastTaskResult -eq 0) { 'Green' } elseif ($tk) { 'Yellow' } else { 'Red' }) $(if ($tk) { "$($tk.State), last run $($ti.LastRunTime), result $($ti.LastTaskResult)" } else { 'task missing' }) 'Scheduled self-repair task.' }
foreach ($f in @(@{P="$V2\logs\status.json";N='Watchdog status.json';M=15})) {
  $i = Get-Item $f.P; $age = if ($i) { [int]((Get-Date) - $i.LastWriteTime).TotalMinutes } else { -1 }
  Add 'Watchdogs' $f.N $(if ($age -ge 0 -and $age -le $f.M) { 'Green' } elseif ($age -ge 0) { 'Yellow' } else { 'Red' }) $(if ($age -ge 0) { "updated $age min ago" } else { 'missing' }) "Proves the watchdog ran recently (expected within $($f.M) min)." }
# 5) Firewall
$fw = @(Get-NetFirewallRule -Group 'Wallace-Roku v2' -Enabled True) + @(Get-NetFirewallRule -Group 'WR2 UptimeKuma' -Enabled True)
Add 'Firewall' 'WR2 rules' $(if ($fw.Count -ge 3) { 'Green' } else { 'Yellow' }) "$($fw.Count) enabled rules (DNS/3000/3001), scoped to LAN+hotspot" 'Lets your LAN and hotspot reach the services, nobody else.'
$hd = @(Get-NetFirewallRule -Group 'WR2 Block HardcodedDNS' -Enabled True).Count
Add 'Firewall' 'Block hard-coded DNS' $(if ($hd) { 'Green' } else { 'Yellow' }) "$hd rules enabled" 'Stops devices bypassing AdGuard with their own DNS servers.'
# 6) PC
$d = Get-PSDrive C; $fg = [math]::Round($d.Free/1GB,1); Add 'PC' 'Disk C:' $(if ($fg -gt 30) { 'Green' } elseif ($fg -gt 10) { 'Yellow' } else { 'Red' }) "$fg GB free" 'Free space on the main drive.'
$os = Get-CimInstance Win32_OperatingSystem; $ram = [math]::Round(100 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100)
$cpu = [int](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
Add 'PC' 'CPU / RAM' $(if ($cpu -lt 85 -and $ram -lt 90) { 'Green' } else { 'Yellow' }) "CPU $cpu% / RAM $ram% used" 'How busy the PC is.'
$tz = Get-CimInstance -Namespace root/wmi MSAcpi_ThermalZoneTemperature
if ($tz) { $c = [math]::Round(($tz | Measure-Object CurrentTemperature -Maximum).Maximum / 10 - 273.15); Add 'PC' 'Temperature' $(if ($c -lt 85) { 'Green' } else { 'Yellow' }) "$c C (ACPI zone)" 'Board temperature from Windows.' }
else { Add 'PC' 'Temperature' 'Gray' 'not available without admin' 'Windows only exposes temperatures to admin tools.' }
$out | ConvertTo-Json -Depth 4 -Compress
