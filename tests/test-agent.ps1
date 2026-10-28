# End-to-end test of a running WALLACE Agent. Never prints the token or pairing code.
param([string]$Base = "http://192.0.2.13:8088", [switch]$Writes, [switch]$WindowsUpdate)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '..\publish\WallaceAgent.exe'
$pass = 0; $fail = 0
function T($name, $ok, $info = '') { if ($ok) { $script:pass++; "PASS $name $info" } else { $script:fail++; "FAIL $name $info" } }
function Call($m, $p, $body = $null, $tok = $script:tok) {
  $h = @{}; if ($tok) { $h.Authorization = "Bearer $tok" }
  $a = @{ Method = $m; Uri = "$Base$p"; Headers = $h; TimeoutSec = 300; UseBasicParsing = $true }
  if ($body -ne $null) { $a.Body = ($body | ConvertTo-Json -Compress -Depth 5); $a.ContentType = 'application/json' }
  try { $r = Invoke-WebRequest @a; [pscustomobject]@{ code = [int]$r.StatusCode; json = ($r.Content | ConvertFrom-Json) } }
  catch { $c = 0; $j = $null; if ($_.Exception.Response) { $c = [int]$_.Exception.Response.StatusCode; try { $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream()); $j = $sr.ReadToEnd() | ConvertFrom-Json } catch {} }; [pscustomobject]@{ code = $c; json = $j } }
}
$cf = Join-Path $env:TEMP ("wa-" + [guid]::NewGuid().ToString('N'))
& $exe --pair "test-harness" --no-open --code-out $cf | Out-Null
$code = ([IO.File]::ReadAllText($cf)).Trim(); Remove-Item $cf
$r = Call POST /v1/pair @{ code = $code; deviceName = 'test-harness' } $null
T 'pair' ($r.code -eq 200 -and $r.json.token.Length -ge 40)
$script:tok = $r.json.token; $tid = $r.json.tokenId
T 'pair code single-use' ((Call POST /v1/pair @{ code = $code } $null).code -eq 401)
T 'bad token 401' ((Call GET /v1/status $null 'nope-nope').code -eq 401)

$s = Call GET /v1/status; T 'status' ($s.code -eq 200 -and $s.json.adguard.reachable) ("AdGuard $($s.json.adguard.version), lists $($s.json.adguard.listsEnabled), rules $($s.json.adguard.listRules), user rules $($s.json.adguard.userRules), msgFirst=$($s.json.adguard.messagingBlockFirst), hotspot=$($s.json.hotspot.state) clients=$($s.json.hotspot.clients)")
T 'messaging block first in AdGuard' ($s.json.adguard.messagingBlockFirst)
foreach ($p in '/v1/session','/v1/hotspot','/v1/monitors','/v1/kuma','/v1/alerts','/v1/health','/v1/logs/watchdog','/v1/logs/agent','/v1/custom-rules') { $x = Call GET $p; T "GET $p" ($x.code -eq 200) }
$x = Call GET /v1/stats; T 'stats' ($x.code -eq 200) ("queries=$($x.json.num_dns_queries) blocked=$($x.json.num_blocked_filtering)")
$x = Call GET '/v1/querylog?limit=20'; T 'querylog' ($x.code -eq 200 -and $x.json.entries.Count -gt 0) ("$($x.json.entries.Count) entries")
$x = Call GET '/v1/querylog?limit=10&status=blocked'; T 'querylog blocked' ($x.code -eq 200) ("$($x.json.entries.Count) entries")
$x = Call GET /v1/blocklists; T 'blocklists' ($x.code -eq 200 -and $x.json.lists.Count -gt 0) ("$($x.json.lists.Count) lists")
$sg = Call GET /v1/safeguard; T 'safeguard' ($sg.code -eq 200) ("adult=$($sg.json.adult) insta=$($sg.json.instagram) safe=$($sg.json.safeSearch) ytRestricted=$($sg.json.youtubeRestricted) exemptRokus=$($sg.json.exemptRokus) blocked24h=$($sg.json.blocked24h)")
T 'youtube restricted is off' (-not $sg.json.youtubeRestricted)
$x = Call GET '/v1/reports/blocked?hours=24'; T 'report 24h' ($x.code -eq 200) ("total=$($x.json.total)")
$x = Call POST /v1/check-host @{ host = 'doubleclick.net' }; T 'check-host doubleclick' ($x.code -eq 200) ("reason=$($x.json.reason)")
$x = Call POST /v1/check-host @{ host = 'instantmessaging-pa.googleapis.com' }; T 'check-host messaging not filtered' ($x.code -eq 200 -and -not $x.json.blocked) ("reason=$($x.json.reason)")
$x = Call GET /v1/updates; T 'updates (read-only)' ($x.code -eq 200 -and $x.json.readOnly) (($x.json.items | % { "$($_.name)=$($_.installed)" }) -join '; ')
if ($WindowsUpdate) { $x = Call GET '/v1/updates?windows=true'; T 'windows update read-only' ($x.code -eq 200) (($x.json.items | ? name -eq 'Windows Update').installed) }

$d = Call GET /v1/devices; T 'devices' ($d.code -eq 200) ("$($d.json.Count) devices, online $(@($d.json | ? online).Count)")
$owner = @($d.json | ? owner) | select -First 1
if ($owner) {
  T 'owner Pixel mode -> 403' ((Call POST "/v1/devices/$($owner.mac)/mode" @{ mode = 'filtered' }).code -eq 403) $owner.name
  T 'owner Pixel pause -> 403' ((Call POST "/v1/devices/$($owner.mac)/pause" @{ on = $true }).code -eq 403)
} else { "INFO owner Pixel not in device list right now (offline?)" }
$phone = @($d.json | ? { $_.phone -and -not $_.owner }) | select -First 1
if ($phone) { T 'phone pause -> 403' ((Call POST "/v1/devices/$($phone.mac)/pause" @{ on = $true }).code -eq 403) $phone.name } else { "INFO no non-owner phone online" }
$roku = @($d.json | ? roku) | select -First 1
if ($roku) { T 'roku pause -> 403' ((Call POST "/v1/devices/$($roku.mac)/pause" @{ on = $true }).code -eq 403) $roku.name }
T 'block whatsapp.net -> 409' ((Call POST /v1/custom-rules @{ domain = 'whatsapp.net' }).code -eq 409)
T 'block ||googleapis.com^ -> 409' ((Call POST /v1/custom-rules @{ rule = '||googleapis.com^' }).code -eq 409)
T 'block t-mobile.com -> 409' ((Call POST /v1/custom-rules @{ domain = 'wifi.t-mobile.com' }).code -eq 409)
T 'edit Messaging marker refused' ((Call POST /v1/custom-rules @{ rule = '! Messaging:protected end' }).code -in 400,409)
T 'raw rule w/ marker -> 409' ((Call POST /v1/custom-rules @{ rule = '||x.test^ ! Messaging:protected' }).code -eq 409)
T 'youtube restricted on -> 403' ((Call PUT /v1/safeguard @{ youtubeRestricted = $true }).code -eq 403)
T 'messaging off -> 403' ((Call PUT /v1/safeguard @{ messagingProtected = $false }).code -eq 403)
T 'hotspot restart needs confirm' ((Call POST /v1/hotspot/restart @{}).code -eq 428)

if ($Writes) {
  $rule = '||wallace-agent-selftest.test^'
  $x = Call POST /v1/custom-rules @{ domain = 'wallace-agent-selftest.test' }; T 'custom add (write)' ($x.code -eq 200 -and $x.json.rules -contains $rule); Start-Sleep 3
  $sw = [Diagnostics.Stopwatch]::StartNew(); do { $x = Call POST /v1/check-host @{ host = 'wallace-agent-selftest.test' }; if ($x.json.blocked) { break }; Start-Sleep 2 } while ($sw.Elapsed.TotalSeconds -lt 40)
  T 'custom rule active' ($x.json.blocked) ("reason=$($x.json.reason) after $([int]$sw.Elapsed.TotalSeconds)s")
  $x = Call DELETE ("/v1/custom-rules?rule=" + [uri]::EscapeDataString($rule)); T 'custom remove (write)' ($x.code -eq 200 -and -not ($x.json.rules -contains $rule))
  $s2 = Call GET /v1/status; T 'messaging still first after writes' ($s2.json.adguard.messagingBlockFirst) ("user rules $($s.json.adguard.userRules) -> $($s2.json.adguard.userRules)")
}

# WebSocket live feed
try {
  $ws = New-Object System.Net.WebSockets.ClientWebSocket; $ws.Options.SetRequestHeader('Authorization', "Bearer $script:tok")
  $ws.ConnectAsync([uri]($Base.Replace('http', 'ws') + '/v1/live'), [Threading.CancellationToken]::None).Wait(10000) | Out-Null
  $buf = New-Object byte[] 262144; $seg = New-Object ArraySegment[byte] -ArgumentList (, $buf)
  $ms = New-Object IO.MemoryStream
  do { $res = $ws.ReceiveAsync($seg, [Threading.CancellationToken]::None); $res.Wait(20000) | Out-Null; $ms.Write($buf, 0, $res.Result.Count) } while (-not $res.Result.EndOfMessage)
  $msg = [Text.Encoding]::UTF8.GetString($ms.ToArray()) | ConvertFrom-Json
  T 'websocket live status' ($msg.type -eq 'status') ("hotspot=$($msg.hotspot.state), $($ms.Length) bytes")
  $ws.Dispose()
} catch { T 'websocket live status' $false $_.Exception.Message }

& $exe --revoke $tid | Out-Null
T 'revoked token rejected' ((Call GET /v1/status).code -eq 401)
"RESULT: $pass passed, $fail failed"
