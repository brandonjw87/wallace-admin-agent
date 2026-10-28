using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WallaceAgent;

/// <summary>Read-side state: hotspot, health tiles, monitors, devices, updates, Uptime Kuma, alerts. Cached and refreshed in the background.</summary>
public static class Sys
{
    public static bool Elevated { get { try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } } }
    public static string Tools => AgentConfig.Current.ToolsDir;
    public static string V2 => Path.Combine(Tools, "wallace-roku-v2");

    public static (int code, string output) RunPs(string script, int timeoutMs = 120000)
    {
        var f = Path.Combine(Path.GetTempPath(), "wagent-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(f, script, new UTF8Encoding(true));
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{f}\"") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8 };
            using var p = Process.Start(psi); var o = p.StandardOutput.ReadToEndAsync(); var er = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(true); } catch { } return (-1, "timeout"); }
            return (p.ExitCode, o.Result + er.Result);
        }
        finally { try { File.Delete(f); } catch { } }
    }
    static void Launch(string script) => Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{script}\"") { UseShellExecute = false, CreateNoWindow = true });

    const string HotspotScript = @"
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
try {
  $p=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
  if($p){ $o.Uplink=$p.ProfileName
    $m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($p)
    $o.State=[string]$m.TetheringOperationalState; $o.Clients=[int]$m.ClientCount; $o.MaxClients=[int]$m.MaxClientCount
    $c=$m.GetCurrentAccessPointConfiguration(); $o.Ssid=$c.Ssid; try{ $o.Band=[string]$c.Band }catch{} }
  else { $o.State='NoUplink' }
} catch { $o.Error=$_.Exception.Message }
$ip=Get-NetIPAddress -IPAddress 192.0.2.11 -AddressFamily IPv4
if($ip){ $v=Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -IncludeHidden; $o.Virtual=$v.InterfaceDescription
  $par=(Get-PnpDeviceProperty -InstanceId $v.PnPDeviceID -KeyName DEVPKEY_Device_Parent).Data
  $h=Get-NetAdapter -Physical | ?{ $_.PnPDeviceID -eq $par }; if($h){ $o.Host=$h.Name; $o.HostDesc=$h.InterfaceDescription } }
$o.Adapters=@(foreach($a in (Get-NetAdapter -Physical | ?{ $_.NdisPhysicalMedium -eq 9 })){
  [ordered]@{ Name=$a.Name; Desc=$a.InterfaceDescription; Status=[string]$a.Status; Link=$a.LinkSpeed;
    Props=@(Get-NetAdapterAdvancedProperty -Name $a.Name | ?{ $_.DisplayName -match 'Band|Width|Wireless Mode|Throughput|Roam|SMPS|Transmit Power' } | %{ $_.DisplayName+' = '+$_.DisplayValue }) } })
$o.Radios=@((netsh wlan show drivers) -match 'Interface name|Radio types' | %{ $_.Trim() })
$t=Get-ScheduledTask -TaskName 'WALLACE Watchdog'
if($t){ $i=$t | Get-ScheduledTaskInfo; $o.Watchdog=('{0}; last run {1:h:mm tt}; result 0x{2:X}' -f $t.State,$i.LastRunTime,$i.LastTaskResult) }
$lf='C:\Users\YOU\Tools\wallace-roku-v2\logs\watchdog.log'
if(Test-Path $lf){ $o.WatchdogLog=@(Get-Content $lf -Tail 8 | % { [string]$_ }) }
$o | ConvertTo-Json -Depth 4 -Compress
";

    // ---------- caches ----------
    public static JsonNode Hotspot = new JsonObject { ["state"] = "unknown" }; public static DateTime HotspotAt;
    public static JsonArray Health = new(); public static DateTime HealthAt; static int healthBusy;
    public static JsonArray Updates; public static DateTime UpdatesAt; static int updBusy;
    public static readonly ConcurrentQueue<JsonObject> AlertFeed = new();
    static readonly ConcurrentDictionary<string, DateTime> alertCool = new();
    public static readonly ConcurrentDictionary<string, JsonObject> MonitorStates = new();

    public static void Alert(string key, string kind, string title, string body, int coolMin = 10)
    {
        if (alertCool.TryGetValue(key, out var t) && (DateTime.Now - t).TotalMinutes < coolMin) return; alertCool[key] = DateTime.Now;
        AlertFeed.Enqueue(new JsonObject { ["time"] = DateTimeOffset.Now.ToString("o"), ["kind"] = kind, ["title"] = title, ["body"] = body, ["key"] = key });
        while (AlertFeed.Count > 200) AlertFeed.TryDequeue(out _);
        Log.Agent($"alert [{kind}] {title}");
    }

    public static async Task RefreshHotspot()
    {
        var (_, o) = await Task.Run(() => RunPs(HotspotScript, 60000));
        var line = o.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("{")) ?? "";
        JsonObject j; try { j = JsonNode.Parse(line)?.AsObject() ?? new JsonObject(); } catch { j = new JsonObject { ["Error"] = "probe returned nothing" }; }
        var r = new JsonObject();
        foreach (var k in new[] { "State", "Ssid", "Band", "Uplink", "Virtual", "Host", "HostDesc", "Watchdog", "Error" }) r[char.ToLower(k[0]) + k[1..]] = Log.Redact((string)j[k]?.ToString() ?? "");
        r["clients"] = (int?)j["Clients"] ?? -1; r["maxClients"] = (int?)j["MaxClients"] ?? -1;
        r["band"] = ((string)r["band"]) switch { "FiveGigahertz" => "5 GHz", "TwoPointFourGigahertz" => "2.4 GHz", "SixGigahertz" => "6 GHz", "Auto" => "Auto", var b => b };
        JsonArray L(JsonNode n) => n is JsonArray a ? new JsonArray(a.Select(x => (JsonNode)Log.Redact(x?.ToString())).ToArray()) : n == null ? new JsonArray() : new JsonArray(Log.Redact(n.ToString()));
        r["radios"] = L(j["Radios"]); r["watchdogLog"] = L(j["WatchdogLog"]);
        var ads = new JsonArray(); foreach (var a in j["Adapters"] is JsonArray aa ? aa.ToList() : j["Adapters"] != null ? new List<JsonNode> { j["Adapters"] } : new()) ads.Add(new JsonObject { ["name"] = a?["Name"]?.ToString(), ["desc"] = a?["Desc"]?.ToString(), ["status"] = a?["Status"]?.ToString(), ["link"] = a?["Link"]?.ToString() });
        r["adapters"] = ads; r["time"] = DateTimeOffset.Now.ToString("o");
        var prev = (string)Hotspot?["state"];
        if (prev == "On" && (string)r["state"] != "On") Alert("wallace-off", "red", "WALLACE hotspot is " + r["state"], "The watchdog (every 3 min) will try to restart it.");
        if (prev != null && prev != "unknown" && prev != "On" && (string)r["state"] == "On") Alert("wallace-on", "green", "WALLACE hotspot is back On", (string)r["band"], 1);
        Hotspot = r; HotspotAt = DateTime.Now;
    }

    public static async Task RefreshHealth()
    {
        if (Interlocked.Exchange(ref healthBusy, 1) == 1) return;
        try
        {
            using var s = typeof(Sys).Assembly.GetManifestResourceStream("probe.ps1"); var script = new StreamReader(s).ReadToEnd();
            var (_, output) = await Task.Run(() => RunPs(script, 180000));
            var jl = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).LastOrDefault(l => l.TrimStart().StartsWith("[")) ?? "";
            var list = new JsonArray();
            try { foreach (var e in JsonNode.Parse(jl).AsArray()) list.Add(new JsonObject { ["layer"] = (string)e["Layer"], ["name"] = (string)e["Name"], ["status"] = (string)e["Status"], ["detail"] = Log.Redact((string)e["Detail"]), ["explain"] = (string)e["Explain"] }); }
            catch { list.Add(new JsonObject { ["layer"] = "Engine", ["name"] = "Probe", ["status"] = "Red", ["detail"] = "probe returned unreadable output", ["explain"] = "The checking script did not return results." }); }
            foreach (var c in list.Where(c => (string)c["status"] == "Red")) Alert("red-" + c["name"], "red", "Red tile: " + c["layer"] + " / " + c["name"], (string)c["detail"], 30);
            Health = list; HealthAt = DateTime.Now;
        }
        finally { Interlocked.Exchange(ref healthBusy, 0); }
    }
    public static bool HealthBusy => Volatile.Read(ref healthBusy) == 1;

    // ---------- desktop app data (read-only) ----------
    public static JsonNode DesktopSettings() { try { return JsonNode.Parse(File.ReadAllText(Path.Combine(AgentConfig.Current.AdminDataDir, "settings.json"))); } catch { return new JsonObject(); } }
    public static Dictionary<string, string> DeviceTypes() { var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); if (DesktopSettings()["DeviceTypes"] is JsonObject o) foreach (var k in o) d[k.Key] = (string)k.Value; return d; }
    public static Dictionary<string, string> DeviceNames() { var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); if (DesktopSettings()["DeviceNames"] is JsonObject o) foreach (var k in o) d[k.Key] = (string)k.Value; return d; }
    public static JsonArray DesktopDevices() { try { var n = JsonNode.Parse(File.ReadAllText(Path.Combine(AgentConfig.Current.AdminDataDir, "devices.json"))); return n as JsonArray ?? new JsonArray(n is JsonObject o ? o.Select(k => k.Value?.DeepClone()).ToArray() : Array.Empty<JsonNode>()); } catch { return new JsonArray(); } }
    public static JsonArray DesktopPaused() { try { return JsonNode.Parse(File.ReadAllText(Path.Combine(AgentConfig.Current.AdminDataDir, "paused.json"))) as JsonArray ?? new(); } catch { return new(); } }

    [DllImport("iphlpapi.dll", ExactSpelling = true)] static extern int GetIpNetTable(IntPtr table, ref int size, bool order);
    public static List<(string ip, string mac, bool dynamic)> ReadArp()
    {
        var list = new List<(string, string, bool)>(); int size = 0; GetIpNetTable(IntPtr.Zero, ref size, false); if (size <= 0) return list;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, true) != 0) return list; int n = Marshal.ReadInt32(buf);
            for (int i = 0; i < n; i++)
            {
                var row = buf + 4 + i * 24; int len = Marshal.ReadInt32(row, 4); int type = Marshal.ReadInt32(row, 20); if (len != 6 || type == 2) continue;
                var mac = new byte[6]; Marshal.Copy(row + 8, mac, 0, 6); if (mac.All(b => b == 0xFF) || mac.All(b => b == 0) || (mac[0] & 1) == 1) continue;
                list.Add((new System.Net.IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(row, 16))).ToString(), string.Join(":", mac.Select(b => b.ToString("X2"))), type == 3));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    // ---------- monitors (same list as the desktop Live Status page) ----------
    static readonly HttpClient mhttp = new(new SocketsHttpHandler { AllowAutoRedirect = true, ConnectTimeout = TimeSpan.FromSeconds(4) }) { Timeout = TimeSpan.FromSeconds(6) };
    public static async Task RunMonitors()
    {
        var defs = DesktopSettings()["Monitors"] as JsonArray;
        var list = defs?.Select(d => ((string)d["Name"], (string)d["Type"], (string)d["Target"])).ToList() ?? new()
        { ("Internet (Cloudflare)", "ping", "1.1.1.1"), ("Internet (HTTPS)", "http", "https://www.google.com/generate_204"), ("Spectrum router", "ping", "192.0.2.15"), ("Hotspot gateway", "ping", "192.0.2.11"), ("AdGuard DNS", "tcp", "127.0.0.1:53"), ("AdGuard web", "http", "http://127.0.0.1:3000"), ("Uptime Kuma", "http", "http://127.0.0.1:3001") };
        var arp = ReadArp();
        await Task.WhenAll(list.Select(async m =>
        {
            var (name, type, target) = m; bool up = false; double ms = -1; string note = ""; var sw = Stopwatch.StartNew();
            try
            {
                if (target.StartsWith("mac:", StringComparison.OrdinalIgnoreCase)) { var mac = target[4..]; var hit = arp.FirstOrDefault(a => string.Equals(a.mac, mac.Replace('-', ':'), StringComparison.OrdinalIgnoreCase)); target = hit.ip; if (target == null) throw new Exception("device not seen on network"); }
                switch ((type ?? "ping").ToLowerInvariant())
                {
                    case "tcp": { var i = target.LastIndexOf(':'); using var c = new TcpClient(); using var cts = new CancellationTokenSource(2500); await c.ConnectAsync(target[..i], int.Parse(target[(i + 1)..]), cts.Token); up = true; note = "port open"; break; }
                    case "http": { using var r = await mhttp.GetAsync(target, HttpCompletionOption.ResponseHeadersRead); up = (int)r.StatusCode < 500; note = "HTTP " + (int)r.StatusCode; break; }
                    default: { using var p = new Ping(); var r = await p.SendPingAsync(target, 1500); up = r.Status == IPStatus.Success; if (up) ms = r.RoundtripTime; note = r.Status.ToString(); break; }
                }
                if (up && ms < 0) ms = sw.Elapsed.TotalMilliseconds;
            }
            catch (Exception ex) { up = false; note = (ex.InnerException ?? ex).Message; }
            var st = MonitorStates.GetOrAdd(name, _ => new JsonObject { ["name"] = name, ["type"] = type, ["target"] = m.Item3, ["history"] = new JsonArray() });
            lock (st)
            {
                bool? was = (bool?)st["up"]; st["up"] = up; st["ms"] = Math.Round(ms, 1); st["note"] = note; st["time"] = DateTimeOffset.Now.ToString("o");
                var h = st["history"].AsArray(); h.Add(up ? 1 : 0); while (h.Count > 120) h.RemoveAt(0);
                st["uptimePct"] = Math.Round(h.Count(x => (int)x == 1) * 100.0 / h.Count, 1);
                if (was == true && !up) Alert("mon-" + name, "red", "Monitor down: " + name, note, 10);
                if (was == false && up) Alert("monup-" + name, "green", "Monitor back up: " + name, note, 1);
            }
        }));
    }

    // ---------- Uptime Kuma ----------
    public static async Task<JsonObject> Kuma()
    {
        var cfg = AgentConfig.Current; var o = new JsonObject { ["url"] = cfg.KumaUrl };
        string ver = "?"; try { using var d = JsonDocument.Parse(File.ReadAllText(Path.Combine(Tools, @"uptime-kuma\package.json"))); ver = d.RootElement.GetProperty("version").GetString(); } catch { }
        o["version"] = ver;
        try { var sw = Stopwatch.StartNew(); using var r = await mhttp.GetAsync(cfg.KumaUrl, HttpCompletionOption.ResponseHeadersRead); o["reachable"] = (int)r.StatusCode < 500; o["http"] = (int)r.StatusCode; o["ms"] = Math.Round(sw.Elapsed.TotalMilliseconds); }
        catch (Exception ex) { o["reachable"] = false; o["error"] = (ex.InnerException ?? ex).Message; }
        if (!string.IsNullOrWhiteSpace(cfg.KumaStatusSlug))
        {
            try
            {
                var page = JsonNode.Parse(await mhttp.GetStringAsync($"{cfg.KumaUrl}/api/status-page/{cfg.KumaStatusSlug}"));
                var hb = JsonNode.Parse(await mhttp.GetStringAsync($"{cfg.KumaUrl}/api/status-page/heartbeat/{cfg.KumaStatusSlug}"));
                var mons = new JsonArray();
                foreach (var g in AdGuard.Arr(page["publicGroupList"])) foreach (var m in AdGuard.Arr(g["monitorList"]))
                {
                    var id = m["id"]?.ToString(); var beats = hb?["heartbeatList"]?[id] as JsonArray; var last = beats?.LastOrDefault();
                    mons.Add(new JsonObject { ["name"] = (string)m["name"], ["up"] = (int?)last?["status"] == 1, ["ms"] = (double?)last?["ping"], ["uptime24"] = (double?)hb?["uptimeList"]?[id + "_24"], ["msg"] = (string)last?["msg"] });
                }
                o["monitors"] = mons;
            }
            catch (Exception ex) { o["statusPageError"] = (ex.InnerException ?? ex).Message; }
        }
        else o["note"] = "Set KumaStatusSlug in agent.json to show individual Uptime Kuma monitors (uses the public status-page API, no Kuma password).";
        return o;
    }

    // ---------- updates (read-only, nothing installs) ----------
    static readonly HttpClient gh = MakeGh();
    static HttpClient MakeGh() { var h = new HttpClient { Timeout = TimeSpan.FromSeconds(15) }; h.DefaultRequestHeaders.UserAgent.ParseAdd("WallaceAgent/1.0"); h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json"); return h; }
    static async Task<string> Latest(string repo) { try { var j = JsonNode.Parse(await gh.GetStringAsync($"https://api.github.com/repos/{repo}/releases/latest")); return (string)j["tag_name"]; } catch { return "?"; } }
    static string FileVer(string p) { try { if (!File.Exists(p)) return "not found"; var v = FileVersionInfo.GetVersionInfo(p); return string.IsNullOrEmpty(v.ProductVersion) ? v.FileVersion : v.ProductVersion.Split('+')[0]; } catch { return "?"; } }
    public static async Task RefreshUpdates(bool windows)
    {
        if (Interlocked.Exchange(ref updBusy, 1) == 1) return;
        try
        {
            var r = new JsonArray(); string aghV = "?"; try { aghV = (string)(await AdGuard.Get("status"))["version"]; } catch { }
            var t1 = Latest("AdguardTeam/AdGuardHome"); var t2 = Latest("dmunozv04/iSponsorBlockTV"); var t3 = Latest("louislam/uptime-kuma"); var t4 = Latest("GyulyVGC/sniffnet");
            await Task.WhenAll(t1, t2, t3, t4);
            string kV = "?"; try { using var d = JsonDocument.Parse(File.ReadAllText(Path.Combine(Tools, @"uptime-kuma\package.json"))); kV = d.RootElement.GetProperty("version").GetString(); } catch { }
            void Add(string n, string i, string l) { string vi = Regex.Match(i ?? "", @"\d+(\.\d+)+").Value, vl = Regex.Match(l ?? "", @"\d+(\.\d+)+").Value; string verdict = vi == "" || vl == "" ? "check manually" : Version.TryParse(vi, out var a) && Version.TryParse(vl, out var b) ? (a >= b ? "up to date" : "update available") : "check manually"; r.Add(new JsonObject { ["name"] = n, ["installed"] = i, ["latest"] = l, ["verdict"] = verdict }); }
            Add("AdGuard Home", aghV, t1.Result); Add("iSponsorBlockTV", FileVer(Path.Combine(Tools, @"isponsorblocktv\iSponsorBlockTV.exe")), t2.Result);
            Add("Uptime Kuma", kV, t3.Result); Add("Sniffnet", FileVer(@"C:\Program Files\Sniffnet\sniffnet.exe"), t4.Result);
            var npcap = Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll"); r.Add(new JsonObject { ["name"] = "Npcap (capture driver)", ["installed"] = File.Exists(npcap) ? FileVer(npcap) : "NOT INSTALLED", ["latest"] = "npcap.com", ["verdict"] = File.Exists(npcap) ? "installed" : "not installed" });
            r.Add(new JsonObject { ["name"] = "WALLACE Admin (desktop)", ["installed"] = FileVer(Path.Combine(Path.GetDirectoryName(AgentConfig.Current.AdminDataDir), @"Programs\WALLACE Admin\WALLACEAdmin.exe")), ["latest"] = "-", ["verdict"] = "-" });
            if (windows)
            {
                var (_, o) = await Task.Run(() => RunPs("$s=New-Object -ComObject Microsoft.Update.Session; $x=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0'); $x.Updates.Count; foreach($u in $x.Updates){ '- ' + $u.Title }", 240000));
                var lines = o.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()).ToArray();
                r.Add(new JsonObject { ["name"] = "Windows Update", ["installed"] = "pending: " + (lines.Length > 0 ? lines[0] : "?"), ["latest"] = string.Join("; ", lines.Skip(1).Take(8).Select(l => l.TrimStart('-', ' '))), ["verdict"] = "read-only - install from Settings > Windows Update", ["windowsUpdates"] = new JsonArray(lines.Skip(1).Select(l => (JsonNode)l.TrimStart('-', ' ')).ToArray()) });
            }
            Updates = r; UpdatesAt = DateTime.Now;
        }
        finally { Interlocked.Exchange(ref updBusy, 0); }
    }

    // ---------- actions (no generic command endpoint; fixed scripts only) ----------
    public static void StartHotspot() => Launch(Path.Combine(V2, "start-hotspot.ps1"));
    public static void RunWatchdog() => Launch(Path.Combine(V2, "watchdog.ps1"));
    /// <summary>Elevated helper actions: only when the agent itself runs elevated (SYSTEM service). Never triggers UAC.</summary>
    public static (bool ok, string msg) Helper(string action, string arg)
    {
        if (!Elevated) return (false, "Needs the WALLACE Agent service (runs elevated). Install it at the PC with install-agent.ps1 -Mode Service, or do this from the desktop app.");
        var allowed = new[] { "pause", "unpause", "restart-adguard" }; if (!allowed.Contains(action)) return (false, "action not allowed");
        if (arg != "" && !Regex.IsMatch(arg, @"^\d{1,3}(\.\d{1,3}){3}$")) return (false, "bad argument");
        var helper = @"C:\ProgramData\WALLACE Admin\wnh-admin.ps1"; if (!File.Exists(helper)) return (false, "helper script missing: " + helper);
        var log = Path.Combine(AgentConfig.LogDir, "admin-helper.log");
        var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{helper}\" -Action {action} -Arg \"{arg}\" -Log \"{log}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = Process.Start(psi); var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd(); p.WaitForExit(180000);
        return (p.ExitCode == 0, Log.Redact(o.Trim()));
    }
}
