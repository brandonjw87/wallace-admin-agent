using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using QRCoder;
using WallaceAgent;

const string AgentVersion = "1.0.0";
var cfg = AgentConfig.Current;

// ---------------- CLI ----------------
if (args.Length > 0 && args[0] == "--pair")
{
    var name = args.Length > 1 && !args[1].StartsWith("--") ? args[1] : "Pixel 10 Pro XL";
    var host = args.SkipWhile(a => a != "--host").Skip(1).FirstOrDefault() ?? cfg.BindAddresses().Select(a => a.ToString()).OrderBy(a => a.StartsWith("100.") ? 1 : 0).FirstOrDefault() ?? "192.0.2.13";
    var code = Auth.CreatePairCode(name);
    var uri = $"wallace://pair?host={host}&port={cfg.Port}&code={code}&name={Uri.EscapeDataString("WALLACE Admin")}";
    using var gen = new QRCodeGenerator(); using var data = gen.CreateQrCode(uri, QRCodeGenerator.ECCLevel.M); var png = new PngByteQRCode(data).GetGraphic(12);
    var f = Path.Combine(AgentConfig.DataDir, "pair-qr.png"); File.WriteAllBytes(f, png);
    var html = Path.Combine(AgentConfig.DataDir, "pair-qr.html");
    File.WriteAllText(html, $"<html><head><title>Pair WALLACE Admin</title></head><body style='font-family:Segoe UI;background:#0b1020;color:#e6e9f2;text-align:center'><h2>Scan with WALLACE Admin on your phone</h2><img src='data:image/png;base64,{Convert.ToBase64String(png)}' style='width:420px;background:#fff;padding:12px;border-radius:12px'/><p>Server {host}:{cfg.Port} &middot; one-time code, expires in 10 minutes. Close this page after pairing.</p></body></html>");
    Log.Agent($"pair code created for '{name}' (host {host})");
    var co = args.SkipWhile(a => a != "--code-out").Skip(1).FirstOrDefault(); if (co != null) File.WriteAllText(co, code); // test harness only
    Console.WriteLine($"Pairing QR written to {html} (valid 10 minutes, single use). The code itself is not printed.");
    if (!args.Contains("--no-open")) try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(html) { UseShellExecute = true }); } catch { }
    // remove the QR files after 10 minutes if we are still around is not needed: they hold a code that expires; --pair-clean overwrites them
    return 0;
}
if (args.Length > 0 && args[0] == "--pair-clean") { foreach (var n in new[] { "pair-qr.png", "pair-qr.html" }) { var f = Path.Combine(AgentConfig.DataDir, n); if (File.Exists(f)) File.WriteAllText(f, "expired"); } Console.WriteLine("QR files blanked."); return 0; }
if (args.Length > 0 && args[0] == "--tokens") { foreach (var t in Auth.List()) Console.WriteLine($"{t.Id}  {t.Name,-28} created {t.Created:u}  last used {(t.LastUsed?.ToString("u") ?? "never")}  {(t.Revoked ? "REVOKED" : "active")}"); return 0; }
if (args.Length > 1 && args[0] == "--revoke") { Console.WriteLine(Auth.Revoke(args[1]) ? "revoked " + args[1] : "no such token"); return 0; }
if (args.Length > 0 && args[0] == "--selftest") return SelfTest.Run();
if (args.Length > 0 && args[0].StartsWith("--")) { Console.WriteLine("Usage: WallaceAgent [--pair [name] [--host ip] [--no-open]] [--pair-clean] [--tokens] [--revoke <id>] [--selftest]   (no args = run server)"); return 1; }

// ---------------- server ----------------
var binds = cfg.BindAddresses();
if (binds.Count == 0) { Log.Agent("no LAN/Tailscale address to bind - exiting"); Console.Error.WriteLine("No 192.168.1.x or 100.x address found to bind."); return 2; }
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Host.UseWindowsService(o => o.ServiceName = "WALLACE Agent");
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(k => { foreach (var a in binds) k.Listen(a, cfg.Port); k.AddServerHeader = false; k.Limits.MaxRequestBodySize = 64 * 1024; });
var app = builder.Build();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20) });
Log.Agent($"WALLACE Agent {AgentVersion} listening on {string.Join(", ", binds)}:{cfg.Port} (elevated={Sys.Elevated})");

var rate = new ConcurrentDictionary<string, (DateTime start, int n)>();
app.Use(async (ctx, next) =>
{
    var ip = ctx.Connection.RemoteIpAddress; var ips = ip?.ToString() ?? "?";
    if (!cfg.Allowed(ip)) { ctx.Response.StatusCode = 403; Log.Audit($"{ips} {ctx.Request.Method} {ctx.Request.Path} 403 network-not-allowed"); return; }
    var w = rate.AddOrUpdate(ips, _ => (DateTime.UtcNow, 1), (_, v) => (DateTime.UtcNow - v.start).TotalSeconds > 60 ? (DateTime.UtcNow, 1) : (v.start, v.n + 1));
    if (w.n > cfg.RateLimitPerMinute) { ctx.Response.StatusCode = 429; return; }
    var path = ctx.Request.Path.Value ?? "";
    if (path is "/v1/ping" or "/v1/pair")
    {
        try { await next(); } catch (Exception ex) { Log.Agent("error " + path + ": " + ex); if (!ctx.Response.HasStarted) { ctx.Response.StatusCode = 500; } }
        Log.Audit($"{ips} {ctx.Request.Method} {path} {ctx.Response.StatusCode}"); return;
    }
    if (!path.StartsWith("/v1/")) { ctx.Response.StatusCode = 404; return; }
    if (Auth.LockedOut(ips)) { ctx.Response.StatusCode = 429; Log.Audit($"{ips} {path} 429 locked-out"); return; }
    var h = ctx.Request.Headers.Authorization.ToString();
    var tok = h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? Auth.Validate(h[7..].Trim()) : null;
    if (tok == null) { Auth.Fail(ips); ctx.Response.StatusCode = 401; Log.Audit($"{ips} {ctx.Request.Method} {path} 401"); return; }
    ctx.Items["tok"] = tok;
    try { await next(); }
    catch (GuardException ge) { if (!ctx.Response.HasStarted) { ctx.Response.StatusCode = ge.Code; await ctx.Response.WriteAsJsonAsync(new { error = ge.Message }); } }
    catch (Exception ex) { Log.Agent("error " + path + ": " + ex); if (!ctx.Response.HasStarted) { ctx.Response.StatusCode = 502; await ctx.Response.WriteAsJsonAsync(new { error = Log.Redact(ex.Message) }); } }
    if (ctx.Request.Method != "GET" || ctx.Response.StatusCode >= 400) Log.Audit($"{ips} token={tok.Id} {ctx.Request.Method} {path} {ctx.Response.StatusCode}");
});

static async Task<JsonObject> Body(HttpRequest r) { try { return (await JsonNode.ParseAsync(r.Body))?.AsObject() ?? new JsonObject(); } catch { throw new GuardException(400, "Body must be JSON"); } }
static string S(JsonNode n) => n is JsonValue v && v.TryGetValue<string>(out var x) ? x : null;
static IResult J(JsonNode n) => Results.Text(n.ToJsonString(), "application/json");
static IResult Err(int code, string msg) => Results.Json(new { error = msg }, statusCode: code);

app.MapGet("/v1/ping", () => Results.Json(new { app = "WALLACE Agent", version = AgentVersion, api = 1 }));
app.MapPost("/v1/pair", async (HttpRequest r) =>
{
    var b = await Body(r); var res = Auth.Redeem(S(b["code"]), S(b["deviceName"]));
    if (res == null) { Auth.Fail(r.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "?"); return Err(401, "Pairing code invalid or expired. Run pair-phone on the PC again."); }
    Log.Audit($"paired device token={res.Value.id}");
    return Results.Json(new { token = res.Value.token, tokenId = res.Value.id, server = "WALLACE Agent " + AgentVersion });
});
app.MapGet("/v1/session", (HttpContext c) => { var t = (DeviceToken)c.Items["tok"]; return Results.Json(new { tokenId = t.Id, name = t.Name, elevated = Sys.Elevated, version = AgentVersion }); });

// ---- status / health ----
async Task<JsonObject> AdguardSummary()
{
    var o = new JsonObject();
    try
    {
        var st = await AdGuard.Get("status"); o["reachable"] = true; o["version"] = (string)st["version"]; o["protection"] = (bool?)st["protection_enabled"]; o["running"] = (bool?)st["running"];
        var f = await AdGuard.Get("filtering/status"); var fl = AdGuard.Arr(f["filters"]);
        o["listsEnabled"] = fl.Count(x => (bool)x["enabled"]); o["listsTotal"] = fl.Count; o["listRules"] = fl.Where(x => (bool)x["enabled"]).Sum(x => (long?)x["rules_count"] ?? 0);
        var ur = AdGuard.Arr(f["user_rules"]).Select(x => (string)x).Where(x => !string.IsNullOrEmpty(x)).ToList(); o["userRules"] = ur.Count;
        o["messagingBlockFirst"] = ur.Count > 0 && ur[0].StartsWith("! Messaging:protected begin");
        o["listsUpdated"] = fl.Where(x => (bool)x["enabled"]).Select(x => (string)x["last_updated"]).Where(x => x != null).OrderBy(x => x).FirstOrDefault();
        var s = await AdGuard.Get("stats"); o["queries"] = (long?)s["num_dns_queries"]; o["blocked"] = (long?)s["num_blocked_filtering"]; o["avgMs"] = Math.Round(((double?)s["avg_processing_time"] ?? 0) * 1000, 1);
    }
    catch (Exception ex) { o["reachable"] = false; o["error"] = Log.Redact(ex.Message); }
    return o;
}
JsonArray Monitors() => new(Sys.MonitorStates.Values.OrderBy(m => (string)m["name"]).Select(m => { lock (m) return m.DeepClone(); }).ToArray());
JsonObject HealthSummary() { var h = Sys.Health; return new JsonObject { ["green"] = h.Count(x => (string)x["status"] == "Green"), ["yellow"] = h.Count(x => (string)x["status"] == "Yellow"), ["red"] = h.Count(x => (string)x["status"] == "Red"), ["time"] = Sys.HealthAt == default ? null : new DateTimeOffset(Sys.HealthAt).ToString("o"), ["running"] = Sys.HealthBusy }; }
async Task<JsonObject> Status() => new()
{
    ["time"] = DateTimeOffset.Now.ToString("o"), ["agent"] = new JsonObject { ["version"] = AgentVersion, ["elevated"] = Sys.Elevated, ["machine"] = Environment.MachineName },
    ["hotspot"] = Sys.Hotspot.DeepClone(), ["adguard"] = await AdguardSummary(), ["health"] = HealthSummary(), ["monitors"] = Monitors(),
    ["alerts"] = Sys.AlertFeed.Count, ["messagingProtected"] = true, ["desktopVersion"] = "3.4.0",
};
app.MapGet("/v1/status", async () => J(await Status()));
app.MapGet("/v1/health", () => J(new JsonObject { ["summary"] = HealthSummary(), ["checks"] = Sys.Health.DeepClone() }));
app.MapPost("/v1/health/recheck", () => { _ = Task.Run(Sys.RefreshHealth); return Results.Accepted(value: new { message = "Recheck started (takes about a minute)." }); });
app.MapGet("/v1/hotspot", () => J(Sys.Hotspot.DeepClone()));
app.MapPost("/v1/hotspot/refresh", async () => { await Sys.RefreshHotspot(); return J(Sys.Hotspot.DeepClone()); });
app.MapPost("/v1/hotspot/restart", async (HttpRequest r) => { var b = await Body(r); if ((bool?)b["confirm"] != true) return Err(428, "Send {\"confirm\":true} to start / repair the hotspot."); Sys.StartHotspot(); Log.Agent("hotspot start/repair requested from phone"); return Results.Json(new { message = "Start / repair hotspot launched (start-hotspot.ps1). Give it ~30 s." }); });
app.MapPost("/v1/watchdog/run", () => { Sys.RunWatchdog(); return Results.Json(new { message = "Watchdog run started." }); });
app.MapGet("/v1/monitors", () => J(Monitors()));
app.MapPost("/v1/monitors/check", async () => { await Sys.RunMonitors(); return J(Monitors()); });
app.MapGet("/v1/kuma", async () => J(await Sys.Kuma()));
app.MapGet("/v1/alerts", () => J(new JsonArray(Sys.AlertFeed.Reverse().Select(a => a.DeepClone()).ToArray())));
app.MapPost("/v1/alerts/clear", () => { while (Sys.AlertFeed.TryDequeue(out _)) { } return Results.Json(new { message = "cleared" }); });
app.MapPost("/v1/alerts/test", () => { Sys.Alert("test-" + DateTime.Now.Ticks, "info", "Test alert", "Sent from the phone app."); return Results.Json(new { message = "ok" }); });

// ---- AdGuard data ----
app.MapGet("/v1/stats", async () =>
{
    var s = await AdGuard.Get("stats"); var o = new JsonObject();
    foreach (var k in new[] { "num_dns_queries", "num_blocked_filtering", "num_replaced_safebrowsing", "num_replaced_safesearch", "num_replaced_parental", "avg_processing_time", "time_units", "dns_queries", "blocked_filtering", "top_queried_domains", "top_blocked_domains", "top_clients", "top_upstreams_responses", "top_upstreams_avg_time" })
        if (s[k] != null) o[k] = s[k].DeepClone();
    return J(o);
});
var clientNameCache = new ConcurrentDictionary<string, string>();
app.MapGet("/v1/querylog", async (int? limit, string search, string status, string olderThan, string client) =>
{
    var q = $"querylog?limit={Math.Clamp(limit ?? 100, 1, 500)}"; if (!string.IsNullOrWhiteSpace(search)) q += "&search=" + Uri.EscapeDataString(search.Trim());
    if (!string.IsNullOrWhiteSpace(client) && string.IsNullOrWhiteSpace(search)) q += "&search=" + Uri.EscapeDataString(client.Trim());
    q += "&response_status=" + (status is "blocked" or "filtered" or "processed" or "whitelisted" or "rewritten" or "safe_search" ? status : "all");
    if (!string.IsNullOrWhiteSpace(olderThan)) q += "&older_than=" + Uri.EscapeDataString(olderThan);
    var r = await AdGuard.Get(q); var arr = new JsonArray();
    foreach (var e in AdGuard.Arr(r["data"]))
    {
        var reason = (string)e["reason"] ?? ""; var rules = AdGuard.Arr(e["rules"]);
        arr.Add(new JsonObject
        {
            ["time"] = (string)e["time"], ["client"] = (string)e["client"], ["clientName"] = (string)e["client_info"]?["name"] ?? "", ["domain"] = (string)e["question"]?["name"], ["type"] = (string)e["question"]?["type"],
            ["reason"] = reason, ["blocked"] = reason.StartsWith("Filtered") && reason != "FilteredSafeSearch" || reason == "FilteredSafeSearch", ["rule"] = rules.Count > 0 ? (string)rules[0]?["text"] : null,
            ["service"] = (string)e["service_name"], ["elapsedMs"] = double.TryParse((string)e["elapsedMs"], System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var ms) ? Math.Round(ms, 1) : null, ["upstream"] = (string)e["upstream"], ["cached"] = (bool?)e["cached"],
            ["protectedMessaging"] = Messaging.IsProtectedHost((string)e["question"]?["name"]),
        });
    }
    return J(new JsonObject { ["oldest"] = (string)r["oldest"], ["entries"] = arr });
});
app.MapGet("/v1/blocklists", async () =>
{
    var f = await AdGuard.Get("filtering/status"); var arr = new JsonArray();
    foreach (var x in AdGuard.Arr(f["filters"]).Concat(AdGuard.Arr(f["whitelist_filters"])))
    {
        var n = (string)x["name"] ?? ""; var m = System.Text.RegularExpressions.Regex.Match(n, @"\[(\w+)\]"); var cat = m.Success ? m.Groups[1].Value : n.StartsWith("Safe Guard:") ? "adult" : "other";
        if (Ops.BypassListUrls.Contains((string)x["url"])) cat = "bypass";
        arr.Add(new JsonObject { ["id"] = (long?)x["id"], ["category"] = cat, ["name"] = n, ["url"] = (string)x["url"], ["enabled"] = (bool?)x["enabled"], ["rules"] = (long?)x["rules_count"], ["lastUpdated"] = (string)x["last_updated"] });
    }
    return J(new JsonObject { ["lists"] = arr, ["intervalHours"] = (int?)f["interval"] });
});
app.MapPost("/v1/blocklists/refresh", async () => { await Ops.Write("refresh lists", () => AdGuard.Send("POST", "filtering/refresh", new JsonObject { ["whitelist"] = false })); return Results.Json(new { message = "AdGuard is re-downloading every enabled list." }); });
app.MapPost("/v1/check-host", async (HttpRequest r) =>
{
    var b = await Body(r); var host = (S(b["host"]) ?? "").Trim().ToLowerInvariant(); var client = (S(b["client"]) ?? "").Trim();
    if (!System.Text.RegularExpressions.Regex.IsMatch(host, @"^[a-z0-9.-]{1,253}$")) return Err(400, "Not a host name");
    var res = await AdGuard.CheckHostFull(host, client == "" ? null : client);
    var reason = (string)res["reason"] ?? "?";
    return J(new JsonObject { ["host"] = host, ["client"] = client, ["reason"] = reason, ["blocked"] = reason.StartsWith("Filtered"), ["rule"] = AdGuard.Arr(res["rules"]).Select(x => (string)x?["text"]).FirstOrDefault(), ["service"] = (string)res["service_name"], ["messagingProtected"] = Messaging.IsProtectedHost(host) });
});

// ---- Safe Guard ----
app.MapGet("/v1/safeguard", async () => J(await Ops.SafeGuardState()));
app.MapPut("/v1/safeguard", async (HttpRequest r) =>
{
    var b = await Body(r); var cur = await Ops.SafeGuardState(); var done = new JsonArray();
    bool? B(string k) => b[k] is JsonValue v && v.TryGetValue<bool>(out var x) ? x : null;
    if (b.ContainsKey("youtubeRestricted") && B("youtubeRestricted") == true) return Err(403, "YouTube restricted mode stays off (Rokus need unrestricted YouTube). This can't be changed.");
    if (b.ContainsKey("messagingProtected") && B("messagingProtected") == false) return Err(403, "Messaging protected is locked and can't be turned off.");
    await Ops.Write("safeguard update", async () =>
    {
        if (B("adult") != null || B("adultExtra") != null) { bool on = B("adult") ?? (bool)cur["adult"]; bool ex = B("adultExtra") ?? (bool)cur["adultExtra"]; await Ops.SetAdult(on, ex); done.Add("adult"); }
        if (B("instagram") != null || B("social") != null) { await Ops.SetServices(B("instagram") ?? (bool)cur["instagram"], B("social") ?? (bool)cur["social"]); done.Add("services"); }
        if (B("safeSearch") is bool ss) { await Ops.SetSafeSearch(ss); done.Add("safeSearch"); }
        if (B("bypass") is bool bp) { await Ops.SetBypass(bp); done.Add("bypass"); }
        if (B("exemptRokus") is bool er) { await Ops.SetRokuExempt(er); done.Add("exemptRokus"); }
        if (B("master") is bool m) { await Ops.SetAdult(m, m && (bool)cur["adultExtra"]); await Ops.SetServices(m, m && (bool)cur["social"]); await Ops.SetSafeSearch(m); done.Add("master"); }
        if (b["categories"] is JsonObject cats) foreach (var kv in cats) if (kv.Value is JsonValue v && v.TryGetValue<bool>(out var on)) { await Ops.SetCategory(kv.Key, on); done.Add("cat:" + kv.Key); }
        await Ops.ForceYoutubeUnrestricted();
    });
    var st = await Ops.SafeGuardState(); st["applied"] = done; return J(st);
});
app.MapPost("/v1/safeguard/reapply-allow", async () => { await Ops.Write("re-apply Roku/YouTube allow", async () => { await Ops.EnsureAllow(); await Ops.ForceYoutubeUnrestricted(); }); return Results.Json(new { message = "Roku/YouTube allow rules re-applied; Messaging protected stays first." }); });

// ---- custom rules ----
app.MapGet("/v1/custom-rules", async () => J(new JsonObject { ["rules"] = new JsonArray((await Ops.CustomRules()).Select(x => (JsonNode)x).ToArray()), ["messagingProtected"] = true }));
app.MapPost("/v1/custom-rules", async (HttpRequest r) =>
{
    var b = await Body(r); var rule = Ops.MakeRule(S(b["rule"]) ?? S(b["domain"]), (bool?)b["allow"] == true);
    var err = Guard.CheckRule(rule); if (err != null) return Err(409, err);
    await Ops.Write("custom add " + rule, () => Ops.EditCustom(l => l.Add(rule)));
    return J(new JsonObject { ["added"] = rule, ["rules"] = new JsonArray((await Ops.CustomRules()).Select(x => (JsonNode)x).ToArray()) });
});
app.MapDelete("/v1/custom-rules", async (string rule) =>
{
    if (string.IsNullOrEmpty(rule)) return Err(400, "rule required");
    var cur = await Ops.CustomRules(); if (!cur.Contains(rule)) return Err(404, "Not in the WALLACE custom block");
    await Ops.Write("custom remove " + rule, () => Ops.EditCustom(l => l.Remove(rule)));
    return J(new JsonObject { ["removed"] = rule, ["rules"] = new JsonArray((await Ops.CustomRules()).Select(x => (JsonNode)x).ToArray()) });
});

// ---- devices ----
var pausedFile = Path.Combine(AgentConfig.DataDir, "paused.json");
JsonArray AgentPaused() { try { return JsonNode.Parse(File.ReadAllText(pausedFile)) as JsonArray ?? new(); } catch { return new(); } }
async Task<(JsonArray list, JsonArray clients)> Devices()
{
    var clients = await AdGuard.Clients(); var types = Sys.DeviceTypes(); var names = Sys.DeviceNames(); var rokus = Ops.RokuMacs();
    var dis = AdGuard.Arr((await AdGuard.Get("access/list"))["disallowed_clients"]).Select(x => (string)x).ToHashSet(StringComparer.OrdinalIgnoreCase);
    var byMac = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
    foreach (var d in Sys.DesktopDevices())
    {
        var mac = Guard.Norm((string)d?["Mac"]); if (mac == "") continue;
        byMac[mac] = new JsonObject { ["mac"] = mac, ["ip"] = (string)d["Ip"], ["network"] = (string)d["Network"], ["name"] = names.GetValueOrDefault(mac.ToUpperInvariant()) ?? names.GetValueOrDefault(mac) ?? (string)d["Name"] ?? (string)d["HostName"] ?? (string)d["MdnsName"] ?? (string)d["NbName"], ["vendor"] = (string)d["Vendor"], ["type"] = types.GetValueOrDefault(mac) ?? (string)d["Type"], ["online"] = (bool?)d["Online"] ?? false, ["lastSeen"] = (string)d["LastSeen"], ["latencyMs"] = (double?)d["LatencyMs"] };
    }
    foreach (var (ip, mac0, dyn) in Sys.ReadArp())
    {
        if (!(ip.StartsWith("192.168.137.") || ip.StartsWith("192.168.1.")) || ip.EndsWith(".255")) continue; var mac = Guard.Norm(mac0);
        if (byMac.TryGetValue(mac, out var e)) { e["ip"] = ip; if (dyn) e["online"] = true; }
        else if (dyn) byMac[mac] = new JsonObject { ["mac"] = mac, ["ip"] = ip, ["network"] = ip.StartsWith("192.168.137.") ? "Hotspot" : "Home LAN", ["name"] = names.GetValueOrDefault(mac) ?? "", ["type"] = types.GetValueOrDefault(mac), ["online"] = true };
    }
    var list = new JsonArray();
    foreach (var d in byMac.Values.OrderByDescending(x => (bool?)x["online"] == true).ThenBy(x => (string)x["network"]).ThenBy(x => (string)x["ip"]))
    {
        string ip = (string)d["ip"], mac = (string)d["mac"], name = (string)d["name"], type = (string)d["type"];
        var c = clients.FirstOrDefault(x => Guard.MatchesClient(x, ip, mac));
        if (c != null && string.IsNullOrEmpty(name)) d["name"] = name = ((string)c["name"]).Replace("SG ", "");
        string mode = c == null ? "default" : (!(bool)c["use_global_settings"] && !(bool)c["filtering_enabled"]) ? "exempt" : !(bool)c["use_global_settings"] ? "roku" : "filtered";
        bool owner = Guard.IsOwner(clients, ip, mac, name) || (c != null && Guard.IsOwnerClient(c));
        bool phone = owner || Guard.IsPhone(clients, types, ip, mac, name + " " + (string)c?["name"], type);
        bool roku = Guard.IsRoku(rokus, types, mac, name + " " + (string)c?["name"], (string)d["vendor"]);
        bool prot = Guard.ProtectedIps.Contains(ip) || AgentConfig.LocalV4().Any(a => a.ToString() == ip);
        d["client"] = (string)c?["name"]; d["mode"] = mode; d["owner"] = owner; d["phone"] = phone; d["roku"] = roku; d["protected"] = prot;
        d["paused"] = (ip != null && dis.Contains(ip)) || dis.Contains(mac);
        d["canPause"] = !(owner || phone || roku || prot);
        d["canChangeMode"] = !owner && !prot;
        d["lockReason"] = owner ? "Owner's Pixel 10 Pro XL - permanently exempt" : phone ? "Phones can never be paused (Messaging protected)" : roku ? "Rokus are protected from pause" : prot ? "Router / this PC / hotspot gateway" : null;
        list.Add(d);
    }
    return (list, clients);
}
app.MapGet("/v1/devices", async () => J((await Devices()).list));
app.MapPost("/v1/devices/{mac}/mode", async (string mac, HttpRequest r) =>
{
    var b = await Body(r); var mode = S(b["mode"]); if (mode is not ("exempt" or "roku" or "filtered")) return Err(400, "mode must be exempt, roku or filtered");
    var (list, clients) = await Devices(); var d = list.FirstOrDefault(x => string.Equals((string)x["mac"], Guard.Norm(mac), StringComparison.OrdinalIgnoreCase));
    if (d == null) return Err(404, "Unknown device");
    if ((bool)d["owner"]) return Err(403, "The owner's Pixel 10 Pro XL is permanently exempt. Its mode can't be changed.");
    if (!(bool)d["canChangeMode"]) return Err(403, (string)d["lockReason"]);
    var display = string.IsNullOrEmpty((string)d["name"]) ? (string)d["mac"] : (string)d["name"];
    await Ops.Write($"mode {d["mac"]} -> {mode}", async () => { await Ops.SetDevice(clients, display, (string)d["ip"], (string)d["mac"], mode, (bool)d["roku"] ? "Roku - " : (bool)d["phone"] ? "Phone - " : null); await Ops.ForceYoutubeUnrestricted(); });
    return J((await Devices()).list.First(x => (string)x["mac"] == (string)d["mac"]));
});
app.MapPost("/v1/devices/{mac}/pause", async (string mac, HttpRequest r) =>
{
    var b = await Body(r); bool on = (bool?)b["on"] ?? true;
    var (list, _) = await Devices(); var d = list.FirstOrDefault(x => string.Equals((string)x["mac"], Guard.Norm(mac), StringComparison.OrdinalIgnoreCase));
    if (d == null) return Err(404, "Unknown device");
    string ip = (string)d["ip"], m = (string)d["mac"];
    if (on && (bool)d["owner"]) return Err(403, "The owner's Pixel 10 Pro XL can never be paused.");
    if (on && (bool)d["phone"]) return Err(403, "Refused: phones can never be paused - texts, one-time codes, RCS/iMessage and Wi-Fi Calling must always work. (Messaging protected)");
    if (on && !(bool)d["canPause"]) return Err(403, "Refused: " + d["lockReason"]);
    bool hs = ip?.StartsWith("192.168.137.") == true; string msg = "";
    if (hs)
    {
        var (ok, log) = Sys.Helper(on ? "pause" : "unpause", ip);
        if (!ok && on) return Err(503, "Hotspot pause needs the firewall (WFP) step: " + log);
        msg = ok ? "Firewall (WFP) " + (on ? "block added. " : "block removed. ") : "";
    }
    await Ops.Write($"pause {m} {ip} -> {on}", () => Ops.SetDisallowed(new[] { ip, m }.Where(x => !string.IsNullOrEmpty(x)), on));
    var pl = AgentPaused(); foreach (var x in pl.Where(x => (string)x["mac"] == m).ToList()) pl.Remove(x); if (on) pl.Add(new JsonObject { ["mac"] = m, ["ip"] = ip, ["name"] = (string)d["name"], ["at"] = DateTimeOffset.Now.ToString("o") }); File.WriteAllText(pausedFile, pl.ToJsonString());
    msg += on ? "AdGuard access list: DNS refused for this device." : "AdGuard access entry removed.";
    if (!hs) msg += " NOTE: Spectrum Wi-Fi devices don't pass through this PC; pause them in the My Spectrum app too.";
    return Results.Json(new { message = msg });
});

// ---- reports ----
app.MapGet("/v1/reports/blocked", async (int? hours) =>
{
    int h = Math.Clamp(hours ?? 24, 1, 24 * 14); var since = DateTime.Now.AddHours(-h);
    var byClient = new Dictionary<string, int>(); var byDomain = new Dictionary<string, int>(); var byReason = new Dictionary<string, int>(); var buckets = new SortedDictionary<string, int>(); int total = 0; string older = null;
    for (int page = 0; page < 20; page++)
    {
        var q = await AdGuard.Get("querylog?response_status=blocked&limit=500" + (older == null ? "" : "&older_than=" + Uri.EscapeDataString(older)));
        var data = AdGuard.Arr(q["data"]); if (data.Count == 0) break; bool past = false;
        foreach (var e in data)
        {
            if (!DateTime.TryParse((string)e["time"], out var t)) continue; if (t < since) { past = true; break; }
            total++; var cl = (string)e["client_info"]?["name"]; cl = string.IsNullOrEmpty(cl) ? (string)e["client"] : cl; byClient[cl] = byClient.GetValueOrDefault(cl) + 1;
            var dm = (string)e["question"]?["name"] ?? "?"; byDomain[dm] = byDomain.GetValueOrDefault(dm) + 1;
            var rs = (string)e["service_name"]; rs = string.IsNullOrEmpty(rs) ? (string)e["reason"] : "Service: " + rs; byReason[rs] = byReason.GetValueOrDefault(rs) + 1;
            var key = h <= 48 ? t.ToString("yyyy-MM-dd HH:00") : t.ToString("yyyy-MM-dd"); buckets[key] = buckets.GetValueOrDefault(key) + 1;
        }
        older = (string)q["oldest"]; if (past || older == null) break;
    }
    JsonArray Top(Dictionary<string, int> d, int n) => new(d.OrderByDescending(k => k.Value).Take(n).Select(k => (JsonNode)new JsonObject { ["key"] = k.Key, ["count"] = k.Value }).ToArray());
    return J(new JsonObject { ["hours"] = h, ["total"] = total, ["byDevice"] = Top(byClient, 20), ["byDomain"] = Top(byDomain, 25), ["byReason"] = Top(byReason, 10), ["buckets"] = new JsonArray(buckets.Select(k => (JsonNode)new JsonObject { ["key"] = k.Key, ["count"] = k.Value }).ToArray()) });
});

// ---- updates / logs ----
app.MapGet("/v1/updates", async (bool? windows, bool? refresh) =>
{
    if (Sys.Updates == null || refresh == true || (windows == true && !(Sys.Updates?.Any(x => (string)x["name"] == "Windows Update") ?? false)) || (DateTime.Now - Sys.UpdatesAt).TotalMinutes > 30) await Sys.RefreshUpdates(windows == true);
    return J(new JsonObject { ["time"] = new DateTimeOffset(Sys.UpdatesAt).ToString("o"), ["items"] = Sys.Updates?.DeepClone() ?? new JsonArray(), ["readOnly"] = true });
});
app.MapGet("/v1/logs/{name}", (string name, int? lines) =>
{
    var n = Math.Clamp(lines ?? 150, 10, 1000);
    string path = name switch { "watchdog" => Path.Combine(Sys.V2, @"logs\watchdog.log"), "hotspot" => Path.Combine(Sys.V2, @"logs\hotspot.log"), "agent" => Path.Combine(AgentConfig.LogDir, "agent.log"), "audit" => Path.Combine(AgentConfig.LogDir, "remote-api.log"), "app" => Path.Combine(AgentConfig.Current.AdminDataDir, "logs", $"app-{DateTime.Now:yyyyMMdd}.log"), _ => null };
    if (path == null) return Err(404, "logs: watchdog, hotspot, agent, audit, app");
    return J(new JsonObject { ["name"] = name, ["lines"] = new JsonArray(Log.Tail(path, n).Select(x => (JsonNode)x).ToArray()) });
});

// ---- live (WebSocket): status snapshot every 5 s ----
app.Map("/v1/live", async (HttpContext ctx) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
    using var ws = await ctx.WebSockets.AcceptWebSocketAsync(); var buf = new byte[1024];
    var recv = ws.ReceiveAsync(buf, ctx.RequestAborted);
    while (ws.State == WebSocketState.Open && !ctx.RequestAborted.IsCancellationRequested)
    {
        var snap = await Status(); snap["type"] = "status";
        var bytes = Encoding.UTF8.GetBytes(snap.ToJsonString());
        try { await ws.SendAsync(bytes, WebSocketMessageType.Text, true, ctx.RequestAborted); } catch { break; }
        var done = await Task.WhenAny(recv, Task.Delay(5000, ctx.RequestAborted).ContinueWith(_ => { }));
        if (done == recv) { if (recv.Result.MessageType == WebSocketMessageType.Close) break; recv = ws.ReceiveAsync(buf, ctx.RequestAborted); }
    }
    try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None); } catch { }
});

// ---- background refresh ----
_ = Task.Run(async () =>
{
    int tick = 0;
    while (true)
    {
        try { if (tick % 6 == 0) await Sys.RefreshHotspot(); } catch (Exception ex) { Log.Agent("hotspot: " + ex.Message); }
        try { if (tick % 6 == 0) await Sys.RunMonitors(); } catch (Exception ex) { Log.Agent("monitors: " + ex.Message); }
        try { if (tick % 60 == 0) _ = Task.Run(Sys.RefreshHealth); } catch { }
        try { if (tick % 60 == 3) await Ops.ForceYoutubeUnrestricted(); } catch { }
        tick++; await Task.Delay(5000);
    }
});

app.Run();
return 0;
