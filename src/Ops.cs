using System.Text.Json.Nodes;

namespace WallaceAgent;

/// <summary>Safe Guard + Blocking + Admin custom rules, ported from WALLACE Admin (SafeGuard.cs / Blocking.cs / Admin.cs).
/// Same AdGuard names and markers, so the desktop app sees exactly the same state.</summary>
public static class Ops
{
    public static readonly (string name, string url, bool core)[] AdultLists =
    {
        ("Safe Guard: HaGeZi NSFW", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt", true),
        ("Safe Guard: OISD NSFW", "https://nsfw.oisd.nl", true),
        ("Safe Guard: StevenBlack porn-only", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts", true),
        ("Safe Guard: Block List Project porn (optional)", "https://blocklistproject.github.io/Lists/adguard/porn-ags.txt", false),
    };
    public static readonly string[] BypassListUrls = { "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt" };
    public static readonly string[] BypassRules = { "||mask.icloud.com^", "||mask-h2.icloud.com^", "||use-application-dns.net^" };
    public static readonly string[] GoogleAllow = { "@@|google.com^", "@@|www.google.com^" };
    public static readonly string[] OtherSocial = { "tiktok", "snapchat", "facebook", "twitter", "reddit", "discord", "tinder", "onlyfans" };
    const string BypBegin = "! SafeGuard:bypass begin", BypEnd = "! SafeGuard:bypass end", PausedPfx = "! SG-paused ";
    public const string CustomBegin = "! WALLACE custom begin", CustomEnd = "! WALLACE custom end";
    public record ListDef(string Name, string Url, bool Default);
    public record Category(string Key, string Title, string Help, ListDef[] Lists, bool DefaultOn);

    public static readonly Category[] Categories =
    {
        new("ads", "Ads on websites and apps", "AdGuard DNS filter + HaGeZi Pro (ads, trackers, pop-ups). The best-balanced DNS ad lists on GitHub.",
            new ListDef[] { new("Safe Guard+ [ads] AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", true),
                            new("Safe Guard+ [ads] HaGeZi Pro", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", true),
                            new("Safe Guard+ [ads] HaGeZi pop-up ads", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt", true) }, true),
        new("strict", "Extra-strict ads, trackers and cookie/consent trackers", "HaGeZi Pro++ + OISD Big + 1Hosts Lite. Catches more tracking/consent-tracker domains; slightly higher chance a site breaks.",
            new ListDef[] { new("Safe Guard+ [strict] HaGeZi Pro++", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt", true),
                            new("Safe Guard+ [strict] OISD Big", "https://big.oisd.nl", true),
                            new("Safe Guard+ [strict] 1Hosts Lite", "https://o0.pages.dev/Lite/adblock.txt", true) }, false),
        new("malware", "Malware, phishing and scam / fake shops", "HaGeZi Threat Intelligence Feeds, URLhaus, Phishing Army, phishing-filter, HaGeZi Fake (scam shops, fake support) + AdGuard browsing security.",
            new ListDef[] { new("Safe Guard+ [malware] HaGeZi TIF medium", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt", true),
                            new("Safe Guard+ [malware] URLhaus", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt", true),
                            new("Safe Guard+ [malware] Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", true),
                            new("Safe Guard+ [malware] phishing-filter", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt", true),
                            new("Safe Guard+ [malware] HaGeZi Fake (scams)", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt", true) }, true),
        new("crypto", "Crypto-mining in the browser", "NoCoin list (hoshsadiq). HaGeZi TIF also covers mining pools.",
            new ListDef[] { new("Safe Guard+ [crypto] NoCoin", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", true) }, true),
        new("telemetry", "Device telemetry (Windows/Office, TikTok)", "HaGeZi native trackers for Windows/Office and TikTok. Does not block Windows Update or Defender. Roku/LG telemetry lists are NOT used (they can break the TVs).",
            new ListDef[] { new("Safe Guard+ [telemetry] HaGeZi Windows/Office", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.winoffice.txt", true),
                            new("Safe Guard+ [telemetry] HaGeZi TikTok", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.tiktok.extended.txt", true) }, false),
        new("gambling", "Gambling", "HaGeZi Gambling list.",
            new ListDef[] { new("Safe Guard+ [gambling] HaGeZi Gambling", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt", true) }, false),
    };

    /// <summary>Always-on allow rules so YouTube on the Rokus, iSponsorBlockTV and Roku itself keep working whatever lists are on.</summary>
    public static readonly string[] AllowRules =
    {
        "@@||googlevideo.com^", "@@||youtubei.googleapis.com^", "@@||s.youtube.com^", "@@||youtube.com^", "@@||www.youtube.com^", "@@||m.youtube.com^",
        "@@||ytimg.com^", "@@||ggpht.com^", "@@||youtube-nocookie.com^", "@@||sponsor.ajay.app^", "@@||sponsorblock.hankmccord.dev^",
        // Roku: only what the TV needs to boot, sign in, show the home screen/channel store, keep time and update firmware.
        // (cooper.logs.roku.com was allow-listed before, which overrode the logs.roku.com block - removed in 3.1.0.)
        "@@||api.roku.com^", "@@||image.roku.com^", "@@||channels.roku.com^", "@@||captive.roku.com^", "@@||ntp.roku.com^", "@@||time.roku.com^",
        "@@||cloudservices.roku.com^", "@@||sr.roku.com^", "@@||wwwimg.roku.com^", "@@||my.roku.com^", "@@||firmware.roku.com^",
        "@@||lgtvsdp.com^", "@@||lgappstv.com^",
    };
    const string AllowBegin = "! SafeGuard+:allow begin (Roku/YouTube/iSponsorBlockTV)", AllowEnd = "! SafeGuard+:allow end";

    static readonly SemaphoreSlim writeLock = new(1, 1);

    /// <summary>Serialises writes, backs up first, and after every write verifies the messaging self-test hosts are not filtered;
    /// on failure the previous user rules are restored and the call fails (409).</summary>
    public static async Task Write(string why, Func<Task> action)
    {
        await writeLock.WaitAsync();
        try
        {
            await AdGuard.Backup(why); var before = await AdGuard.UserRules();
            await action();
            var bad = new List<string>();
            foreach (var h in Messaging.SelfTestHosts) { var r = await AdGuard.CheckHost(h); if (r.StartsWith("Filtered")) bad.Add(h + "=" + r); }
            if (bad.Count > 0)
            {
                Log.Agent("messaging self-test FAILED after '" + why + "': " + string.Join(", ", bad) + " - rolling back user rules");
                await AdGuard.SetRules(before);
                throw new GuardException(409, "Rolled back: the change would have blocked messaging (" + string.Join(", ", bad) + ").");
            }
            Log.Agent("write ok: " + why);
        }
        finally { writeLock.Release(); }
    }

    // ---------- Safe Guard ----------
    public static async Task<JsonObject> SafeGuardState()
    {
        var f = await AdGuard.Get("filtering/status"); var filters = AdGuard.Arr(f["filters"]);
        bool En(string url) => filters.Any(x => (string)x["url"] == url && (bool)x["enabled"]);
        var rules = AdGuard.Arr(f["user_rules"]).Select(r => (string)r).ToList();
        var ss = await AdGuard.Get("safesearch/status");
        var bs = AdGuard.Arr((await AdGuard.Get("blocked_services/get"))["ids"]).Select(x => (string)x).ToList();
        var clients = await AdGuard.Clients();
        var rokuClients = clients.Where(c => ((string)c["name"] ?? "").StartsWith("SG Roku -")).ToList();
        bool exemptRokus = rokuClients.Count > 0 && rokuClients.All(c => !(bool)c["use_global_settings"] && (bool)c["filtering_enabled"]);
        var sgIds = filters.Where(x => ((string)x["name"] ?? "").StartsWith("Safe Guard")).Select(x => (long)x["id"]).ToHashSet();
        var idToCat = new Dictionary<long, string>();
        foreach (var c in Categories) foreach (var x in filters.Where(x => c.Lists.Any(l => l.Url == (string)x["url"]))) idToCat[(long)x["id"]] = c.Key;
        int blocked24 = 0; var tally = new Dictionary<string, int>(); var catCount = new Dictionary<string, int>();
        try
        {
            var q = await AdGuard.Get("querylog?response_status=blocked&limit=1000"); var since = DateTime.Now.AddHours(-24);
            foreach (var e in AdGuard.Arr(q["data"]))
            {
                if (!DateTime.TryParse((string)e["time"], out var t) || t < since) continue;
                string reason = (string)e["reason"] ?? ""; bool sg = reason is "FilteredBlockedService" or "FilteredParental" or "FilteredSafeSearch";
                foreach (var r in AdGuard.Arr(e["rules"])) if (r?["filter_list_id"] != null) { var id = (long)r["filter_list_id"]; if (sgIds.Contains(id)) sg = true; if (idToCat.TryGetValue(id, out var ck)) catCount[ck] = catCount.GetValueOrDefault(ck) + 1; }
                if (!sg) continue; blocked24++; var d = (string)e["question"]?["name"] ?? "?"; tally[d] = tally.GetValueOrDefault(d) + 1;
            }
        }
        catch (Exception ex) { Log.Agent("querylog: " + ex.Message); }
        var cats = new JsonArray();
        foreach (var c in Categories)
        {
            var mine = filters.Where(x => c.Lists.Any(l => l.Url == (string)x["url"])).ToList();
            bool on = mine.Count > 0 && c.Lists.Where(l => l.Default).All(l => mine.Any(x => (string)x["url"] == l.Url && (bool)x["enabled"]));
            cats.Add(new JsonObject { ["key"] = c.Key, ["title"] = c.Title, ["help"] = c.Help, ["on"] = on, ["rules"] = mine.Where(x => (bool)x["enabled"]).Sum(x => (int?)x["rules_count"] ?? 0), ["blocked24h"] = catCount.GetValueOrDefault(c.Key) });
        }
        bool adult = AdultLists.Where(a => a.core).All(a => En(a.url));
        bool safe = (bool)ss["enabled"] && !GoogleAllow.Any(rules.Contains);
        bool insta = bs.Contains("instagram"), social = OtherSocial.All(bs.Contains);
        return new JsonObject
        {
            ["master"] = adult || insta || social || safe,
            ["adult"] = adult, ["adultExtra"] = En(AdultLists[3].url), ["instagram"] = insta, ["social"] = social, ["safeSearch"] = safe,
            ["youtubeRestricted"] = (bool?)ss["youtube"] == true, ["bypass"] = rules.Contains(BypBegin) && BypassListUrls.All(En),
            ["parental"] = (bool)(await AdGuard.Get("parental/status"))["enabled"], ["exemptRokus"] = exemptRokus, ["rokuClients"] = rokuClients.Count,
            ["categories"] = cats, ["blocked24h"] = blocked24,
            ["top"] = new JsonArray(tally.OrderByDescending(k => k.Value).Take(10).Select(k => (JsonNode)new JsonObject { ["domain"] = k.Key, ["count"] = k.Value }).ToArray()),
            ["messagingProtected"] = true, ["messagingExplain"] = Messaging.Explain,
        };
    }

    static async Task EditRules(Func<List<string>, List<string>> edit) { var r = await AdGuard.UserRules(); await AdGuard.SetRules(edit(r)); }

    public static async Task SetAdult(bool on, bool extra)
    {
        var filters = AdGuard.Arr((await AdGuard.Get("filtering/status"))["filters"]);
        foreach (var a in AdultLists)
        {
            bool want = on && (a.core || extra);
            if (!filters.Any(x => (string)x["url"] == a.url)) { if (!want) continue; await AdGuard.Send("POST", "filtering/add_url", new JsonObject { ["name"] = a.name, ["url"] = a.url, ["whitelist"] = false }); }
            await AdGuard.Send("POST", "filtering/set_url", new JsonObject { ["url"] = a.url, ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = a.name, ["url"] = a.url, ["enabled"] = want } });
        }
        await AdGuard.Send("POST", on ? "parental/enable" : "parental/disable", new JsonObject());
    }
    public static async Task SetServices(bool insta, bool social)
    {
        var cur = AdGuard.Arr((await AdGuard.Get("blocked_services/get"))["ids"]).Select(x => (string)x).ToList();
        cur.Remove("instagram"); cur.RemoveAll(OtherSocial.Contains); if (insta) cur.Add("instagram"); if (social) cur.AddRange(OtherSocial);
        await AdGuard.Send("PUT", "blocked_services/update", new JsonObject { ["ids"] = new JsonArray(cur.Distinct().Select(x => (JsonNode)x).ToArray()), ["schedule"] = new JsonObject { ["time_zone"] = "Local" } });
    }
    /// <summary>YouTube is ALWAYS false (Rokus share the hotspot DNS identity and need unrestricted YouTube).</summary>
    public static async Task SetSafeSearch(bool on)
    {
        await AdGuard.Send("PUT", "safesearch/settings", new JsonObject { ["enabled"] = on, ["bing"] = true, ["duckduckgo"] = true, ["ecosia"] = true, ["google"] = true, ["pixabay"] = true, ["yandex"] = true, ["youtube"] = false });
        await EditRules(r => r.Select(x => on && GoogleAllow.Contains(x) ? PausedPfx + x : !on && x.StartsWith(PausedPfx) && GoogleAllow.Contains(x[PausedPfx.Length..]) ? x[PausedPfx.Length..] : x).ToList());
    }
    public static async Task ForceYoutubeUnrestricted()
    {
        var ss = await AdGuard.Get("safesearch/status"); if ((bool?)ss["youtube"] != true) return;
        var b = ss.DeepClone().AsObject(); b["youtube"] = false; await AdGuard.Send("PUT", "safesearch/settings", b); Log.Agent("forced safesearch.youtube=false");
    }
    public static async Task SetBypass(bool on)
    {
        await EditRules(r => { int b = r.IndexOf(BypBegin), e = r.IndexOf(BypEnd); if (b >= 0 && e > b) r.RemoveRange(b, e - b + 1); if (on) { r.Add(BypBegin); r.AddRange(BypassRules); r.Add(BypEnd); } return r; });
        foreach (var x in AdGuard.Arr((await AdGuard.Get("filtering/status"))["filters"]))
            if (BypassListUrls.Contains((string)x["url"]))
                await AdGuard.Send("POST", "filtering/set_url", new JsonObject { ["url"] = (string)x["url"], ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = (string)x["name"], ["url"] = (string)x["url"], ["enabled"] = on } });
    }
    public static async Task SetCategory(string key, bool on)
    {
        var c = Categories.FirstOrDefault(x => x.Key == key) ?? throw new GuardException(400, "Unknown category " + key);
        await EnsureAllow();
        var filters = AdGuard.Arr((await AdGuard.Get("filtering/status"))["filters"]);
        foreach (var l in c.Lists)
        {
            bool want = on && l.Default;
            if (!filters.Any(x => (string)x["url"] == l.Url)) { if (!want) continue; await AdGuard.Send("POST", "filtering/add_url", new JsonObject { ["name"] = l.Name, ["url"] = l.Url, ["whitelist"] = false }); }
            await AdGuard.Send("POST", "filtering/set_url", new JsonObject { ["url"] = l.Url, ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = l.Name, ["url"] = l.Url, ["enabled"] = want } });
        }
        if (key == "malware" && on) await AdGuard.Send("POST", "safebrowsing/enable", new JsonObject());
    }
    public static async Task EnsureAllow()
    {
        var rules = await AdGuard.UserRules();
        int b = rules.IndexOf(AllowBegin), e = rules.IndexOf(AllowEnd); if (b >= 0 && e > b) rules.RemoveRange(b, e - b + 1);
        var seen = new HashSet<string>(AllowRules); rules = rules.Where(r => r.StartsWith("!") || seen.Add(r)).ToList();
        rules.RemoveAll(r => r == "@@||cooper.logs.roku.com^");
        var block = new List<string> { AllowBegin }; block.AddRange(AllowRules); block.Add(AllowEnd); rules.InsertRange(0, block);
        await AdGuard.SetRules(rules);
    }

    // ---------- Roku exemption / per-device mode ----------
    public static JsonObject ClientBody(string name, IEnumerable<string> ids, string mode, JsonArray tags)
    {
        bool exempt = mode == "exempt", roku = mode == "roku";
        return new JsonObject
        {
            ["name"] = name, ["ids"] = new JsonArray(ids.Distinct(StringComparer.OrdinalIgnoreCase).Select(i => (JsonNode)i).ToArray()), ["tags"] = tags ?? new JsonArray(),
            ["use_global_settings"] = !(exempt || roku), ["filtering_enabled"] = !exempt, ["parental_enabled"] = false, ["safebrowsing_enabled"] = false,
            ["safe_search"] = new JsonObject { ["enabled"] = false }, ["use_global_blocked_services"] = !(exempt || roku), ["blocked_services"] = new JsonArray(),
            ["blocked_services_schedule"] = new JsonObject { ["time_zone"] = "Local" }, ["upstreams"] = new JsonArray(), ["ignore_querylog"] = false, ["ignore_statistics"] = false,
        };
    }
    public static async Task SetDevice(JsonArray clients, string display, string ip, string mac, string mode, string prefix = null)
    {
        var c = clients.FirstOrDefault(x => Guard.MatchesClient(x, ip, mac));
        var ids = new List<string>(); if (!string.IsNullOrEmpty(ip)) ids.Add(ip); if (!string.IsNullOrEmpty(mac)) ids.Add(Guard.Norm(mac));
        if (c != null)
        {
            bool macKnown = !string.IsNullOrEmpty(mac) && c["ids"].AsArray().Any(x => string.Equals(Guard.Norm((string)x), Guard.Norm(mac)));
            foreach (var i in c["ids"].AsArray()) { var v = (string)i; if (macKnown && !string.IsNullOrEmpty(ip) && System.Net.IPAddress.TryParse(v, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) continue; ids.Add(v); }
            string name = (string)c["name"];
            await AdGuard.Send("POST", "clients/update", new JsonObject { ["name"] = name, ["data"] = ClientBody(name, ids, mode, c["tags"]?.DeepClone() as JsonArray) });
        }
        else await AdGuard.Send("POST", "clients/add", ClientBody("SG " + (prefix ?? (mode == "roku" ? "Roku - " : "")) + display, ids, mode, null));
    }
    public static HashSet<string> RokuMacs()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try { foreach (var l in File.ReadAllLines(Path.Combine(AgentConfig.Current.ToolsDir, @"roku-dhcp\roku-macs.txt"))) if (!l.TrimStart().StartsWith("#") && l.Contains(',')) set.Add(Guard.Norm(l.Split(',')[0].Trim())); } catch { }
        return set;
    }
    public static async Task SetRokuExempt(bool exempt)
    {
        var mode = exempt ? "roku" : "filtered"; var clients = await AdGuard.Clients();
        try
        {
            foreach (var l in File.ReadAllLines(Path.Combine(AgentConfig.Current.ToolsDir, @"roku-dhcp\roku-macs.txt")).Where(l => !l.TrimStart().StartsWith("#") && l.Contains(',')))
            { var p = l.Split(','); var mac = p[0].Trim(); var ip = p.Length > 1 ? p[1].Trim() : ""; var nm = p.Length > 2 ? p[2].Trim() : mac; await SetDevice(clients, nm, ip, mac, mode, "Roku - "); clients = await AdGuard.Clients(); }
        }
        catch (Exception ex) { Log.Agent("roku clients: " + ex.Message); }
        foreach (var c in clients.Where(c => ((string)c["name"] ?? "").StartsWith("SG Roku -")).ToList())
        {
            var name = (string)c["name"]; var ids = c["ids"].AsArray().Select(i => (string)i);
            await AdGuard.Send("POST", "clients/update", new JsonObject { ["name"] = name, ["data"] = ClientBody(name, ids, mode, c["tags"]?.DeepClone() as JsonArray) });
        }
        await EnsureAllow(); await ForceYoutubeUnrestricted();
    }

    // ---------- custom rules (Admin custom block only) ----------
    public static async Task<List<string>> CustomRules()
    {
        var r = await AdGuard.UserRules(); int b = r.IndexOf(CustomBegin), e = r.IndexOf(CustomEnd); return b >= 0 && e > b ? r.GetRange(b + 1, e - b - 1) : new();
    }
    public static string MakeRule(string input, bool allow)
    {
        var s = (input ?? "").Trim(); if (s == "" || s.StartsWith("!")) throw new GuardException(400, "Empty rule");
        if (s.Contains('|') || s.Contains('^') || s.Contains('$') || s.StartsWith("/")) return s;
        s = s.Replace("https://", "").Replace("http://", "").Split('/')[0].Trim('.').ToLowerInvariant();
        if (!System.Text.RegularExpressions.Regex.IsMatch(s, @"^[a-z0-9.-]+\.[a-z0-9-]+$")) throw new GuardException(400, "Not a domain: " + s);
        return (allow ? "@@||" : "||") + s + "^";
    }
    public static async Task EditCustom(Action<List<string>> edit)
    {
        var all = await AdGuard.UserRules(); int b = all.IndexOf(CustomBegin), e = all.IndexOf(CustomEnd); var mine = new List<string>();
        if (b >= 0 && e > b) { mine = all.GetRange(b + 1, e - b - 1); all.RemoveRange(b, e - b + 1); }
        edit(mine); mine = mine.Distinct().ToList();
        if (mine.Count > 0) { all.Add(CustomBegin); all.AddRange(mine); all.Add(CustomEnd); }
        await AdGuard.SetRules(all);
    }

    // ---------- pause (AdGuard access list) ----------
    public static async Task SetDisallowed(IEnumerable<string> ids, bool on)
    {
        var a = await AdGuard.Get("access/list"); var dis = AdGuard.Arr(a["disallowed_clients"]).Select(x => (string)x).ToList();
        foreach (var i in ids) { if (Guard.ProtectedIps.Contains(i)) continue; dis.RemoveAll(x => string.Equals(x, i, StringComparison.OrdinalIgnoreCase)); if (on) dis.Add(i); }
        await AdGuard.Send("POST", "access/set", new JsonObject { ["allowed_clients"] = a["allowed_clients"]?.DeepClone() ?? new JsonArray(), ["disallowed_clients"] = new JsonArray(dis.Select(x => (JsonNode)x).ToArray()), ["blocked_hosts"] = a["blocked_hosts"]?.DeepClone() ?? new JsonArray() });
    }
}

public class GuardException : Exception { public int Code; public GuardException(int code, string msg) : base(msg) { Code = code; } }
