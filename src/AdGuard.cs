using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WallaceAgent;

/// <summary>Local AdGuard Home client (127.0.0.1:3000). Credentials are read from the admin file only to build the auth header,
/// never logged or returned. Every set_rules write is forced through Messaging.Enforce().</summary>
public static class AdGuard
{
    const string Base = "http://127.0.0.1:3000/control/";
    static HttpClient http; static readonly object g = new();
    static HttpClient Http()
    {
        if (http != null) return http;
        lock (g)
        {
            if (http != null) return http;
            var t = File.ReadAllText(Path.Combine(AgentConfig.Current.ToolsDir, @"AdGuardHome\ADMIN-LOGIN.txt"));
            string u = Regex.Match(t, @"(?i)user\w*\s*[:=]\s*(\S+)").Groups[1].Value, p = Regex.Match(t, @"(?i)pass\w*\s*[:=]\s*(\S+)").Groups[1].Value;
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            h.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(u + ":" + p)));
            return http = h;
        }
    }
    static async Task<HttpResponseMessage> Do(Func<HttpRequestMessage> mk)
    {
        var r = await Http().SendAsync(mk());
        if (r.StatusCode == System.Net.HttpStatusCode.Unauthorized) { Log.Agent("adguard 401, reloading credentials"); lock (g) http = null; r = await Http().SendAsync(mk()); }
        return r;
    }
    public static async Task<JsonNode> Get(string path)
    {
        var r = await Do(() => new HttpRequestMessage(HttpMethod.Get, Base + path));
        if (!r.IsSuccessStatusCode) throw new Exception($"AdGuard {path.Split('?')[0]}: {(int)r.StatusCode}");
        return JsonNode.Parse(await r.Content.ReadAsStringAsync());
    }
    public static async Task Send(string method, string path, JsonNode body)
    {
        if (path == "filtering/set_rules" && body is JsonObject bo)
            bo["rules"] = new JsonArray(Messaging.Enforce((bo["rules"]?.AsArray() ?? new JsonArray()).Select(x => (string)x)).Select(x => (JsonNode)x).ToArray());
        HttpRequestMessage Mk() { var req = new HttpRequestMessage(new HttpMethod(method), Base + path) { Content = new StringContent(body?.ToJsonString() ?? "{}", Encoding.UTF8, "application/json") }; req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json"); return req; }
        var r = await Do(Mk);
        if (!r.IsSuccessStatusCode) throw new Exception($"AdGuard {path}: {(int)r.StatusCode} {Log.Redact(await r.Content.ReadAsStringAsync())}");
    }
    public static JsonArray Arr(JsonNode n) => n as JsonArray ?? new JsonArray();
    public static async Task<List<string>> UserRules() => Arr((await Get("filtering/status"))["user_rules"]).Select(r => (string)r).Where(r => !string.IsNullOrEmpty(r)).ToList();
    public static Task SetRules(IEnumerable<string> rules) => Send("POST", "filtering/set_rules", new JsonObject { ["rules"] = new JsonArray(rules.Select(r => (JsonNode)r).ToArray()) });
    public static async Task<JsonArray> Clients() => Arr((await Get("clients"))["clients"]);
    public static async Task<string> CheckHost(string host, string client = null)
    {
        var r = await Get("filtering/check_host?name=" + Uri.EscapeDataString(host) + (string.IsNullOrEmpty(client) ? "" : "&client=" + Uri.EscapeDataString(client)));
        return (string)r["reason"] ?? "?";
    }
    public static async Task<JsonNode> CheckHostFull(string host, string client = null) =>
        await Get("filtering/check_host?name=" + Uri.EscapeDataString(host) + (string.IsNullOrEmpty(client) ? "" : "&client=" + Uri.EscapeDataString(client)));

    /// <summary>Backup of AdGuard settings via the API (no secrets) before every write.</summary>
    public static async Task<string> Backup(string why)
    {
        var dir = Path.Combine(AgentConfig.DataDir, "backups"); Directory.CreateDirectory(dir);
        var o = new JsonObject { ["time"] = DateTime.Now.ToString("s"), ["reason"] = why };
        foreach (var k in new[] { "filtering/status", "clients", "blocked_services/get", "safesearch/status", "access/list", "parental/status", "safebrowsing/status" })
            try { o[k] = await Get(k); } catch (Exception ex) { o[k] = "ERROR " + Log.Redact(ex.Message); }
        if (o["clients"] is JsonObject c) c.Remove("auto_clients");
        if (o["filtering/status"] is JsonObject fs && fs["filters"] is JsonArray) { } // keep lists (urls/names only)
        var f = Path.Combine(dir, $"adguard-{DateTime.Now:yyyyMMdd-HHmmss-fff}.json");
        await File.WriteAllTextAsync(f, o.ToJsonString(new JsonSerializerOptions { WriteIndented = true })); return f;
    }
}
