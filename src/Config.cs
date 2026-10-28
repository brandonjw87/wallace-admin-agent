using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WallaceAgent;

public class AgentConfig
{
    public int Port { get; set; } = 8088;
    /// <summary>"auto" = every up IPv4 on the home LAN (192.168.1.x) plus any Tailscale address (192.0.2.22/10). Never 0.0.0.0, never the hotspot.</summary>
    public List<string> Bind { get; set; } = new() { "auto" };
    public List<string> AllowedNetworks { get; set; } = new() { "192.0.2.20/24", "192.0.2.22/10" };
    public string ToolsDir { get; set; } = @"C:\Users\YOU\Tools";
    public string AdminDataDir { get; set; } = @"C:\Users\YOU\AppData\Local\WALLACE Admin";
    public string KumaUrl { get; set; } = "http://127.0.0.1:3001";
    public string KumaStatusSlug { get; set; } = "";
    public int RateLimitPerMinute { get; set; } = 240;

    public static string DataDir { get { var d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WALLACE Agent"); Directory.CreateDirectory(d); return d; } }
    public static string LogDir { get { var d = Path.Combine(DataDir, "logs"); Directory.CreateDirectory(d); return d; } }
    static string FilePath => Path.Combine(DataDir, "agent.json");
    public static AgentConfig Current { get; private set; } = Load();
    static AgentConfig Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(FilePath)) ?? new(); } catch { }
        var c = new AgentConfig(); try { File.WriteAllText(FilePath, JsonSerializer.Serialize(c, new JsonSerializerOptions { WriteIndented = true })); } catch { } return c;
    }

    public static IEnumerable<IPAddress> LocalV4() => NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
        .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork);

    public List<IPAddress> BindAddresses()
    {
        var res = new List<IPAddress>();
        foreach (var b in Bind)
        {
            if (b == "auto") res.AddRange(LocalV4().Where(a => a.ToString().StartsWith("192.168.1.") || InCidr(a, "192.0.2.22/10")));
            else if (IPAddress.TryParse(b, out var ip) && !ip.Equals(IPAddress.Any) && !ip.ToString().StartsWith("192.168.137.")) res.Add(ip);
        }
        return res.Distinct().ToList();
    }
    public bool Allowed(IPAddress a)
    {
        if (a == null) return false; if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        return AllowedNetworks.Any(n => InCidr(a, n)) || LocalV4().Any(l => l.Equals(a));
    }
    public static bool InCidr(IPAddress a, string cidr)
    {
        var p = cidr.Split('/'); if (!IPAddress.TryParse(p[0], out var net) || a.AddressFamily != net.AddressFamily) return false;
        int bits = p.Length > 1 ? int.Parse(p[1]) : 32; var ab = a.GetAddressBytes(); var nb = net.GetAddressBytes();
        for (int i = 0; i < ab.Length && bits > 0; i++, bits -= 8) { int m = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF; if ((ab[i] & m) != (nb[i] & m)) return false; }
        return true;
    }
}

public static class Log
{
    static readonly object g = new();
    static readonly Regex Secret = new(@"(?i)(pass\w*|secret\w*|private_key|token|psk|api[_-]?key|authorization|bearer)(\s*[:=]?\s*)\S+", RegexOptions.Compiled);
    public static string Redact(string s) => s == null ? "" : Secret.Replace(s, "$1$2<redacted>");
    public static void Write(string file, string msg) { try { lock (g) File.AppendAllText(Path.Combine(AgentConfig.LogDir, file), $"{DateTime.Now:s} {Redact(msg)}\r\n"); } catch { } }
    public static void Agent(string m) => Write("agent.log", m);
    public static void Audit(string m) => Write("remote-api.log", m);
    static readonly string[] Forbidden = { "ADMIN-LOGIN", "AdGuardHome.yaml", "HOTSPOT-PASSWORD", "dev-config-backup", ".webui_secret_key", "client-key", "EverydayOfEvey" };
    public static bool IsForbidden(string path) => Forbidden.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
    public static List<string> Tail(string path, int n)
    {
        if (IsForbidden(path) || !File.Exists(path)) return new();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); using var r = new StreamReader(fs);
        var q = new Queue<string>(); string l; while ((l = r.ReadLine()) != null) { q.Enqueue(Redact(l)); if (q.Count > n) q.Dequeue(); }
        return q.ToList();
    }
}
