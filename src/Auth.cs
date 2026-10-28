using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WallaceAgent;

public class DeviceToken { public string Id { get; set; } public string Name { get; set; } public string Hash { get; set; } public DateTime Created { get; set; } public DateTime? LastUsed { get; set; } public bool Revoked { get; set; } }
public class PairCode { public string Hash { get; set; } public DateTime Expires { get; set; } public string Name { get; set; } }
class TokenStore { public List<DeviceToken> Tokens { get; set; } = new(); public List<PairCode> Pending { get; set; } = new(); }

/// <summary>Device tokens: 256-bit random, only SHA-256 hashes are stored, and the store file is DPAPI (LocalMachine) protected.
/// Pairing: a one-time 256-bit code (10 min) shown as a QR on the PC is exchanged for a long-lived device token.</summary>
public static class Auth
{
    static readonly object g = new();
    static string FilePath => Path.Combine(AgentConfig.DataDir, "tokens.dat");
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("WALLACE Agent token store v1");

    static TokenStore Load()
    {
        try { if (!File.Exists(FilePath)) return new(); var raw = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), Entropy, DataProtectionScope.LocalMachine); return JsonSerializer.Deserialize<TokenStore>(raw) ?? new(); }
        catch (Exception ex) { Log.Agent("token store unreadable: " + ex.GetType().Name); return new(); }
    }
    static void Save(TokenStore s) { var b = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(s), Entropy, DataProtectionScope.LocalMachine); var tmp = FilePath + ".tmp"; File.WriteAllBytes(tmp, b); File.Move(tmp, FilePath, true); }

    public static string NewSecret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s ?? "")));
    static bool Eq(string a, string b) => CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));

    public static string CreatePairCode(string name)
    {
        var code = NewSecret();
        lock (g) { var s = Load(); s.Pending.RemoveAll(p => p.Expires < DateTime.UtcNow); s.Pending.Add(new PairCode { Hash = Hash(code), Expires = DateTime.UtcNow.AddMinutes(10), Name = name }); Save(s); }
        return code;
    }
    public static (string id, string token)? Redeem(string code, string deviceName)
    {
        lock (g)
        {
            var s = Load(); var h = Hash(code); var p = s.Pending.FirstOrDefault(x => x.Expires > DateTime.UtcNow && Eq(x.Hash, h)); if (p == null) return null;
            s.Pending.Remove(p); var tok = NewSecret(); var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
            s.Tokens.Add(new DeviceToken { Id = id, Name = string.IsNullOrWhiteSpace(deviceName) ? p.Name : deviceName.Trim()[..Math.Min(60, deviceName.Trim().Length)], Hash = Hash(tok), Created = DateTime.UtcNow }); Save(s);
            return (id, tok);
        }
    }
    static readonly ConcurrentDictionary<string, DateTime> lastTouch = new();
    public static DeviceToken Validate(string token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 100) return null; var h = Hash(token);
        lock (g)
        {
            var s = Load(); var t = s.Tokens.FirstOrDefault(x => !x.Revoked && Eq(x.Hash, h)); if (t == null) return null;
            if (!lastTouch.TryGetValue(t.Id, out var lt) || (DateTime.UtcNow - lt).TotalMinutes > 5) { t.LastUsed = DateTime.UtcNow; lastTouch[t.Id] = DateTime.UtcNow; Save(s); }
            return t;
        }
    }
    public static List<DeviceToken> List() { lock (g) return Load().Tokens.Select(t => new DeviceToken { Id = t.Id, Name = t.Name, Created = t.Created, LastUsed = t.LastUsed, Revoked = t.Revoked }).ToList(); }
    public static bool Revoke(string id) { lock (g) { var s = Load(); var t = s.Tokens.FirstOrDefault(x => x.Id == id); if (t == null) return false; t.Revoked = true; Save(s); return true; } }

    // ---- brute-force protection: 10 bad attempts / 10 min per address => locked out 15 min ----
    static readonly ConcurrentDictionary<string, List<DateTime>> fails = new();
    public static bool LockedOut(string ip) { if (!fails.TryGetValue(ip, out var l)) return false; lock (l) { l.RemoveAll(t => t < DateTime.UtcNow.AddMinutes(-15)); return l.Count >= 10; } }
    public static void Fail(string ip) { var l = fails.GetOrAdd(ip, _ => new()); lock (l) l.Add(DateTime.UtcNow); }
}
