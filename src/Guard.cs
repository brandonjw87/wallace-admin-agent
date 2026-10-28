using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WallaceAgent;

/// <summary>Ported verbatim from WALLACE Admin Messaging.cs (3.2.0 ABSOLUTE RULE). Messaging is never blocked for any phone.</summary>
public static class Messaging
{
    public const string Begin = "! Messaging:protected begin (WALLACE: messaging/calls/OTP are NEVER blocked - do not edit)", End = "! Messaging:protected end";
    public static readonly string[] Domains =
    {
        // Google Messages / RCS (Jibe), Google push (FCM), Google account + connectivity checks
        "jibe.google.com", "telephony.goog", "messages.google.com", "messages-pa.googleapis.com", "instantmessaging-pa.googleapis.com", "tachyon.googleapis.com",
        "mtalk.google.com", "fcm.googleapis.com", "fcmtoken.googleapis.com", "fcmregistrations.googleapis.com", "firebaseinstallations.googleapis.com",
        "android.googleapis.com", "android.clients.google.com", "play.googleapis.com", "www.googleapis.com", "oauth2.googleapis.com", "accounts.google.com",
        "clients3.google.com", "connectivitycheck.gstatic.com", "voice.google.com", "fi.google.com",
        // Apple iMessage / FaceTime / push (APNs) / activation
        "push.apple.com", "ess.apple.com", "identity.apple.com", "albert.apple.com", "gs.apple.com", "icloud-content.com", "setup.icloud.com", "gateway.icloud.com",
        "keyvalueservice.icloud.com", "ckdatabasews.icloud.com", "facetime.apple.com",
        // Carrier Wi-Fi Calling (ePDG / IMS / XCAP / visual voicemail)
        "3gppnetwork.org", "t-mobile.com", "tmobile.com", "vzw.com", "verizon.com", "verizonwireless.com", "att.com", "att.net", "sprint.com", "uscc.com", "mintmobile.com", "spectrummobile.com",
        // Chat apps
        "whatsapp.net", "whatsapp.com", "wa.me", "signal.org", "whispersystems.org", "signal.art", "telegram.org", "telegram.me", "t.me", "messenger.com", "edge-mqtt.facebook.com", "mqtt-mini.facebook.com",
        // One-time-code / 2FA senders
        "twilio.com", "authy.com", "duosecurity.com", "sinch.com", "nexmo.com", "vonage.com", "messagebird.com", "plivo.com",
    };
    public const string GoogleApiRegex = @"@@/^(instantmessaging|rcs|tachyon|messages)[a-z0-9-]*\.googleapis\.com$/$important";
    public static readonly string[] SelfTestHosts = { "instantmessaging-pa.googleapis.com", "courier.push.apple.com", "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org", "mtalk.google.com", "g.whatsapp.net" };

    public static List<string> Block() { var l = new List<string> { Begin }; l.AddRange(Domains.Select(d => "@@||" + d + "^$important")); l.Add(GoogleApiRegex); l.Add(End); return l; }

    /// <summary>True if host is (a subdomain of) a protected messaging domain.</summary>
    public static bool IsProtectedHost(string host)
    {
        host = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant(); if (host == "") return false;
        if (Regex.IsMatch(host, @"^(instantmessaging|rcs|tachyon|messages)[a-z0-9-]*\.googleapis\.com$")) return true;
        return Domains.Any(d => host == d || host.EndsWith("." + d));
    }

    /// <summary>Applied to EVERY user-rule list before it is sent to AdGuard: removes block rules that target messaging hosts,
    /// then puts the protected allow block (with $important) first so it overrides every list, category and blocked service.</summary>
    public static List<string> Enforce(IEnumerable<string> input)
    {
        var rules = (input ?? Enumerable.Empty<string>()).Where(r => r != null).ToList();
        int b = rules.FindIndex(r => r.StartsWith("! Messaging:protected begin")), e = rules.IndexOf(End);
        if (b >= 0 && e > b) rules.RemoveRange(b, e - b + 1); else if (b >= 0) rules.RemoveAt(b);
        var outp = new List<string>();
        foreach (var r in rules)
        {
            var t = r.Trim();
            if (!t.StartsWith("!") && !t.StartsWith("#") && !t.StartsWith("@@"))
            {
                var m = Regex.Match(t, @"^\|{0,2}([a-z0-9.*-]+)\^?", RegexOptions.IgnoreCase);
                if (m.Success && IsProtectedHost(m.Groups[1].Value.Replace("*.", ""))) { Log.Agent("messaging guard: dropped rule that would block messaging: " + t); continue; }
            }
            outp.Add(r);
        }
        var res = Block(); res.AddRange(outp); return res;
    }

    static readonly string[] PhoneWords = { "phone", "iphone", "pixel", "galaxy", "android", "moto", "oneplus" };
    public static bool PhoneName(string s) { s = (s ?? "").ToLowerInvariant(); return PhoneWords.Any(s.Contains); }
    public const string Explain = "Messaging protected (locked): texts, one-time codes, RCS chats, iMessage/FaceTime, Wi-Fi Calling, WhatsApp/Signal/Telegram/Messenger and voicemail are never blocked for any phone. Nothing in this app can override it.";

    /// <summary>Host a block-style rule targets (null for allow rules / comments / unparseable).</summary>
    public static string BlockTarget(string rule)
    {
        var t = (rule ?? "").Trim(); if (t == "" || t.StartsWith("!") || t.StartsWith("#") || t.StartsWith("@@")) return null;
        var m = Regex.Match(t, @"^\|{0,2}([a-z0-9.*-]+)\^?", RegexOptions.IgnoreCase); return m.Success ? m.Groups[1].Value.Replace("*.", "") : null;
    }
    /// <summary>True if a block rule would hit messaging: direct domain match, a parent domain of a protected host (e.g. ||googleapis.com^), wildcard/regex hitting a self-test host.</summary>
    public static bool WouldBlockMessaging(string rule)
    {
        var t = (rule ?? "").Trim(); if (t.StartsWith("@@") || t.StartsWith("!") || t == "") return false;
        var host = BlockTarget(t);
        if (host != null)
        {
            host = host.Trim('.').ToLowerInvariant();
            if (IsProtectedHost(host)) return true;
            if (Domains.Any(d => d.EndsWith("." + host)) || SelfTestHosts.Any(h => h.EndsWith("." + host)) || host is "googleapis.com" or "google.com" or "apple.com" or "icloud.com" or "facebook.com" or "gstatic.com") return true;
        }
        if (t.StartsWith("/"))
        {
            var end = t.LastIndexOf('/'); if (end > 0) { try { var rx = new Regex(t[1..end], RegexOptions.IgnoreCase); if (SelfTestHosts.Concat(Domains).Any(rx.IsMatch)) return true; } catch { return true; } }
        }
        if (Regex.IsMatch(t, @"\$(.*,)?(dnsrewrite|dnstype|client|ctag)", RegexOptions.IgnoreCase) && host != null && Domains.Any(d => d.Contains(host.Trim('*', '.')))) return true;
        return false;
    }
}

/// <summary>Non-overridable server-side rules for the phone API (the phone UI only mirrors them).</summary>
public static class Guard
{
    public static readonly string[] ProtectedIps = { "192.0.2.11", "127.0.0.1", "::1", "192.0.2.15" };
    static readonly Regex YtRestrict = new(@"restrict(moderate)?\.youtube\.com|youtube.*\$dnsrewrite|forcesafesearch|\$safesearch", RegexOptions.IgnoreCase);

    public static bool IsOwnerClient(JsonNode c) { var n = (string)c?["name"] ?? ""; return n.Contains("(owner)", StringComparison.OrdinalIgnoreCase) || Flat(n).Contains("pixel 10 pro xl"); }
    public static bool MatchesClient(JsonNode c, string ip, string mac) => (c?["ids"]?.AsArray() ?? new JsonArray()).Any(i => (!string.IsNullOrEmpty(ip) && string.Equals((string)i, ip, StringComparison.OrdinalIgnoreCase)) || (!string.IsNullOrEmpty(mac) && string.Equals(Norm((string)i), Norm(mac), StringComparison.OrdinalIgnoreCase)));
    public static string Norm(string mac) => (mac ?? "").Replace('-', ':').ToLowerInvariant();

    static string Flat(string s) => Regex.Replace((s ?? "").ToLowerInvariant(), "[^a-z0-9()]+", " ");
    public static bool IsOwner(JsonArray clients, string ip, string mac, string name) =>
        Flat(name).Contains("pixel 10 pro xl") || (name ?? "").Contains("(owner)", StringComparison.OrdinalIgnoreCase) ||
        clients.Any(c => IsOwnerClient(c) && MatchesClient(c, ip, mac));

    public static bool IsPhone(JsonArray clients, Dictionary<string, string> types, string ip, string mac, string name, string devType)
    {
        if (!string.IsNullOrEmpty(mac) && types.Any(k => string.Equals(Norm(k.Key), Norm(mac), StringComparison.OrdinalIgnoreCase) && k.Value == "Phone")) return true;
        if (devType == "Phone" || Messaging.PhoneName(name) || Messaging.PhoneName(devType)) return true;
        return clients.Any(c => ((string)c["name"] ?? "").StartsWith("SG Phone") && MatchesClient(c, ip, mac));
    }
    public static bool IsRoku(HashSet<string> rokuMacs, Dictionary<string, string> types, string mac, string name, string vendor) =>
        rokuMacs.Contains(Norm(mac)) || types.Any(k => string.Equals(Norm(k.Key), Norm(mac)) && k.Value == "Roku") || (vendor ?? "").Contains("Roku", StringComparison.OrdinalIgnoreCase) || (name ?? "").Contains("Roku", StringComparison.OrdinalIgnoreCase);

    /// <summary>Validates a custom rule before it is written. Returns an error (=> HTTP 409) or null.</summary>
    public static string CheckRule(string rule)
    {
        if (string.IsNullOrWhiteSpace(rule)) return "Empty rule";
        if (rule.Contains("Messaging:protected", StringComparison.OrdinalIgnoreCase) || rule.Contains("SafeGuard", StringComparison.OrdinalIgnoreCase) || rule.Contains("WALLACE custom", StringComparison.OrdinalIgnoreCase)) return "Managed block markers can't be edited from the phone.";
        if (rule.Contains('\n') || rule.Contains('\r')) return "One rule at a time.";
        if (Messaging.WouldBlockMessaging(rule)) return "Refused: this rule would block messaging (texts, one-time codes, RCS/iMessage, Wi-Fi Calling, chat apps). Messaging protected is locked.";
        if (YtRestrict.IsMatch(rule)) return "Refused: YouTube restricted mode stays off (Rokus need unrestricted YouTube).";
        if (rule.Contains("$client", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(rule, "pixel|owner", RegexOptions.IgnoreCase)) return "Refused: the owner's Pixel 10 Pro XL is permanently exempt.";
        return null;
    }
}
