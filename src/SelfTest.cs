namespace WallaceAgent;

/// <summary>Offline checks of the non-overridable rules (no network, no writes).</summary>
public static class SelfTest
{
    public static int Run()
    {
        int fail = 0; void T(string name, bool ok) { Console.WriteLine((ok ? "PASS " : "FAIL ") + name); if (!ok) fail++; }
        var e = Messaging.Enforce(new[] { "||ads.example^", "||whatsapp.net^", "! Messaging:protected begin x", "@@||junk^", "! Messaging:protected end", "||mtalk.google.com^" });
        T("messaging block first", e[0].StartsWith("! Messaging:protected begin"));
        T("messaging block intact", e.Contains(Messaging.End) && e.Count(r => r.StartsWith("! Messaging:protected begin")) == 1);
        T("blocking rule for whatsapp dropped", !e.Contains("||whatsapp.net^") && !e.Contains("||mtalk.google.com^"));
        T("unrelated rule kept", e.Contains("||ads.example^"));
        T("409: block signal.org", Guard.CheckRule("||signal.org^") != null);
        T("409: block sub.fcm.googleapis.com", Guard.CheckRule("||x.fcm.googleapis.com^") != null);
        T("409: parent googleapis.com", Guard.CheckRule("||googleapis.com^") != null);
        T("409: regex hitting messaging", Guard.CheckRule("/whatsapp/") != null);
        T("409: youtube restrict rewrite", Guard.CheckRule("||youtube.com^$dnsrewrite=restrict.youtube.com") != null);
        T("409: marker edit", Guard.CheckRule("! Messaging:protected end") != null);
        T("ok: block doubleclick.net", Guard.CheckRule("||doubleclick.net^") == null);
        T("ok: allow example.com", Guard.CheckRule("@@||example.com^") == null);
        var clients = new System.Text.Json.Nodes.JsonArray(System.Text.Json.Nodes.JsonNode.Parse("{\"name\":\"SG Phone - Brandon Pixel 10 Pro XL (owner)\",\"ids\":[\"192.0.2.23\",\"00:00:5E:00:53:04\"]}"));
        T("owner detected by MAC", Guard.IsOwner(clients, null, "00-00-5E-00-53-05", ""));
        T("owner is phone", Guard.IsPhone(clients, new(), "192.0.2.23", null, "", null));
        T("phone by name", Guard.IsPhone(new(), new(), null, null, "Galaxy S24", null));
        T("CIDR 100.64/10", AgentConfig.InCidr(System.Net.IPAddress.Parse("192.0.2.24"), "192.0.2.22/10") && !AgentConfig.InCidr(System.Net.IPAddress.Parse("100.128.0.1"), "192.0.2.22/10"));
        T("hotspot not allowed network", !new AgentConfig().AllowedNetworks.Any(n => AgentConfig.InCidr(System.Net.IPAddress.Parse("192.0.2.25"), n)));
        Console.WriteLine(fail == 0 ? "SELFTEST PASS" : $"SELFTEST FAIL ({fail})"); return fail == 0 ? 0 : 1;
    }
}
