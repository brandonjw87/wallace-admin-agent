# WALLACE Agent (backend for the WALLACE Admin Android app)

Small authenticated .NET 8 (ASP.NET Core / Kestrel) service on **port 8088** that exposes WALLACE Admin's
monitor/control actions as a fixed set of **intent endpoints** (`/v1/...`). The phone never gets the AdGuard
password and there is **no AdGuard passthrough and no "run command" endpoint**.

## Binding / network
- Binds only to the PC's home-LAN IPv4 (192.168.1.x, currently **192.0.2.13**) and, once Tailscale is installed, its 100.x address.
  Never 0.0.0.0, never the hotspot (192.0.2.11).
- Requests from anything outside `192.0.2.20/24` and `192.0.2.22/10` get 403 (edit `AllowedNetworks` in
  `C:\ProgramData\WALLACE Agent\agent.json` if the phone should also work from the WALLACE hotspot).
- **Never port-forward 8088** on the Spectrum router. Remote access = Tailscale only.

## Auth
- `pair-phone.cmd` (or `WallaceAgent.exe --pair`) shows a one-time QR (256-bit code, 10 minutes, single use).
- The phone exchanges it at `POST /v1/pair` for its own 256-bit device token (stored in the Android Keystore).
- The server stores only SHA-256 hashes, in `tokens.dat` protected with DPAPI (LocalMachine).
- `WallaceAgent.exe --tokens` lists devices, `--revoke <id>` revokes one.
- Per-IP rate limit (240/min) and lockout after 10 bad tokens in 15 min. Audit log: `C:\ProgramData\WALLACE Agent\logs\remote-api.log` (no secrets).

## Non-overridable server-side rules
- Every AdGuard rule write goes through `Messaging.Enforce()` (ported verbatim from the desktop app). The `Messaging:protected` block is always first.
- Custom-rule writes that would block a messaging host (or a parent domain, regex, marker edit) → **409**.
- After **every** write the messaging self-test hosts are checked with `check_host`; if any is filtered the user rules are rolled back → 409.
- A backup of the AdGuard settings (API JSON, no secrets) is written to `C:\ProgramData\WALLACE Agent\backups\` before every write.
- Owner **Pixel 10 Pro XL** (`(owner)` client or name match): mode and pause → **403**.
- All phones, Rokus, the router, this PC and the hotspot gateway can't be paused → 403. 192.0.2.11 / 127.0.0.1 / 192.0.2.15 can never be disallowed.
- Safe search `youtube` is always forced `false`; `youtubeRestricted:true` → 403; rules that rewrite YouTube to restricted → 409. A background check re-forces it every 5 min.
- Hotspot restart needs `{"confirm":true}`. There is no hotspot-off or pause-all endpoint.
- Windows Update is read-only (COM search only).

## Endpoints
`GET /v1/ping` (no auth) · `POST /v1/pair` · `GET /v1/session` · `GET /v1/status` · `GET /v1/health`, `POST /v1/health/recheck` ·
`GET /v1/hotspot`, `POST /v1/hotspot/refresh`, `POST /v1/hotspot/restart {confirm}` · `POST /v1/watchdog/run` ·
`GET /v1/monitors`, `POST /v1/monitors/check` · `GET /v1/kuma` · `GET /v1/alerts`, `POST /v1/alerts/clear|test` ·
`GET /v1/stats` · `GET /v1/querylog?limit&search&status&olderThan` · `GET /v1/blocklists`, `POST /v1/blocklists/refresh` ·
`POST /v1/check-host {host,client}` · `GET/PUT /v1/safeguard` · `POST /v1/safeguard/reapply-allow` ·
`GET/POST/DELETE /v1/custom-rules` · `GET /v1/devices`, `POST /v1/devices/{mac}/mode {mode}`, `POST /v1/devices/{mac}/pause {on}` ·
`GET /v1/reports/blocked?hours=` · `GET /v1/updates?windows=true` · `GET /v1/logs/{watchdog|hotspot|app|agent|audit}` ·
`WS /v1/live` (status snapshot every 5 s).

## Build / test
```
dotnet publish src\WallaceAgent.csproj -c Release -o publish
publish\WallaceAgent.exe --selftest
start publish\WallaceAgent.exe          (runs in the foreground; Ctrl+C to stop)
powershell -File tests\test-agent.ps1 [-Writes] [-WindowsUpdate]
```

## Install (Brandon approves and runs it; nothing was installed automatically)
- `install-agent.ps1 -Mode UserTask` – per-user logon task, **no UAC**. Everything works except firewall (WFP) pause of hotspot devices.
- `install-agent.ps1 -Mode Service` – run from an **elevated** PowerShell (one UAC). Windows service as LocalSystem, enables hotspot pause via the existing `C:\ProgramData\WALLACE Admin\wnh-admin.ps1` helper, locks down the data folder ACL and adds a scoped firewall rule.
- `install-agent.ps1 -Uninstall [-Mode Service]` removes the task/service.

## Data
`C:\ProgramData\WALLACE Agent\` – `agent.json` (config), `tokens.dat` (DPAPI, hashes only), `backups\`, `logs\`, `paused.json`, `pair-qr.html/png` (expired codes are harmless; `--pair-clean` blanks them).
Reads (never writes) the desktop app's `%LOCALAPPDATA%\WALLACE Admin\settings.json`, `devices.json`. The desktop app is unchanged.


---
WALLACE Admin agent - small Windows service the Android app pairs with.

## Build
Open in Android Studio (or run `./gradlew assembleDebug`).

