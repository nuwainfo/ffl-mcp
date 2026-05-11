# ffl-mcp (local-only)
MCP server for ffl. Let AI share anything for you.

Backed by [ffl](https://github.com/nuwainfo/ffl), which turns any file/folder into an HTTPS link.

This is a minimal MCP server that shells out to `ffl` / `ffl.com` locally.
No file contents are sent to the LLM; the model only triggers local `ffl`.

This demo shows collaborative debugging: Claude on the left shares a local environment (DB + logs) via P2P link, Claude on the right downloads and diagnoses the error. In this scenario, the two Claudes represent different people working on separate machines.

![ffl-mcp-demo](https://github.com/user-attachments/assets/522aa8bb-e151-4613-9b43-aac67a596d1a)

---

## Table of Contents

- [Installation](#installation)
  - [Windows — GUI Installer](#windows--gui-installer)
  - [Linux / macOS — one-liner](#linux--macos--one-liner)
  - [Windows — one-liner (PowerShell)](#windows--one-liner-powershell)
  - [uvx (no binary, requires uv)](#uvx-no-binary-requires-uv)
  - [Run directly (development)](#run-directly-development)
- [MCP Config (manual JSON)](#mcp-config-manual-json)
- [Tools](#tools)
  - [Sharing](#sharing)
  - [Downloading](#downloading)
  - [Keygen](#keygen)
  - [Session Management](#session-management)
- [Notes](#notes)
- [Testing](#testing)
- [WSL2 Users](#wsl2-users)

---

## Installation

> ⚡ **Short URLs for convenience**
>
> - **Linux/macOS:** `curl -fsSL https://fastfilelink.com/mcp/install.sh | bash`
> - **Windows (script):** `iwr -useb https://fastfilelink.com/mcp/install.ps1 | iex`
>
> 🔒 `fastfilelink.com/mcp/*` is a redirect to GitHub. Use the direct GitHub URLs below if you prefer.

### Windows — GUI Installer

Download and run **[ffl-mcp-setup.exe](https://github.com/nuwainfo/ffl-mcp/releases/latest/download/ffl-mcp-setup.exe)** from the latest release.

No command line needed — the installer registers ffl-mcp with Claude Desktop and Claude Code automatically.

### Linux / macOS — one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/nuwainfo/ffl-mcp/refs/heads/main/install.sh | bash
```

Downloads the platform binary from the latest GitHub release and runs `ffl-mcp install` to register with Claude. Falls back to `uvx` automatically if no binary is available for your platform.

### Windows — one-liner (PowerShell)

```powershell
iwr -useb https://raw.githubusercontent.com/nuwainfo/ffl-mcp/refs/heads/main/install.ps1 | iex
```

Downloads `ffl-mcp.exe` from the latest GitHub release and registers it with Claude.

### uvx (no binary, requires uv)

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install
```

Targets can be controlled with `--target` (default: all):

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --target claude-desktop,codex-desktop,codex-cli
```

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --print
```

If Claude Code CLI is installed, the installer also runs `claude mcp add` automatically (user scope).
The installer also writes Codex MCP config to `~/.codex/config.toml` for Codex Desktop/CLI/IDE.
If Codex CLI is installed, the installer also runs `codex mcp add` automatically.
For custom config paths, pass the file:

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --config /path/to/claude_desktop_config.json
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --codex-config /path/to/codex/config.toml
```

### Run directly (development)

Prereq: `uv` installed.

```bash
# optional: override embedded ffl.com (APE) or use "ffl" on PATH
export FFL_BIN="$HOME/bin/ffl.com"
chmod +x "$FFL_BIN"

# optional safety: restrict file sharing to a directory
export ALLOWED_BASE_DIR="$HOME/Downloads"

# optional: use stdin for text/base64 instead of temp files
export FFL_USE_STDIN=1

uvx --from git+https://github.com/nuwainfo/ffl-mcp ffl-mcp
```

---

## MCP Config (manual JSON)

```json
{
  "mcpServers": {
    "ffl": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/nuwainfo/ffl-mcp", "ffl-mcp"],
      "env": {
        "ALLOWED_BASE_DIR": "/Users/you/Downloads",
        "FFL_USE_STDIN": "1"
      }
    }
  }
}
```

---

## Tools

### Sharing

| Tool | Input |
|---|---|
| `fflShareText(text, name?, ...)` | Plain text |
| `fflShareBase64(dataB64, name?, ...)` | Binary data (base64-encoded) |
| `fflShareFile(path, name?, ...)` | Single local file or folder |
| `fflShareFiles(paths, name?, ...)` | Multiple files (ffl auto-zips them into one download) |

**Common options for all share tools:**

| Option | Default | Description |
|---|---|---|
| `e2ee` | `False` | End-to-end encryption |
| `qrInTerminal` | `False` | Return ASCII QR art (`qrCode` in response) |
| `authUser` / `authPassword` | — | HTTP Basic Auth to protect the link |
| `maxDownloads` | `1` | Stop serving after N downloads (P2P only) |
| `timeoutSeconds` | `1800` | Inactivity timeout in seconds (P2P only) |
| `recipientAuth` | — | `pickup` (6-digit code), `pubkey` (RSA), `pubkey+pickup`, or `email` (OTP) |
| `pickupCode` | auto | Specific pickup code for `pickup` mode |
| `recipientPublicKey` | — | Path to `.fflpub` file for `pubkey` mode |
| `recipientEmail` | — | Email(s) for `email` OTP mode, comma-separated |
| `alias` | — | Custom link alias e.g. `my-release` (requires Standard+ account) |
| `receipt` | — | Email notification when recipient downloads |
| `receiptConfirm` | — | Require recipient confirmation before download; pass a message or `""` |
| `forceRelay` | `False` | Disable WebRTC, route all traffic through tunnel |
| `port` | — | Local HTTP server port (auto-detect by default). Useful with fixed tunnels. |
| `invite` | `False` | Open the ffl invite page in a local browser with the generated sharing link. |
| `enableReporting` | `False` | Enable ffl diagnostic error reporting. Disabled by default. |
| `upload` | — | Upload to FFL server instead of P2P — e.g. `"1 day"`, `"6 hours"` (requires Standard+ account) |
| `resumeUpload` | `False` | Resume an interrupted upload |
| `proxy` | — | Proxy URL e.g. `socks5://127.0.0.1:9050` |

**Additional options for `fflShareFile` / `fflShareFiles`:**

| Option | Default | Description |
|---|---|---|
| `preview` | `False` | Append `?preview=true` to the link — recipient's browser opens in preview mode showing a file list before downloading. Recommended for folders and multi-file shares. |
| `exclude` | — | Glob or regex patterns to exclude, comma-separated — e.g. `*.pyc,__pycache__` or `re:\.env$` |
| `pause` | — | Pause server upload at a percentage from 1 to 99. Requires `upload`. |
| `vfs` | `False` | Expose as VFS server (`vfs://` URI) — `fflShareFile` only |
| `preferredTunnel` | — | Set preferred tunnel for this and future runs — `cloudflare`, `ngrok`, `bore`, etc. |

**Response fields:** `sessionId`, `link`, `pid`, `qrCode?` (ASCII art when `qrInTerminal=True`), `debugLogPath?`

### Downloading

```
fflDownload(url, outputPath?, resume?, authUser?, authPassword?,
            recipientAuth?, pickupCode?, recipientPrivateKey?, proxy?,
            enableReporting?)
  -> {ok, returncode, outputPath?, transferMode?, transferInfo?, message?, ...}
```

Downloads from FastFileLink URLs (WebRTC P2P when possible, HTTP fallback) or any HTTP(S) URL (works like wget).

| `transferMode` | Meaning |
|---|---|
| `webrtc_p2p` | Direct peer-to-peer (fastest) |
| `http_fallback` | HTTP relay when WebRTC fails |
| `http_direct` | Regular HTTP download (non-FastFileLink URL) |

For authenticated links: pass `recipientAuth` + `pickupCode` (pickup mode) or `recipientPrivateKey` (pubkey mode).
Set `enableReporting=True` only when you want to opt into ffl diagnostic error reporting for troubleshooting.

### Keygen

```
fflKeygen(name?) -> {ok, returncode, output}
```

Generates an RSA keypair for passwordless `pubkey` recipient auth:
- `<name>.fflpub` — share with the sender (pass as `recipientPublicKey`)
- `<name>.fflkey` — keep private (pass as `recipientPrivateKey` when downloading)

### Session Management

- `fflListSessions()` — list active share sessions
- `fflStopSession(sessionId)` — terminate a session
- `fflGetSession(sessionId)` — get session details
- `fflGetSessionEvents(sessionId, limit=50)` — retrieve webhook events

---

## Notes

- `FFL_USE_STDIN=1` avoids writing text/base64 payloads to disk.
- `FFL_RUN_MODE=python` runs the Core.py CLI (requires `FFL_CORE_PATH`).
- `FFL_USE_HOOK=1` starts a local webhook server and passes it to `ffl` for real-time link/progress events.
- `FFL_DEBUG=1` saves ffl output to a temp log file; path returned as `debugLogPath`. Set `FFL_DEBUG=/path/to/log.txt` to use a fixed path.
- `ALLOWED_BASE_DIR` restricts `fflShareFile`/`fflShareFiles` to a specific directory.

---

## Testing

```bash
# Unit + binary tests (no network needed)
python -m unittest discover -s tests -p "*Test.py" -v

# All tests including share/download round-trips (requires network)
FFL_INTEGRATION_TESTS=1 python -m unittest discover -s tests -p "*Test.py" -v
```

---

## WSL2 Users

If you encounter `TLSError([0x6300])` errors, run this command to disable Windows interop for `.com` files:

```bash
sudo sh -c 'echo -1 > /proc/sys/fs/binfmt_misc/WSLInterop'
```

This allows ffl.com (APE binary) to run natively on Linux instead of being executed through Windows.
