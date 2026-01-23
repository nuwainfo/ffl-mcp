# ffl-mcp (local-only)
MCP server for ffl. Let AI share anything for you.

Backed by [ffl](https://github.com/nuwainfo/ffl), which turns any file/folder into an https link.

This is a minimal MCP server that shells out to `ffl` / `ffl.com` locally.
No file contents are sent to the LLM; the model only triggers local `ffl`.

## Run (no PyPI, run directly from Git)

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


## Claude Desktop / Claude Code / Codex auto-install (no JSON)

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install
```

Targets can be controlled with `--target` (default: all):

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --target claude-desktop,codex-cli
```

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --print
```

If Claude Code CLI is installed, the installer also runs `claude mcp add` automatically (user scope).
If Codex CLI is installed, the installer also runs `codex mcp add` automatically.
For other MCP clients or custom config paths, pass the file:

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --config /path/to/claude_desktop_config.json
```

## Claude Desktop / Claude Code config (uvx)

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

## Tools

**Sharing:**
- `fflShareText(text, ..., e2ee=True, qrInTerminal=False) -> {sessionId, link, qrCode?, ...}`
- `fflShareBase64(dataB64, ..., e2ee=True, qrInTerminal=False) -> {sessionId, link, qrCode?, ...}`
- `fflShareFile(path, ..., e2ee=True, qrInTerminal=False) -> {sessionId, link, qrCode?, ...}`

All share functions use **end-to-end encryption (E2EE) by default** for security. Set `e2ee=False` to disable if needed.

Set `qrInTerminal=True` to get a scannable ASCII QR code in the response (displayed as terminal art, not base64 PNG).

**Downloading:**
- `fflDownload(url, outputPath?, resume?, ...) -> {ok, returncode, outputPath?, transferMode?, transferInfo?, message?, ...}`

Downloads from FastFileLink URLs (uses **WebRTC P2P when possible**, falls back to HTTP) or regular HTTP(S) URLs (works like wget).

Returns transfer mode information:
- `webrtc_p2p`: Fast direct peer-to-peer connection
- `http_fallback`: HTTP relay (when WebRTC fails)
- `http_direct`: Direct HTTP download (non-FastFileLink URLs)

**Session Management:**
- `fflListSessions()`
- `fflStopSession(sessionId)`
- `fflGetSession(sessionId)`
- `fflGetSessionEvents(sessionId, limit=50)`

## Notes

- `FFL_USE_STDIN=1` avoids writing text/base64 payloads to disk.
- `FFL_RUN_MODE=python` runs the Core.py CLI (requires `FFL_CORE_PATH`).
- `--hook` and `--proxy` are passed through to ffl.
- `FFL_USE_HOOK=1` starts a local webhook server and passes it to `ffl` for link/progress events.
- `FFL_DEBUG=1` enables debug logging - ffl output is saved to a temp file with path returned in `debugLogPath`.

## WSL2 Users

If you encounter `TLSError([0x6300])` errors, run this command to disable Windows interop for `.com` files:

```bash
sudo sh -c 'echo -1 > /proc/sys/fs/binfmt_misc/WSLInterop'
```

This allows ffl.com (APE binary) to run natively on Linux instead of being executed through Windows.
