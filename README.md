# ffl-mcp (local-only)
MCP server for ffl. Let AI share anything for you.

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

## Tools

- `fflShareText(text, ...) -> {sessionId, link, ...}`
- `fflShareBase64(dataB64, ...) -> {sessionId, link, ...}`
- `fflShareFile(path, ...) -> {sessionId, link, ...}`
- `fflListSessions()`
- `fflStopSession(sessionId)`
- `fflGetSession(sessionId)`
- `fflGetSessionEvents(sessionId, limit=50)`

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

## Claude Desktop auto-install (no JSON)

```bash
FFL_BIN="$HOME/bin/ffl.com" uvx --from git+https://github.com/nuwainfo/ffl-mcp install
```

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --print
```

If Claude Code CLI is installed, the installer also runs `claude mcp add` automatically (user scope).
For other MCP clients or custom config paths, pass the file:

```bash
uvx --from git+https://github.com/nuwainfo/ffl-mcp install --config /path/to/claude_desktop_config.json
```

## Notes

- `FFL_USE_STDIN=1` avoids writing text/base64 payloads to disk.
- `FFL_RUN_MODE=python` runs the Core.py CLI (requires `FFL_CORE_PATH`).
- `--hook` and `--proxy` are passed through to ffl.
- `FFL_USE_HOOK=1` starts a local webhook server and passes it to `ffl` for link/progress events.
