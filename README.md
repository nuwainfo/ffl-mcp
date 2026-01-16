# ffl-mcp

MCP server that exposes FastFileLink (ffl/ffl.com/Core.py --cli) as tools.

## Install

```
pip install -r requirements.txt
```

## Environment

- `FFL_RUN_MODE`: `binary` (default) or `python`
- `FFL_BIN`: path to `ffl` or `ffl.com` (default: `ffl`)
- `FFL_CORE_PATH`: path to `Core.py` when `FFL_RUN_MODE=python`
- `FFL_PYTHON`: python executable for Core.py (default: `python`)
- `FFL_COMMAND`: full command override (e.g. `"/path/to/ffl.com"` or `"python /path/Core.py --cli"`)
- `FFL_USE_STDIN`: `1|true|yes` to use stdin for text/base64 (default: temp file)
- `ALLOWED_BASE_DIR`: optional base dir restriction for `fflShareFile`
- `FFL_WAIT_LINK_SECONDS`: seconds to wait for JSON link (default: 20)

## Run (stdio)

```
python mcp_ffl.py
```

## Run (http/sse)

```
python mcp_ffl.py --transport http --host 127.0.0.1 --port 8000 --path /mcp
```

## Tool names

- `fflShareText`
- `fflShareBase64`
- `fflShareFile`
- `fflListSessions`
- `fflGetSession`
- `fflStopSession`

## Notes

- `fflShareFile` enforces `ALLOWED_BASE_DIR` when set.
- `fflShareText`/`fflShareBase64` use temp files by default for compatibility with Core.py.
