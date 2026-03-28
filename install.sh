#!/usr/bin/env bash
# ffl-mcp installer for Linux / macOS
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nuwainfo/ffl-mcp/refs/heads/main/install.sh | bash

set -euo pipefail

REPO_OWNER="nuwainfo"
REPO_NAME="ffl-mcp"

# -- Detect platform ----------------------------------------------------------
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "$OS_RAW" in
  Linux*)  OS="linux"  ;;
  Darwin*) OS="darwin" ;;
  *)       echo "Unsupported OS: $OS_RAW"; exit 1 ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64)  ARCH="x86_64"  ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *)             echo "Unsupported arch: $ARCH_RAW"; exit 1 ;;
esac

echo "Platform: ${OS}/${ARCH}"

# -- Helpers ------------------------------------------------------------------
fetchHtml() {
  command -v curl >/dev/null 2>&1 \
    && curl -fsSL "$1" \
    || wget -qO- "$1"
}

# -- Resolve latest release tag (no API: follow redirect) ---------------------
echo "Resolving latest release..."
LATEST_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest"

if command -v curl >/dev/null 2>&1; then
  TAG="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$LATEST_URL" | sed 's|.*/tag/||')"
else
  TAG="$(wget -S --spider "$LATEST_URL" 2>&1 | grep -i 'Location:' | tail -n1 | sed 's|.*/tag/||' | tr -d '[:space:]')"
fi

[ -z "$TAG" ] && { echo "Could not resolve latest release tag"; exit 1; }
echo "Latest tag: $TAG"

# -- Fetch asset list (no API: scrape expanded_assets HTML) -------------------
ASSETS_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/expanded_assets/${TAG}"
ASSETS_HTML="$(fetchHtml "$ASSETS_URL")"
ASSETS_DATA="$(printf '%s\n' "$ASSETS_HTML" \
  | grep -oE "/${REPO_OWNER}/${REPO_NAME}/releases/download/${TAG}/[^\">< ]+" \
  | sed 's|^|https://github.com|')"
NAMES_LIST="$(printf '%s\n' "$ASSETS_DATA" | sed 's|.*/||')"

# -- Find matching binary -----------------------------------------------------
DOWNLOAD_URL=""
while IFS= read -r name; do
  [ -z "$name" ] && continue
  nameLower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  [[ "$nameLower" == *"$OS"* && "$nameLower" == *"$ARCH"* && "$nameLower" == *"ffl-mcp"* ]] || continue
  DOWNLOAD_URL="$(printf '%s\n' "$ASSETS_DATA" | grep "/${name}$" | head -n1)"
  break
done <<< "$NAMES_LIST"

# -- Install ------------------------------------------------------------------
if [ -n "$DOWNLOAD_URL" ]; then
  echo "Found binary: $DOWNLOAD_URL"
  TMP_BIN="$(mktemp)"
  trap 'rm -f "$TMP_BIN"' EXIT
  command -v curl >/dev/null 2>&1 \
    && curl -fL --retry 3 -o "$TMP_BIN" "$DOWNLOAD_URL" \
    || wget -O "$TMP_BIN" "$DOWNLOAD_URL"
  chmod +x "$TMP_BIN"
  echo "Registering MCP server with Claude..."
  "$TMP_BIN" install
else
  echo "No platform binary found for ${OS}/${ARCH} in release ${TAG} -- falling back to uvx."
  echo "Available assets:"; printf '%s\n' "$NAMES_LIST" | grep -v '^$' | sed 's/^/  - /'

  if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found. Installing uv..."
    curl -fsSL https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
  fi

  uvx --from "git+https://github.com/${REPO_OWNER}/${REPO_NAME}" ffl-mcp install
fi

echo ""
echo "Done! Restart Claude to connect the ffl-mcp server."
