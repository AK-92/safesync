#!/usr/bin/env bash
# ==============================================================================
# SafeSync Installer for macOS
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${SCRIPT_DIR}/bin/safesync"

echo "=============================================================="
echo "  Installing SafeSync..."
echo "=============================================================="

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Error: Cannot find binary at $BIN_SRC" >&2
  exit 1
fi

chmod +x "$BIN_SRC"

# Check if ~/.local/bin exists or can be created
TARGET_DIR="${HOME}/.local/bin"
mkdir -p "$TARGET_DIR" 2>/dev/null || true

if [[ -d "$TARGET_DIR" && -w "$TARGET_DIR" ]]; then
  cp "$BIN_SRC" "${TARGET_DIR}/safesync"
  chmod +x "${TARGET_DIR}/safesync"
  INSTALLED_PATH="${TARGET_DIR}/safesync"
else
  # Fallback to /usr/local/bin if writable
  if [[ -w "/usr/local/bin" ]]; then
    cp "$BIN_SRC" "/usr/local/bin/safesync"
    chmod +x "/usr/local/bin/safesync"
    INSTALLED_PATH="/usr/local/bin/safesync"
  else
    # Install as helper function in ~/.zshrc
    INSTALLED_PATH="$BIN_SRC"
  fi
fi

# Ensure ~/.zshrc has the command mapped safely (SEC-02)
ZSHRC="${HOME}/.zshrc"
if [[ -f "$ZSHRC" ]]; then
  if ! grep -q "safesync()" "$ZSHRC" && ! grep -q "alias safesync=" "$ZSHRC"; then
    echo "" >> "$ZSHRC"
    echo "# SafeSync CLI" >> "$ZSHRC"
    ESCAPED_PATH="${INSTALLED_PATH//\'/\'\\\'\'}"
    printf "alias safesync='%s'\n" "$ESCAPED_PATH" >> "$ZSHRC"
    echo "Added alias to ~/.zshrc"
  fi
fi

echo ""
echo "=============================================================="
echo " [✓] SafeSync installed successfully!"
echo " Location: $INSTALLED_PATH"
echo ""
echo " To start using it, reload your terminal:"
echo "   source ~/.zshrc"
echo ""
echo " Or test it right now with:"
echo "   safesync --help"
echo "=============================================================="

