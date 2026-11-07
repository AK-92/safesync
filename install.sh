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

# Check installation target directories in order of preference (REC-08)
TARGET_DIR="${HOME}/.local/bin"
mkdir -p "$TARGET_DIR" 2>/dev/null || true

INSTALLED_PATH=""
INSTALL_TYPE="path"

if [[ -d "$TARGET_DIR" && -w "$TARGET_DIR" ]]; then
  cp "$BIN_SRC" "${TARGET_DIR}/safesync"
  chmod +x "${TARGET_DIR}/safesync"
  INSTALLED_PATH="${TARGET_DIR}/safesync"
elif [[ -w "/usr/local/bin" ]]; then
  cp "$BIN_SRC" "/usr/local/bin/safesync"
  chmod +x "/usr/local/bin/safesync"
  INSTALLED_PATH="/usr/local/bin/safesync"
else
  # Fallback to source path with prominent warning (SEC-18)
  INSTALLED_PATH="$BIN_SRC"
  INSTALL_TYPE="alias"
  echo ""
  echo " [!] WARNING: Neither ~/.local/bin nor /usr/local/bin is writable."
  echo "     Falling back to source repository path:"
  echo "     $INSTALLED_PATH"
  echo "     Do not delete or relocate this repository directory!"
  echo ""
fi

# Ensure ~/.local/bin is in PATH for both interactive and script execution (REC-08 / DEF-18)
if [[ "$INSTALL_TYPE" == "path" && "$INSTALLED_PATH" == "${HOME}/.local/bin/safesync" ]]; then
  TARGET_PROFILE="${HOME}/.zprofile"
  if [[ ! -f "$TARGET_PROFILE" ]]; then
    TARGET_PROFILE="${HOME}/.zshrc"
  fi

  if [[ -w "$TARGET_PROFILE" || (! -e "$TARGET_PROFILE" && -w "$HOME") ]]; then
    if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]] && ! grep -q '\.local/bin' "$TARGET_PROFILE" 2>/dev/null; then
      echo "" >> "$TARGET_PROFILE"
      echo '# SafeSync: user local binaries' >> "$TARGET_PROFILE"
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$TARGET_PROFILE"
      echo "Added ~/.local/bin to PATH in $TARGET_PROFILE"
    fi
  fi
fi

# Fallback alias or backward compatibility in ~/.zshrc (SEC-02)
ZSHRC="${HOME}/.zshrc"
if [[ -f "$ZSHRC" && -w "$ZSHRC" ]]; then
  if [[ "$INSTALL_TYPE" == "alias" ]] && ! grep -q "safesync" "$ZSHRC" 2>/dev/null; then
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
echo "   source ~/.zprofile 2>/dev/null || source ~/.zshrc"
echo ""
echo " Or test it right now with:"
echo "   safesync --help"
echo "=============================================================="
