#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$REPO_ROOT/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

find_python() {
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "[ai-osint-hub] Creating virtual environment at $VENV_DIR ..."
    if command -v uv >/dev/null 2>&1; then
        uv venv "$VENV_DIR"
    elif SYS_PY="$(find_python)"; then
        "$SYS_PY" -m venv "$VENV_DIR"
    else
        echo "ERROR: Neither 'uv' nor Python 3.10+ was found on PATH." >&2
        echo "Install uv:     curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
        echo "Or install Python 3.11+ via your system package manager (brew/apt)." >&2
        exit 1
    fi
fi

if ! "$VENV_PYTHON" -c "import hub" >/dev/null 2>&1; then
    echo "[ai-osint-hub] Installing package into .venv ..."
    if command -v uv >/dev/null 2>&1; then
        uv pip install --python "$VENV_PYTHON" -e "$REPO_ROOT"
    else
        "$VENV_PYTHON" -m pip install --upgrade pip
        "$VENV_PYTHON" -m pip install -e "$REPO_ROOT"
    fi
fi

echo "[ai-osint-hub] Launching Web Workbench ..."
exec "$VENV_PYTHON" -m hub.cli web --open "$@"
