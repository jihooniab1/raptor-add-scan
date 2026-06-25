#!/usr/bin/env bash
# Convenience wrapper around launcher.py.
# All arguments forward to launcher.py unchanged.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${script_dir}/launcher.py" "$@"
