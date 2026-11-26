#!/usr/bin/env bash
# Stops a PktPath Studio instance started by start-studio.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STARTER="$HERE/start-studio.sh"
if [[ ! -x "$STARTER" && ! -f "$STARTER" ]]; then
  echo "缺少 start-studio.sh，无法停止。" >&2
  exit 1
fi
exec bash "$STARTER" --stop "$@"
