#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( "$1" != "cordis" && "$1" != "go" ) ]]; then
  echo "usage: $0 cordis|go /absolute/isolated-app-dir" >&2; exit 2
fi
here="$(cd -- "$(dirname -- "$0")" && pwd)"
mode="$1"; app="$2"
[[ "$app" = /* ]] || { echo "app-dir must be absolute" >&2; exit 2; }
[[ -x "$here/pktpath-offline" ]] || { echo "pktpath-offline binary missing" >&2; exit 1; }
[[ ! -e "$app/instance.json" ]] || { echo "instance.json already exists; verify that instance before launching" >&2; exit 1; }
manifest="$here/collectors/collectors.json"
[[ -f "$manifest" ]] || { echo "packaged explicit collector manifest missing; no disk/PATH fallback" >&2; exit 1; }
if [[ "$mode" = "go" ]]; then
  exec "$here/pktpath-offline" --headless --port 0 --app-dir "$app" --collector-manifest "$manifest"
fi
node="$here/node-linux-x64/bin/node"
host="$here/cordis-analyzer-host/host.mjs"
[[ -x "$node" ]] || { echo "packaged Linux x64 Node missing; no PATH lookup or automatic Go fallback" >&2; exit 1; }
[[ -f "$host" && -f "$here/cordis-analyzer-host/lifecycle.mjs" ]] || { echo "packaged host module missing" >&2; exit 1; }
(cd "$here/cordis-analyzer-host" && "$node" --input-type=module -e "await import('@cordisjs/core')")
exec "$here/pktpath-offline" --headless --port 0 --app-dir "$app" --collector-manifest "$manifest" \
  --cordis-plugin-host "$host" --cordis-plugin-node "$node" \
  --cordis-analyzer-host "$host" --cordis-analyzer-node "$node"
