#!/usr/bin/env bash
# Fail-closed PktPath Studio launcher (pure Cordis Wave 1 / WAVE1-CONTRACT.md v1.2).
# SHA256 of frozen contract: 34c55d3fcfe32186a9c714e8b447bbfa9828cf5960ee078f861eb6fca286fc97
# Linux bundle entry (Ning --launchers-dir copies this as start-studio.sh).
# Never falls back to PATH Node; never calls a Go Studio binary.
set -euo pipefail

OFFICIAL_CONTRACT_SHA256="34c55d3fcfe32186a9c714e8b447bbfa9828cf5960ee078f861eb6fca286fc97"
ENTRY_REL="studio-cordis/src/main.ts"
WEB_INDEX_REL="studio-cordis/web/index.html"
CORDIS_CORE_REL="studio-cordis/node_modules/@cordisjs/core/package.json"
ANDROID_COLLECTOR_REL="collectors/android-arm64/pktpath"
DEFAULT_HOST="127.0.0.1"
HEALTH_PATH="/api/health"
QUIT_PATH="/api/app/quit"
READY_PREFIX="PKTPATH_STUDIO_READY"
READY_TIMEOUT_MS=20000
QUIT_WAIT_MS=8000
FORCE_KILL_WAIT_MS=3000

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
PktPath Studio 启动器

请先将组合包完整解压，再运行 start-studio.sh（不要在压缩包预览中直接运行）。
启动成功后会打开系统默认浏览器。本机不会做数据包采集。
停止服务：运行 stop-studio.sh，或 start-studio.sh --stop
排障时前台运行：start-studio.sh --foreground
关闭最后一个浏览器标签后默认约 25 秒自动优雅退出；禁用：start-studio.sh --no-auto-quit
自定义空闲退出时间：start-studio.sh --auto-quit-ms 25000
EOF
}

fail() {
  local code="$1"; shift
  echo "$*" >&2
  exit "$code"
}

default_app_dir() {
  if [[ -n "${PKTPATH_APP_DIR:-}" ]]; then
    printf '%s\n' "$PKTPATH_APP_DIR"
    return
  fi
  printf '%s\n' "${HOME}/.local/share/pktpath-studio"
}

runtime_path() {
  printf '%s\n' "$1/logs/launcher-runtime.json"
}

require_start_files() {
  NODE="$HERE/node/bin/node"
  [[ -e "$NODE" ]] || fail 1 "缺少随包 Node（node/bin/node），拒绝启动，不会回退到 PATH。"
  [[ -x "$NODE" ]] || fail 1 "随包 Node（node/bin/node）不可执行，拒绝启动，不会回退到 PATH。"
  ENTRY="$HERE/$ENTRY_REL"
  WEBIDX="$HERE/$WEB_INDEX_REL"
  CORDISPKG="$HERE/$CORDIS_CORE_REL"
  COLLECTORS="$HERE/collectors"
  ANDROID_BIN="$HERE/$ANDROID_COLLECTOR_REL"
  APP_ROOT="$HERE/studio-cordis"
  WEB_DIR="$HERE/studio-cordis/web"
  [[ -f "$ENTRY" ]] || fail 1 "缺少 Studio 入口（studio-cordis/src/main.ts），拒绝启动。"
  [[ -f "$WEBIDX" ]] || fail 1 "缺少前端页面（studio-cordis/web/index.html），拒绝启动。"
  [[ -f "$CORDISPKG" ]] || fail 1 "缺少 @cordisjs/core（studio-cordis/node_modules/@cordisjs/core/package.json），拒绝启动。"
  [[ -f "$ANDROID_BIN" ]] || fail 1 "缺少 Android 采集器（collectors/android-arm64/pktpath），拒绝启动。"
}

preflight_import() {
  if ! (cd "$APP_ROOT" && "$NODE" --input-type=module -e "await import('@cordisjs/core')"); then
    fail 1 "随包 Node 无法加载 @cordisjs/core，拒绝启动。"
  fi
}

http_get() {
  local url="$1"
  "$NODE" --input-type=module -e '
const url = process.argv[1];
const ac = new AbortController();
const t = setTimeout(() => ac.abort(), 2000);
try {
  const res = await fetch(url, { signal: ac.signal });
  const body = await res.text();
  clearTimeout(t);
  if (res.status === 200 && /"ok"\s*:\s*true/.test(body)) process.exit(0);
} catch {}
process.exit(1);
' "$url"
}

http_quit() {
  local url="$1"
  "$NODE" --input-type=module -e '
const url = process.argv[1];
const ac = new AbortController();
const t = setTimeout(() => ac.abort(), 5000);
try {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: "{}",
    signal: ac.signal,
  });
  const body = await res.text();
  clearTimeout(t);
  if (res.status === 200 && /"ok"\s*:\s*true/.test(body)) process.exit(0);
} catch {}
process.exit(1);
' "$url" || true
}

pid_alive() {
  local pid="$1"
  [[ -n "$pid" && "$pid" -gt 0 ]] && kill -0 "$pid" 2>/dev/null
}

cmdline_of() {
  local pid="$1"
  if [[ -r "/proc/$pid/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$pid/cmdline"
    echo
  else
    ps -p "$pid" -o args= 2>/dev/null || true
  fi
}

comm_of() {
  local pid="$1"
  if [[ -r "/proc/$pid/comm" ]]; then
    tr -d '\n' < "/proc/$pid/comm"
  else
    ps -p "$pid" -o comm= 2>/dev/null || true
  fi
}

wait_pid_exit() {
  local pid="$1" ms="$2" waited=0
  while (( waited < ms )); do
    pid_alive "$pid" || return 0
    sleep 0.1
    waited=$((waited + 100))
  done
  pid_alive "$pid" && return 1 || return 0
}

kill_carefully() {
  local pid="$1"
  pid_alive "$pid" || return 0
  local comm cmd
  comm="$(comm_of "$pid")"
  cmd="$(cmdline_of "$pid")"
  if [[ "$comm" != "node" && "$cmd" != *node* ]]; then
    echo "拒绝结束 PID $pid：进程名不是 node，避免误杀。" >&2
    return 1
  fi
  if [[ "$cmd" != *main.ts* && "$cmd" != *studio-cordis* ]]; then
    echo "拒绝结束 PID $pid：命令行与 Studio 入口不匹配，避免误杀。" >&2
    return 1
  fi
  kill -TERM "$pid" 2>/dev/null || true
  wait_pid_exit "$pid" "$FORCE_KILL_WAIT_MS" || kill -KILL "$pid" 2>/dev/null || true
}

read_ready_from_log() {
  local log="$1"
  [[ -f "$log" ]] || return 1
  # last matching line
  local line
  line="$(grep -E "${READY_PREFIX}[[:space:]]+url=http[^[:space:]]+[[:space:]]+pid=[0-9]+" "$log" 2>/dev/null | tail -n 1 || true)"
  [[ -n "$line" ]] || return 1
  READY_URL="$(printf '%s\n' "$line" | sed -E "s/.*url=([^[:space:]]+).*/\1/")"
  READY_PID="$(printf '%s\n' "$line" | sed -E "s/.*pid=([0-9]+).*/\1/")"
  [[ -n "$READY_URL" && -n "$READY_PID" ]]
}

open_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  elif command -v gio >/dev/null 2>&1; then
    gio open "$url" >/dev/null 2>&1 || true
  fi
}

write_runtime() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  "$NODE" --input-type=module -e '
import fs from "node:fs";
const [path, pid, launcherPid, url, host, appDir, entry, nodePath, outLog, errLog] = process.argv.slice(1);
fs.writeFileSync(path, JSON.stringify({
  pid: Number(pid),
  launcher_pid: Number(launcherPid),
  url, host, app_dir: appDir, entry, node: nodePath,
  started_at: new Date().toISOString(),
  logs: { out: outLog, err: errLog },
}, null, 2) + "\n");
' "$path" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"
}

do_stop() {
  local app_dir="$1"
  # node may be needed for HTTP; prefer bundled, else we cannot POST.
  local node="$HERE/node/bin/node"
  local rt
  rt="$(runtime_path "$app_dir")"
  if [[ ! -f "$rt" ]]; then
    echo "没有正在运行的 Studio 记录，无需停止。"
    exit 0
  fi
  if [[ ! -x "$node" ]]; then
    fail 1 "缺少随包 Node，无法发送退出请求。"
  fi
  NODE="$node"
  local url pid
  url="$("$NODE" --input-type=module -e 'import fs from "node:fs"; const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(j.url||""));' "$rt")"
  pid="$("$NODE" --input-type=module -e 'import fs from "node:fs"; const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(j.pid||""));' "$rt")"
  if [[ -z "$url" && ! ( -n "$pid" && "$pid" != "0" ) ]]; then
    rm -f "$rt"
    echo "没有正在运行的 Studio 进程，已清理残留记录。"
    exit 0
  fi
  if [[ -n "$url" ]]; then
    http_quit "${url%/}${QUIT_PATH}" || true
    if [[ -n "$pid" ]]; then wait_pid_exit "$pid" "$QUIT_WAIT_MS" || true; fi
  fi
  if pid_alive "$pid"; then
    kill_carefully "$pid" || true
    wait_pid_exit "$pid" "$FORCE_KILL_WAIT_MS" || true
  fi
  if pid_alive "$pid"; then
    fail 1 "停止 Studio 超时，进程仍在运行（PID $pid）。"
  fi
  rm -f "$rt"
  echo "Studio 已停止。"
  exit 0
}

STOP=0
FOREGROUND=0
NO_OPEN=0
HELP=0
HOST=""
PORT=""
APP_DIR=""
COLLECTORS_DIR=""
WEB_DIR_ARG=""
FORWARD=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stop|-Stop) STOP=1; shift ;;
    --foreground|-Foreground) FOREGROUND=1; shift ;;
    --no-open|--no-browser|-NoOpen|-NoBrowser) NO_OPEN=1; shift ;;
    --help|-h|-Help) HELP=1; shift ;;
    --host=*) HOST="${1#--host=}"; shift ;;
    --host|-Host)
      [[ $# -ge 2 ]] || fail 2 "缺少 --host 参数值。"
      HOST="$2"; shift 2 ;;
    --port=*) PORT="${1#--port=}"; shift ;;
    --port|-Port)
      [[ $# -ge 2 ]] || fail 2 "缺少 --port 参数值。"
      PORT="$2"; shift 2 ;;
    --app-dir=*) APP_DIR="${1#--app-dir=}"; shift ;;
    --app-dir)
      [[ $# -ge 2 ]] || fail 2 "缺少 --app-dir 参数值。"
      APP_DIR="$2"; shift 2 ;;
    --collectors-dir=*) COLLECTORS_DIR="${1#--collectors-dir=}"; shift ;;
    --collectors-dir)
      [[ $# -ge 2 ]] || fail 2 "缺少 --collectors-dir 参数值。"
      COLLECTORS_DIR="$2"; shift 2 ;;
    --web-dir=*) WEB_DIR_ARG="${1#--web-dir=}"; shift ;;
    --web-dir)
      [[ $# -ge 2 ]] || fail 2 "缺少 --web-dir 参数值。"
      WEB_DIR_ARG="$2"; shift 2 ;;
    --) shift; FORWARD+=("$@"); break ;;
    *) FORWARD+=("$1"); shift ;;
  esac
done

if [[ "$HELP" -eq 1 ]]; then
  usage
  exit 0
fi

if [[ "${PKTPATH_NO_OPEN:-}" == "1" || "${PKTPATH_NO_OPEN:-}" == "true" ]]; then
  NO_OPEN=1
fi

if [[ -z "$APP_DIR" ]]; then
  APP_DIR="$(default_app_dir)"
fi

if [[ "$STOP" -eq 1 ]]; then
  do_stop "$APP_DIR"
fi

require_start_files
preflight_import

if [[ -z "$HOST" ]]; then
  HOST="${PKTPATH_HOST:-$DEFAULT_HOST}"
fi
if [[ -z "$COLLECTORS_DIR" ]]; then
  COLLECTORS_DIR="$COLLECTORS"
fi
if [[ -n "$WEB_DIR_ARG" ]]; then
  WEB_DIR="$WEB_DIR_ARG"
fi

mkdir -p "$APP_DIR/logs"
OUT_LOG="$APP_DIR/logs/studio.out.log"
ERR_LOG="$APP_DIR/logs/studio.err.log"
RT="$(runtime_path "$APP_DIR")"

if [[ -f "$RT" ]]; then
  EXIST_URL="$("$NODE" --input-type=module -e 'import fs from "node:fs"; try { const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(j.url||"")); } catch {}' "$RT" || true)"
  EXIST_PID="$("$NODE" --input-type=module -e 'import fs from "node:fs"; try { const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(String(j.pid||"")); } catch {}' "$RT" || true)"
  if [[ -n "$EXIST_URL" && -n "$EXIST_PID" ]] && pid_alive "$EXIST_PID"; then
    if http_get "${EXIST_URL%/}${HEALTH_PATH}"; then
      echo "Studio 已在运行：$EXIST_URL"
      if [[ "$NO_OPEN" -eq 0 ]]; then open_browser "$EXIST_URL"; fi
      exit 0
    fi
  fi
  if [[ -n "$EXIST_PID" ]] && ! pid_alive "$EXIST_PID"; then
    rm -f "$RT"
  fi
fi

ARGS=("$ENTRY" --host "$HOST" --app-dir "$APP_DIR" --collectors-dir "$COLLECTORS_DIR" --web-dir "$WEB_DIR" --no-open)
if [[ -n "$PORT" ]]; then
  ARGS+=(--port "$PORT")
fi
if [[ ${#FORWARD[@]} -gt 0 ]]; then
  ARGS+=("${FORWARD[@]}")
fi

: >"$OUT_LOG"
: >"$ERR_LOG"

echo "正在启动 PktPath Studio…"

if [[ "$FOREGROUND" -eq 1 ]]; then
  "$NODE" "${ARGS[@]}" >>"$OUT_LOG" 2>>"$ERR_LOG" &
  PROC_PID=$!
else
  "$NODE" "${ARGS[@]}" >>"$OUT_LOG" 2>>"$ERR_LOG" &
  PROC_PID=$!
  disown "$PROC_PID" 2>/dev/null || true
fi

cleanup_failed_start() {
  local maybe_url="${1:-}" maybe_pid="${2:-}"
  if [[ -n "$maybe_url" ]]; then
    http_quit "${maybe_url%/}${QUIT_PATH}" || true
  fi
  local victim="$maybe_pid"
  [[ -n "$victim" ]] || victim="$PROC_PID"
  if pid_alive "$victim"; then
    wait_pid_exit "$victim" 2000 || true
  fi
  if pid_alive "$victim"; then
    kill_carefully "$victim" || true
  fi
  if pid_alive "$PROC_PID" && [[ "$PROC_PID" != "$victim" ]]; then
    kill_carefully "$PROC_PID" || true
  fi
  rm -f "$RT"
}

READY_URL=""
READY_PID=""
waited=0
while (( waited < READY_TIMEOUT_MS )); do
  if ! pid_alive "$PROC_PID"; then
    break
  fi
  if read_ready_from_log "$OUT_LOG" || read_ready_from_log "$ERR_LOG"; then
    if http_get "${READY_URL%/}${HEALTH_PATH}"; then
      break
    fi
  fi
  sleep 0.1
  waited=$((waited + 100))
done

if [[ -n "$READY_URL" ]] && http_get "${READY_URL%/}${HEALTH_PATH}"; then
  STUDIO_PID="$READY_PID"
  [[ -n "$STUDIO_PID" && "$STUDIO_PID" != "0" ]] || STUDIO_PID="$PROC_PID"
  write_runtime "$RT" "$STUDIO_PID" "$PROC_PID" "$READY_URL" "$HOST" "$APP_DIR" "$ENTRY" "$NODE" "$OUT_LOG" "$ERR_LOG"
  echo "Studio 已就绪：$READY_URL"
  if [[ "$NO_OPEN" -eq 0 ]]; then
    open_browser "$READY_URL"
  fi
  if [[ "$FOREGROUND" -eq 1 ]]; then
    trap 'http_quit "${READY_URL%/}${QUIT_PATH}" || true; wait_pid_exit "$STUDIO_PID" "$QUIT_WAIT_MS" || kill_carefully "$STUDIO_PID" || true; rm -f "$RT"; exit 130' INT TERM
    wait "$PROC_PID" || true
    rm -f "$RT"
    exit 0
  fi
  exit 0
fi

read_ready_from_log "$OUT_LOG" || read_ready_from_log "$ERR_LOG" || true
cleanup_failed_start "${READY_URL:-}" "${READY_PID:-}"
if ! pid_alive "$PROC_PID"; then
  fail 1 "Studio 在就绪前已退出。请查看日志：${OUT_LOG}"$'\n'"$(tail -n 8 "$ERR_LOG" 2>/dev/null || true)$(tail -n 8 "$OUT_LOG" 2>/dev/null || true)"
fi
fail 1 "等待 Studio 就绪超时，已停止后台进程，未打开浏览器。请查看日志：${OUT_LOG}"
