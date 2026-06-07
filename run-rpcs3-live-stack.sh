#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DOTNET=${DOTNET:-/home/deck/.dotnet/dotnet}

ARCADIA_ROOT=${ARCADIA_ROOT:-"$ROOT/arcadia"}
SOURCE_SERVER_ROOT=${SOURCE_SERVER_ROOT:-"$ROOT/Source-Server"}

GAME_HOST=${TF2PS3_GAME_HOST:-127.0.0.1}
GAME_PORT=${TF2PS3_GAME_PORT:-27015}
SOURCE_HOST=${TF2PS3_SOURCE_HOST:-127.0.0.1}
SOURCE_PORT=${TF2PS3_SOURCE_PORT:-27016}
SOURCE_MAP=${TF2PS3_DEDICATED_MAP:-ctf_2fort}
SOURCE_HOSTNAME=${TF2PS3_DEDICATED_HOSTNAME:-TF2PS3}
NET_TRACE=${TF2PS3_NET_TRACE:-1}

LOG_DIR=${TF2PS3_STACK_LOG_DIR:-"$ROOT/artifacts/live-stack"}
PLASMA_EVIDENCE_LOG=${PLASMA_EVIDENCE_LOG:-"$LOG_DIR/live-gamemanager-events.jsonl"}
ARCADIA_LOG="$LOG_DIR/arcadia.log"
SOURCE_LOG="$LOG_DIR/source-server.log"
PLASMA_LOG="$LOG_DIR/plasma-gamemanager.log"

arcadia_pid=""
source_pid=""
plasma_pid=""

usage() {
	cat <<EOF
Usage: $0 [--check]

Expected local source folders:
  $ROOT/arcadia        Arcadia source tree, containing src/server/Arcadia.csproj
  $ROOT/Source-Server  PS3 Source server source tree, containing tools/run_tf2ps3_dedicated.sh

Useful overrides:
  ARCADIA_ROOT=/path/to/arcadia
  SOURCE_SERVER_ROOT=/path/to/tf2ps3-source-worktree
  TF2PS3_GAME_HOST=127.0.0.1
  TF2PS3_GAME_PORT=27015
  TF2PS3_SOURCE_HOST=127.0.0.1
  TF2PS3_SOURCE_PORT=27016
  TF2PS3_NET_TRACE=1
  TF2PS3_STACK_LOG_DIR=$ROOT/artifacts/live-stack
EOF
}

cleanup() {
	for pid in "$plasma_pid" "$source_pid" "$arcadia_pid"; do
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
		fi
	done
	for pid in "$plasma_pid" "$source_pid" "$arcadia_pid"; do
		if [ -n "$pid" ]; then
			wait "$pid" 2>/dev/null || true
		fi
	done
}

trap cleanup EXIT INT TERM

check_file() {
	path=$1
	description=$2
	if [ ! -f "$path" ]; then
		echo "missing $description: $path" >&2
		return 1
	fi
}

check_executable() {
	path=$1
	description=$2
	if [ ! -x "$path" ]; then
		echo "missing executable $description: $path" >&2
		return 1
	fi
}

check_layout() {
	status=0
	if [ ! -x "$DOTNET" ]; then
		echo "missing dotnet: $DOTNET" >&2
		status=1
	fi
	check_file "$ARCADIA_ROOT/src/server/Arcadia.csproj" "Arcadia project" || status=1
	check_executable "$SOURCE_SERVER_ROOT/tools/run_tf2ps3_dedicated.sh" "Source server launcher" || status=1
	check_file "$ROOT/src/PlasmaGameManager.Server/PlasmaGameManager.Server.csproj" "PlasmaGameManager server project" || status=1
	if [ "$status" -eq 0 ]; then
		echo "stack layout ok"
		echo "arcadia:       $ARCADIA_ROOT"
		echo "source-server: $SOURCE_SERVER_ROOT"
		echo "game endpoint: $GAME_HOST:$GAME_PORT"
		echo "source backend:$SOURCE_HOST:$SOURCE_PORT"
		echo "logs:          $LOG_DIR"
	fi
	return "$status"
}

case "${1:-}" in
	--help|-h)
		usage
		exit 0
		;;
	--check)
		check_layout
		exit $?
		;;
	"")
		;;
	*)
		usage >&2
		exit 2
		;;
esac

check_layout
mkdir -p "$LOG_DIR"
: > "$PLASMA_EVIDENCE_LOG"
: > "$ARCADIA_LOG"
: > "$SOURCE_LOG"
: > "$PLASMA_LOG"

echo "starting Arcadia/FESL/Theater..."
(
	cd "$ARCADIA_ROOT"
	ArcadiaSettings__ListenAddress="${ARCADIA_LISTEN_ADDRESS:-0.0.0.0}" \
	ArcadiaSettings__TheaterAddress="${ARCADIA_THEATER_ADDRESS:-theater.ps3.arcadia}" \
	ArcadiaSettings__MessengerAddress="${ARCADIA_MESSENGER_ADDRESS:-messaging.ea.com}" \
	ArcadiaSettings__MessengerPort="${ARCADIA_MESSENGER_PORT:-42069}" \
	ArcadiaSettings__Tf2StatsShape="${ARCADIA_TF2_STATS_SHAPE:-empty}" \
	ArcadiaSettings__EnableTf2StaticServer=true \
	ArcadiaSettings__Tf2StaticServerAddress="$GAME_HOST" \
	ArcadiaSettings__Tf2StaticServerPort="$GAME_PORT" \
	ArcadiaSettings__Tf2StaticServerPublicPort="$GAME_PORT" \
	ArcadiaSettings__Tf2StaticServerName="${ARCADIA_TF2_SERVER_NAME:-TF2_PS3_LOCAL}" \
	ArcadiaSettings__Tf2StaticServerMap="$SOURCE_MAP" \
	ArcadiaSettings__Tf2StaticServerMaxPlayers="${ARCADIA_TF2_MAX_PLAYERS:-16}" \
	ArcadiaSettings__Tf2StaticServerActivePlayers="${ARCADIA_TF2_ACTIVE_PLAYERS:-0}" \
	DebugSettings__EnableFileLogging="${ARCADIA_ENABLE_FILE_LOGGING:-true}" \
	DebugSettings__DisableTheaterJoinTimeout="${ARCADIA_DISABLE_THEATER_JOIN_TIMEOUT:-true}" \
	DnsSettings__EnableDns="${ARCADIA_ENABLE_DNS:-false}" \
	"$DOTNET" run --project src/server/Arcadia.csproj
) > "$ARCADIA_LOG" 2>&1 &
arcadia_pid=$!

sleep "${TF2PS3_ARCADIA_STARTUP_DELAY:-2}"

echo "starting Source backend on $SOURCE_HOST:$SOURCE_PORT..."
(
	cd "$SOURCE_SERVER_ROOT"
	TF2PS3_DEDICATED_PORT="$SOURCE_PORT" \
	TF2PS3_DEDICATED_MAP="$SOURCE_MAP" \
	TF2PS3_DEDICATED_HOSTNAME="$SOURCE_HOSTNAME" \
	TF2PS3_NET_TRACE="$NET_TRACE" \
	TF2PS3_DEDICATED_LOGGING="${TF2PS3_DEDICATED_LOGGING:-1}" \
	tools/run_tf2ps3_dedicated.sh
) > "$SOURCE_LOG" 2>&1 &
source_pid=$!

sleep "${TF2PS3_SOURCE_STARTUP_DELAY:-4}"

echo "starting PlasmaGameManager on $GAME_HOST:$GAME_PORT -> source $SOURCE_HOST:$SOURCE_PORT..."
(
	cd "$ROOT"
	PLASMA_BIND="${PLASMA_BIND:-0.0.0.0}" \
	PLASMA_PROFILE="${PLASMA_PROFILE:-tf2-ps3}" \
	PLASMA_SOURCE_PROXY=1 \
	PLASMA_SOURCE_PROTOCOL="${PLASMA_SOURCE_PROTOCOL:-ps3-native-passthrough}" \
	"$DOTNET" run --project src/PlasmaGameManager.Server/PlasmaGameManager.Server.csproj -- \
		--bind "${PLASMA_BIND:-0.0.0.0}" \
		--port "$GAME_PORT" \
		--profile "${PLASMA_PROFILE:-tf2-ps3}" \
		--source-host "$SOURCE_HOST" \
		--source-port "$SOURCE_PORT" \
		--source-timeout-ms "${PLASMA_SOURCE_TIMEOUT_MS:-250}" \
		--evidence-log "$PLASMA_EVIDENCE_LOG"
) > "$PLASMA_LOG" 2>&1 &
plasma_pid=$!

cat <<EOF
stack running
  Arcadia pid:       $arcadia_pid  log: $ARCADIA_LOG
  Source pid:        $source_pid   log: $SOURCE_LOG
  PlasmaGameManager: $plasma_pid   log: $PLASMA_LOG
  Evidence log:      $PLASMA_EVIDENCE_LOG

RPCS3 IP/Host switch target:
  theater.ps3.arcadia=$GAME_HOST&&hl2-ps3.fesl.ea.com=$GAME_HOST&&messaging.ea.com=$GAME_HOST

Press Ctrl+C to stop the stack.
EOF

wait "$arcadia_pid" "$source_pid" "$plasma_pid"
