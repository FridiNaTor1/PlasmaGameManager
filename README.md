# PlasmaGameManager

PlasmaGameManager is a reverse-engineered EA Games Plasma/GameManager server. Its first target is reviving Team Fortress 2 on PS3, but the protocol layer should also provide a foundation for other EA titles that used Plasma/GameManager.

This project owns the UDP GameManager/session layer. It is intended to run alongside Arcadia for FESL/Theater/login and, eventually, a PS3-compatible Source dedicated server for the actual TF2 gameplay backend.

## How It Works

TF2 PS3 does not connect straight to a normal PC Source server from the server browser. The flow is split into layers:

- **FESL/Theater:** Arcadia handles account login, server listing, matchmaking, and returns the game server endpoint.
- **Plasma/GameManager:** This server handles the PS3 game-session handshake, player reservation, roster, mesh/join state, and the transition toward the game backend.
- **Source backend:** A PS3-compatible Source dedicated server is still required for map simulation and gameplay traffic.

The goal is a native semantic implementation, not replaying one captured packet sequence. The server decodes client messages into GameManager commands, updates explicit session/player state, and writes responses using the recovered Plasma/GameManager packet model.

## Current Status

This repository is currently aimed at TF2 PS3 research and local RPCS3 testing. Arcadia integration is expected. The Source PS3 server is **TBD** while legal and distribution details are worked out; it may need to stay private.

## Requirements

- Linux shell environment.
- .NET SDK. This repo pins SDK `8.0.419` in `global.json`.
- Arcadia, preferably this build: [FridiNaTor1/arcadia](https://github.com/FridiNaTor1/arcadia).
- RPCS3 with network/RPCN support enabled for local testing.
- A PS3-compatible TF2 Source server: **TBD**.

The local development machine uses:

```sh
/home/YOURUSERNAME/.dotnet/dotnet
```

If your SDK is somewhere else, set `DOTNET` when running scripts:

```sh
DOTNET=/path/to/dotnet ./run-rpcs3-live-stack.sh --check
```

## Repository Layout

Public source lives under `src/`.

The following folders are intentionally gitignored because they are local/private working areas:

- `arcadia/`
- `Source-Server/`
- `docs/`
- `re/`
- `scripts/`
- `tests/`

Putting Arcadia into the ignored `arcadia/` folder makes the easy launcher simpler, but it is not required. You can keep Arcadia elsewhere and point the launcher at it with `ARCADIA_ROOT`.

## Build

From the repository root:

```sh
/home/deck/.dotnet/dotnet build PlasmaGameManager.sln
```

If your `dotnet` is on `PATH`, this also works:

```sh
dotnet build PlasmaGameManager.sln
```

## Easy Run

Use this when Arcadia and the Source backend are placed in the ignored local folders:

```text
arcadia/
Source-Server/
```

Expected local layout:

```text
arcadia/src/server/Arcadia.csproj
Source-Server/tools/run_tf2ps3_dedicated.sh
```

Check the stack:

```sh
./run-rpcs3-live-stack.sh --check
```

Start Arcadia, PlasmaGameManager, and the Source backend together:

```sh
./run-rpcs3-live-stack.sh
```

Defaults:

- Arcadia/FESL/Theater runs from `arcadia/`.
- PlasmaGameManager listens on UDP `27015`.
- Source backend listens on UDP `27016`.
- Local test host is `127.0.0.1`.
- Logs are written to `artifacts/live-stack/`.

Useful overrides:

```sh
TF2PS3_GAME_HOST=127.0.0.1 \
TF2PS3_GAME_PORT=27015 \
TF2PS3_SOURCE_HOST=127.0.0.1 \
TF2PS3_SOURCE_PORT=27016 \
./run-rpcs3-live-stack.sh
```

## Separate Run

Use this when you want to start each service manually or Arcadia is installed elsewhere.

1. Start Arcadia:

```sh
cd /path/to/arcadia
/home/deck/.dotnet/dotnet run --project src/server/Arcadia.csproj
```

For TF2 PS3 testing, Arcadia must advertise the PlasmaGameManager endpoint as the static TF2 server. The launcher sets these automatically, but manual runs should set equivalent values:

```sh
ArcadiaSettings__EnableTf2StaticServer=true \
ArcadiaSettings__Tf2StaticServerAddress=127.0.0.1 \
ArcadiaSettings__Tf2StaticServerPort=27015 \
ArcadiaSettings__Tf2StaticServerPublicPort=27015 \
/home/deck/.dotnet/dotnet run --project src/server/Arcadia.csproj
```

2. Start the Source backend:

```sh
cd /path/to/source-server
TF2PS3_DEDICATED_PORT=27016 \
TF2PS3_DEDICATED_MAP=ctf_2fort \
tools/run_tf2ps3_dedicated.sh
```

The Source backend is currently **TBD** for public release.

3. Start PlasmaGameManager:

```sh
cd /path/to/PlasmaGameManager
/home/deck/.dotnet/dotnet run --project src/PlasmaGameManager.Server/PlasmaGameManager.Server.csproj -- \
  --bind 0.0.0.0 \
  --port 27015 \
  --profile tf2-ps3 \
  --source-host 127.0.0.1 \
  --source-port 27016 \
  --evidence-log artifacts/live-stack/live-gamemanager-events.jsonl
```

## RPCS3 Configuration

For local testing:

1. Enable network connection and RPCN.
2. Enable UPNP.
3. Set `IP/Hosts switches`.

Default local test switches:

```text
theater.ps3.arcadia=127.0.0.1&&hl2-ps3.fesl.ea.com=127.0.0.1&&messaging.ea.com=127.0.0.1
```

Replace `127.0.0.1` with your server host if RPCS3 is running on another machine.

For example:

```text
theater.ps3.arcadia=192.168.1.50&&hl2-ps3.fesl.ea.com=192.168.1.50&&messaging.ea.com=192.168.1.50
```

## Notes

- Arcadia owns FESL/Theater/login and server advertisement.
- PlasmaGameManager owns the PS3 GameManager UDP session.
- The Source backend owns actual map simulation and gameplay.
- The public repository intentionally excludes private reverse-engineering notes, local test scripts, PCAPs, binaries, and private Source-server work.
