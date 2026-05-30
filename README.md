# proxylint

Go CLI tool to validate and connectivity-check proxy links by launching **Xray** and/or **sing-box** cores.  
Telegram proxies are checked directly using **github.com/go-telegram/bot** (SOCKS5) or raw TCP (MTProto).

## Features

- **Input**: single proxy link (`--proxy`) or file (`--in`), one link per line
- **Core checks** (vless, trojan, vmess, ss, socks, http):
  - Launch `xray` or `sing-box` with generated config
  - Probe through SOCKS inbound to configurable URL
- **Telegram checks** (`tg://proxy`, `https://t.me/proxy`, `mtproto://`):
  - SOCKS5 proxies: verified via `go-telegram/bot` call to Bot API
  - MTProto proxies: verified via raw TCP + MTProto handshake probe
- **Configurable**: timeout, retries, delay, concurrency, probe URL, core selection
- **Output**: valid proxies written to file one per line; optional failed and JSON files

## Requirements

- Go `1.26+` (to build)
- **xray** and/or **sing-box** binaries in PATH (for non-Telegram proxy checks)
- No API keys needed — Telegram check uses a fake bot token (only verifies Telegram reachability, not bot functionality)

## Build

```bash
go build -o proxylint ./cmd/proxylint
```

## Usage

```bash
./proxylint check --in /Users/arian/Documents/proxies.txt --out valid.txt
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--proxy` | `""` | Single proxy link to check |
| `--in` | `""` | Input file path (one proxy per line) |
| `--out` | `valid.txt` | Output file for connected proxies |
| `--failed` | `""` | Optional output file for failed proxies |
| `--json` | `""` | Optional JSON report file |
| `--timeout` | `8s` | Per-check timeout |
| `--retries` | `1` | Retry count per core |
| `--retry-delay` | `300ms` | Delay between retries |
| `--concurrency` | `30` | Concurrent checks |
| `--probe-url` | `https://www.google.com/generate_204` | HTTP probe URL (for core checks) |
| `--core` | `any` | Core mode: `any`, `xray`, `sing-box`, `both` |
| `--xray-bin` | `xray` | Xray binary path |
| `--singbox-bin` | `sing-box` | sing-box binary path |

### Core mode

- `xray` — only check with xray
- `sing-box` — only check with sing-box
- `any` (default) — check with both, pass if either succeeds
- `both` — check with both, pass only if both succeed

Telegram proxies always use the built-in Go checker (bypass cores).

## Examples

Check proxies from a file and save valid ones:

```bash
./proxylint check --in /Users/arian/Documents/proxies.txt --out /Users/arian/Documents/valid.txt
```

Use only xray core:

```bash
./proxylint check --in proxies.txt --core xray --out valid.txt
```

Strict verification on both cores with debug output:

```bash
./proxylint check --in proxies.txt --core both --out valid.txt --failed failed.txt --json report.json
```

Single proxy with custom timeout and probe URL:

```bash
./proxylint check --proxy "vless://..." --timeout 10s --probe-url "https://example.com/generate_204"
```

File with Telegram SOCKS5 and MTProto proxies:

```bash
./proxylint check --in tg_proxies.txt --out tg_valid.txt --timeout 15s
```

## Validated run data

The command below was run against `/home/ubuntu/Downloads/Telegram Desktop/proxies.txt` with Xray core:

```bash
./proxylint check \
  --in "/home/ubuntu/Downloads/Telegram Desktop/proxies.txt" \
  --core xray \
  --xray-bin "/tmp/opencode/xray/xray" \
  --timeout 4s \
  --retries 0 \
  --concurrency 40 \
  --out "/tmp/opencode/valid.txt" \
  --failed "/tmp/opencode/failed.txt" \
  --json "/tmp/opencode/report.json"
```

Observed summary:

```text
done: total=2229 parsed=2227 parse_fail=2 passed=105 failed=2122
```

Generated files from that run:

- `/tmp/opencode/valid.txt` -> 105 lines
- `/tmp/opencode/failed.txt` -> 2122 lines
- `/tmp/opencode/report.json` -> full JSON report for 2227 parsed entries

## Output format

Valid proxies are written to `--out` (one URL per line).  
The console shows per-proxy results:

```
OK [xray] vless (vless://...) latency=340ms
FAIL [telegram] telegram-socks (https://t.me/proxy?server=...) err=connection refused
```

Exit codes:
- `0` — all proxies passed
- `1` — at least one proxy failed or parse error
- `2` — argument / config error
