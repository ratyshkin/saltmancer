# saltmancer — CREATE2 vanity & safety explorer (offline)

**saltmancer** helps you **predict CREATE2 addresses** and **hunt salts** that
yield recognizable prefixes (e.g., `0x0000…`, `0xdead…`) — all without RPC.
You can assemble init code from bytecode + constructor args, score vanity hits,
and export reports (JSON/CSV) or a tiny SVG badge.

No node. No internet. Pure EIP-1014 math.

## Why this is useful

- Vanity for branding: get a contract address with `0x0000` / `0xDEAD` prefix.
- Pre-deployment safety: see how many addresses in your scan share the same
  first 2 bytes (**prefix crowding**) — good context for recognizability.
- CI-friendly: reproducible outputs; no external calls.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
