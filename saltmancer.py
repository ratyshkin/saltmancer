#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
saltmancer — CREATE2 vanity & safety explorer (offline).

Commands
  compute       -> One-shot CREATE/CREATE2 address (with convenience flags)
  hunt          -> Batch search salts for vanity constraints (prefix/suffix/zeros)
  score         -> Score a list of addresses for vanity (CSV/JSON)
  svg-badge     -> Render a tiny vanity badge from a best hit

Notes
- No RPC, no bytecode fetching. You provide bytecode or init code or init code hash.
- If you pass --bytecode and constructor ABI+args, we'll assemble init code (bytecode + ABI-encoded args).
- Safety angle: "prefix crowding" report shows how many hits share the same starting nibbles.

Examples
  # Minimal compute with known init code hash
  $ python saltmancer.py compute --deployer 0xDepl... --salt-int 42 --init-code-hash 0xabc...

  # Compute from bytecode + constructor args (ABI encoded)
  $ python saltmancer.py compute --deployer 0xDepl... --salt-text hello \
        --bytecode 0x600a600c600039600a6000f3... \
        --constructor "address,uint256" --arg 0xCafe... --arg 1000

  # Hunt salts for vanity prefix 0x0000 (first 4 hex nibbles after 0x)
  $ python saltmancer.py hunt --deployer 0xDepl... --bytecode 0x60... --constructor "" \
        --range-start 0 --range-count 100000 --want-prefix 0000 --csv hits.csv --svg badge.svg
"""

import csv
import json
import os
import sys
import math
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

import click
from eth_utils import keccak, to_checksum_address

try:
    from eth_abi import encode as abi_encode
except Exception:  # pragma: no cover
    abi_encode = None

# -------------------------- Helpers --------------------------

def strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h

def norm0x(h: str) -> str:
    return h if h.startswith("0x") else ("0x" + h)

def to_bytes(h: str) -> bytes:
    h2 = strip0x(h)
    if len(h2) % 2 != 0:
        raise click.ClickException("Hex length must be even")
    try:
        return bytes.fromhex(h2)
    except Exception as e:
        raise click.ClickException(f"Invalid hex: {e}")

def pad32(b: bytes) -> bytes:
    return b.rjust(32, b"\x00")

def as_salt_bytes(salt_int: Optional[int], salt_text: Optional[str], salt_hex: Optional[str]) -> bytes:
    if sum(x is not None for x in (salt_int, salt_text, salt_hex)) != 1:
        raise click.ClickException("Provide exactly one of --salt-int / --salt-text / --salt-hex")
    if salt_int is not None:
        if salt_int < 0:
            raise click.ClickException("salt-int must be >= 0")
        return pad32(salt_int.to_bytes((salt_int.bit_length()+7)//8 or 1, "big"))
    if salt_text is not None:
        return pad32(salt_text.encode("utf-8"))
    return pad32(to_bytes(salt_hex))

def keccak_hex(b: bytes) -> str:
    return "0x" + keccak(b).hex()

def eip1014_create2(deployer: str, salt: bytes, init_code_hash: bytes) -> str:
    if not deployer.startswith("0x") or len(deployer) != 42:
        raise click.ClickException("deployer must be a 0x-prefixed 20-byte address")
    b = b"\xff" + bytes.fromhex(strip0x(deployer)) + salt + init_code_hash
    return to_checksum_address("0x" + keccak(b)[12:].hex())

def create_address(deployer: str, nonce: int) -> str:
    # Legacy CREATE (RLP(deployer, nonce)); simplified for common nonces 0..0x7f ranges is fine to use rlp
    import rlp
    from rlp.sedes import big_endian_int, Binary
    payload = [bytes.fromhex(strip0x(deployer)), nonce]
    addr = keccak(rlp.encode(payload))[12:]
    return to_checksum_address("0x" + addr.hex())

def build_init_code(bytecode: Optional[str], ctor_types: Optional[str], ctor_args: List[str]) -> Optional[bytes]:
    if bytecode is None:
        return None
    code = to_bytes(bytecode)
    if ctor_types is None:
        # No constructor args
        return code
    if ctor_types.strip() == "":
        return code  # explicitly no args
    if abi_encode is None:
        raise click.ClickException("eth-abi not installed; cannot encode constructor args. See requirements.txt")
    types = [t.strip() for t in ctor_types.split(",")] if ctor_types else []
    # normalize values
    vals = []
    for t, a in zip(types, ctor_args):
        if t.startswith("uint") or t.startswith("int"):
            vals.append(int(a, 0))
        elif t == "address":
            vals.append(a)
        elif t == "bool":
            vals.append(a.lower() in ("1","true","yes","y"))
        elif t == "bytes" or t.startswith("bytes"):
            vals.append(bytes.fromhex(strip0x(a)))
        elif t == "string":
            vals.append(a)
        else:
            vals.append(a)
    enc = abi_encode(types, vals)
    return code + enc

# -------------------------- Vanity scoring --------------------------

@dataclass
class VanityHit:
    salt_hex: str
    address: str
    score: int
    metrics: Dict[str, int]

def vanity_score(addr: str, want_prefix: Optional[str], want_suffix: Optional[str], want_leading_zeros: int) -> Tuple[int, Dict[str,int]]:
    h = strip0x(addr).lower()
    pts = 0
    m = {"leading_zero_nibbles":0, "prefix_match":0, "suffix_match":0}
    # leading zeros
    lz = 0
    for c in h:
        if c == "0": lz += 1
        else: break
    m["leading_zero_nibbles"] = lz
    pts += min(lz, 40) * 2  # up to 80 pts
    # explicit prefix
    if want_prefix:
        want = want_prefix.lower()
        k = len(want)
        pref = 1 if h.startswith(want) else 0
        m["prefix_match"] = pref * k
        pts += pref * (10 + k)  # reward longer exact match
    # suffix
    if want_suffix:
        want = want_suffix.lower()
        k = len(want)
        suf = 1 if h.endswith(want) else 0
        m["suffix_match"] = suf * k
        pts += suf * (10 + k)
    # target zeros
    if want_leading_zeros > 0:
        pts += (10 if lz >= want_leading_zeros else 0)
    return pts, m

# -------------------------- CLI --------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """saltmancer — CREATE2 vanity & safety explorer (offline)."""
    pass

@cli.command("compute")
@click.option("--deployer", required=True, type=str, help="0x deployer address (20 bytes).")
@click.option("--salt-int", type=int, default=None, help="Salt as integer.")
@click.option("--salt-text", type=str, default=None, help="Salt from UTF-8 text (padded to 32 bytes).")
@click.option("--salt-hex", type=str, default=None, help="Salt as hex (0x...).")
@click.option("--init-code", type=str, default=None, help="Full init code (0x...).")
@click.option("--init-code-hash", type=str, default=None, help="Keccak256 of init code (0x...).")
@click.option("--bytecode", type=str, default=None, help="Creation bytecode (no args).")
@click.option("--constructor", "ctor_types", type=str, default=None, help='Constructor types CSV, e.g. "address,uint256". Empty string means no args.')
@click.option("--arg", "ctor_args", multiple=True, help="Constructor arg (repeat).")
@click.option("--create-nonce", type=int, default=None, help="If provided, also compute legacy CREATE address for deployer+nonce.")
def compute_cmd(deployer, salt_int, salt_text, salt_hex, init_code, init_code_hash, bytecode, ctor_types, ctor_args, create_nonce):
    """Compute CREATE2 (and optional CREATE) addresses."""
    salt = as_salt_bytes(salt_int, salt_text, salt_hex) if (salt_int is not None or salt_text is not None or salt_hex is not None) else None

    if init_code_hash:
        ich = to_bytes(init_code_hash)
    else:
        ic = init_code or build_init_code(bytecode, ctor_types, list(ctor_args))
        if ic is None:
            raise click.ClickException("Provide one of --init-code / --init-code-hash / --bytecode (+constructor)")
        ich = keccak(ic)

    out = {}
    if salt is not None:
        addr = eip1014_create2(deployer, salt, ich)
        out["create2"] = {"address": addr, "salt": "0x"+salt.hex(), "init_code_hash": "0x"+ich.hex()}
    if create_nonce is not None:
        out["create"] = {"address": create_address(strip0x(deployer), create_nonce), "nonce": create_nonce}
    click.echo(json.dumps(out, indent=2))

@cli.command("hunt")
@click.option("--deployer", required=True, type=str, help="0x deployer address.")
@click.option("--init-code", type=str, default=None, help="Full init code (0x...).")
@click.option("--init-code-hash", type=str, default=None, help="Keccak256 of init code (0x...).")
@click.option("--bytecode", type=str, default=None, help="Creation bytecode (optional).")
@click.option("--constructor", "ctor_types", type=str, default=None, help='Constructor types CSV, e.g. "address,uint256". Empty string means no args.')
@click.option("--arg", "ctor_args", multiple=True, help="Constructor arg (repeat).")
@click.option("--range-start", type=int, default=0, show_default=True, help="Start salt integer.")
@click.option("--range-count", type=int, default=100000, show_default=True, help="How many salts to scan from start.")
@click.option("--want-prefix", type=str, default=None, help='Desired hex prefix (e.g., "0000" or "dead").')
@click.option("--want-suffix", type=str, default=None, help='Desired hex suffix (e.g., "c0de").')
@click.option("--want-leading-zeros", type=int, default=0, show_default=True, help="Desired leading zero nibbles (>=0).")
@click.option("--top", type=int, default=20, show_default=True, help="Keep best N hits in memory.")
@click.option("--csv", "csv_out", type=click.Path(writable=True), default=None, help="Write CSV hits.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON hits.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write SVG badge for best hit.")
def hunt_cmd(deployer, init_code, init_code_hash, bytecode, ctor_types, ctor_args, range_start, range_count, want_prefix, want_suffix, want_leading_zeros, top, csv_out, json_out, svg_out):
    """Search salt integers for vanity CREATE2 addresses."""
    if init_code_hash:
        ich = to_bytes(init_code_hash)
    else:
        ic = init_code or build_init_code(bytecode, ctor_types, list(ctor_args))
        if ic is None:
            raise click.ClickException("Provide one of --init-code / --init-code-hash / --bytecode (+constructor)")
        ich = keccak(ic)

    best: List[VanityHit] = []
    prefix_count: Dict[str,int] = {}

    for i in range(range_start, range_start + range_count):
        salt = pad32(i.to_bytes((i.bit_length()+7)//8 or 1, "big"))
        addr = eip1014_create2(deployer, salt, ich)
        # score
        score, metrics = vanity_score(addr, want_prefix, want_suffix, want_leading_zeros)
        # maintain prefix crowding (first 4 nibbles)
        p4 = strip0x(addr)[:4]
        prefix_count[p4] = prefix_count.get(p4, 0) + 1

        if score > 0 or (want_prefix is None and want_suffix is None and want_leading_zeros == 0):
            best.append(VanityHit("0x"+salt.hex(), addr, score, metrics))
            best.sort(key=lambda h: (-h.score, h.address))
            if len(best) > max(1, top):
                best = best[:top]

    # outputs
    hits = [asdict(h) for h in best]
    resp = {
        "deployer": deployer,
        "init_code_hash": "0x"+ich.hex(),
        "scanned": range_count,
        "range_start": range_start,
        "top": hits,
        "prefix_crowding_unique_p4": len(prefix_count),
    }
    click.echo(json.dumps(resp, indent=2))

    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["salt_hex","address","score","leading_zero_nibbles","prefix_match","suffix_match"])
            for h in best:
                w.writerow([h.salt_hex, h.address, h.score, h.metrics["leading_zero_nibbles"], h.metrics["prefix_match"], h.metrics["suffix_match"]])
        click.echo(f"Wrote CSV: {csv_out}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(resp, f, indent=2)
        click.echo(f"Wrote JSON: {json_out}")

    if svg_out:
        if best:
            b = best[0]
            color = "#3fb950" if b.metrics["leading_zero_nibbles"] >= 6 or (want_prefix or want_suffix) else "#d29922"
            svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="760" height="48" role="img" aria-label="saltmancer">
  <rect width="760" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    saltmancer: best {b.address[:14]}…  score {b.score}  salt {b.salt_hex[:10]}…  LZ={b.metrics['leading_zero_nibbles']}
  </text>
  <circle cx="735" cy="24" r="6" fill="{color}"/>
</svg>"""
            with open(svg_out, "w", encoding="utf-8") as f:
                f.write(svg)
            click.echo(f"Wrote SVG badge: {svg_out}")
        else:
            click.echo("No hits to badge.")

@cli.command("score")
@click.argument("path", type=str)
@click.option("--csv-out", type=click.Path(writable=True), default=None, help="Write CSV with scores.")
@click.option("--want-prefix", type=str, default=None)
@click.option("--want-suffix", type=str, default=None)
@click.option("--want-leading-zeros", type=int, default=0, show_default=True)
def score_cmd(path, csv_out, want_prefix, want_suffix, want_leading_zeros):
    """
    Score a list of addresses (txt or json array) for vanity metrics.
    """
    addrs: List[str] = []
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            if isinstance(obj, list):
                addrs = [str(x) for x in obj]
    else:
        with open(path, "r", encoding="utf-8") as f:
            addrs = [l.strip() for l in f if l.strip()]

    rows = []
    for a in addrs:
        s, m = vanity_score(a, want_prefix, want_suffix, want_leading_zeros)
        rows.append({"address": a, "score": s, **m})
    click.echo(json.dumps(rows, indent=2))

    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["address","score","leading_zero_nibbles","prefix_match","suffix_match"])
            w.writeheader()
            w.writerows(rows)
        click.echo(f"Wrote CSV: {csv_out}")

@cli.command("svg-badge")
@click.argument("address", type=str)
@click.option("--score", type=int, default=0)
@click.option("--out", type=click.Path(writable=True), default="saltmancer-badge.svg", show_default=True)
def badge_cmd(address, score, out):
    """Render a tiny vanity badge for a single address."""
    h = strip0x(address)
    lz = 0
    for c in h:
        if c == "0": lz += 1
        else: break
    color = "#3fb950" if lz >= 6 else "#d29922" if lz >= 3 else "#6e7681"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="600" height="48" role="img" aria-label="saltmancer">
  <rect width="600" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    saltmancer: {address[:14]}…  score {score}  LZ={lz}
  </text>
  <circle cx="575" cy="24" r="6" fill="{color}"/>
</svg>"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg)
    click.echo(f"Wrote SVG badge: {out}")

if __name__ == "__main__":
    cli()
