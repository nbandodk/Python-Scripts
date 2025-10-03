#!/usr/bin/env python3
"""
remove_unscoped_ips.py

Filter subdomains to only those that resolve to IPs within in-scope subnet(s)/CIDR(s).

Given:
  1) A file of in-scope networks (CIDRs, single IPs, or IP ranges)
  2) A file of subdomains gathered during passive recon

This script resolves each subdomain to its IP addresses and retains only the
subdomains whose resolved IPs fall within the in-scope networks. It can also
output out-of-scope subdomains and a CSV mapping for auditing.

No third-party dependencies are required (uses Python standard library).

Examples
--------
# Keep only in-scope subdomains (writes to in_scope.txt)
python remove_unscoped_ips.py \
  --cidrs scope.txt \
  --subdomains subdomains.txt \
  --output-in-scope in_scope.txt

# Also write out-of-scope and a CSV mapping
python remove_unscoped_ips.py \
  --cidrs scope.txt \
  --subdomains subdomains.txt \
  --output-in-scope in_scope.txt \
  --output-out-of-scope out_scope.txt \
  --output-csv mapping.csv

# Only consider IPv4 results, with custom timeout and 100 workers
python remove_unscoped_ips.py \
  --cidrs scope.txt \
  --subdomains subdomains.txt \
  --family ipv4 \
  --timeout 3 \
  --workers 100 \
  --output-in-scope in_scope_ipv4.txt

Input formats
-------------
Scope file (one per line; comments with # are allowed):
    10.0.0.0/8
    192.168.1.10       # single host OK
    203.0.113.10-203.0.113.63  # range OK
    2001:db8::/32

Subdomains file (one per line). URL prefixes and paths will be stripped:
    app.example.com
    https://api.example.com/login
    CDN.EXAMPLE.COM.

Exit codes
----------
  0 success
  1 bad arguments / input files
  2 runtime error
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import os
import re
import socket
import sys
import time
from typing import Iterable, List, Optional, Sequence, Set, Tuple, Union


# -----------------------------
# Parsing helpers
# -----------------------------

_COMMENT_RE = re.compile(r"\s*#.*$")
_PROTOCOL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _strip_comments(line: str) -> str:
    return _COMMENT_RE.sub("", line).strip()


def _normalize_hostname(s: str) -> Optional[str]:
    """Lowercase, strip scheme, port, trailing dot, and path. Return None if invalid."""
    s = s.strip()
    if not s:
        return None
    # Remove CSV-like extra tokens, keep only the first if comma-separated
    if "," in s:
        s = s.split(",", 1)[0]
    # Keep only first whitespace-delimited token
    s = s.split()[0]
    # Strip scheme
    if _PROTOCOL_RE.match(s):
        s = _PROTOCOL_RE.sub("", s)
    # Strip credentials if present (user:pass@host)
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    # Strip path/query/fragment
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    # Strip port
    if s.startswith("[") and "]" in s:
        # IPv6 literal in brackets: [2001:db8::1]:443 -> keep inside brackets
        host = s.split("]", 1)[0][1:]
    else:
        host = s.split(":", 1)[0]
    host = host.rstrip(".").lower()
    # Skip pure IP literals; we expect hostnames here but allow them anyway
    return host or None


# -----------------------------
# Scope parsing (CIDR/IP/ranges)
# -----------------------------

def _parse_network_token(token: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    token = token.strip()
    if not token:
        return []
    # Try CIDR (or IP as /32 or /128 when strict=False)
    try:
        net = ipaddress.ip_network(token, strict=False)
        return [net]
    except Exception:
        pass
    # Try single IP
    try:
        ip = ipaddress.ip_address(token)
        net = ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}", strict=False)
        return [net]
    except Exception:
        pass
    # Try hyphenated range: start-end
    if "-" in token:
        start, end = [p.strip() for p in token.split("-", 1)]
        try:
            ip_start = ipaddress.ip_address(start)
            ip_end = ipaddress.ip_address(end)
            if ip_start.version != ip_end.version:
                raise ValueError("IP range version mismatch")
            nets = list(ipaddress.summarize_address_range(ip_start, ip_end))
            return nets
        except Exception:
            pass
    raise ValueError(f"Unrecognized network token: {token}")


def load_scope_networks(path: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = _strip_comments(raw)
            if not line:
                continue
            # Allow comma or whitespace separated tokens per line
            tokens = re.split(r"[\s,]+", line)
            for t in tokens:
                if not t:
                    continue
                nets.extend(_parse_network_token(t))
    # Normalize/merge by collapsing overlapping networks (best-effort)
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
    v4 = list(ipaddress.collapse_addresses(v4))
    v6 = list(ipaddress.collapse_addresses(v6))
    return v4 + v6


# -----------------------------
# DNS resolution
# -----------------------------

def resolve_ips(host: str, family: str = "any") -> Tuple[Set[str], Set[str]]:
    """Resolve hostname to IPv4/IPv6 sets using system resolver.

    Returns (ipv4_set, ipv6_set).
    """
    ipv4: Set[str] = set()
    ipv6: Set[str] = set()

    family_map = {
        "any": socket.AF_UNSPEC,
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }
    fam = family_map.get(family, socket.AF_UNSPEC)

    try:
        # getaddrinfo may return duplicates; filter below
        for res in socket.getaddrinfo(host, None, fam, socket.SOCK_STREAM):
            sockaddr = res[4]
            if not sockaddr:
                continue
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    ipv4.add(str(ip_obj))
                else:
                    ipv6.add(str(ip_obj))
            except Exception:
                # Skip non-IP results
                continue
    except socket.gaierror:
        # Hostname cannot be resolved
        pass
    except Exception:
        # Any other error (timeout, etc.)
        pass

    return ipv4, ipv6


# -----------------------------
# Scope checkers
# -----------------------------

def _any_ip_in_scope(ips: Iterable[str], networks: Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> Tuple[bool, List[str]]:
    matched_networks: List[str] = []
    if not ips:
        return False, matched_networks
    for ip_str in ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            continue
        for net in networks:
            # Only compare same IP version
            if (ip_obj.version == 4 and isinstance(net, ipaddress.IPv4Network)) or (
                ip_obj.version == 6 and isinstance(net, ipaddress.IPv6Network)
            ):
                if ip_obj in net:
                    matched_networks.append(str(net))
    return (len(matched_networks) > 0), matched_networks


# -----------------------------
# Main processing
# -----------------------------

def load_subdomains(path: str) -> List[str]:
    subs: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            raw = _strip_comments(raw)
            if not raw:
                continue
            host = _normalize_hostname(raw)
            if not host:
                continue
            subs.append(host)
    # Deduplicate while preserving order
    seen = set()
    out = []
    for h in subs:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def process_subdomain(host: str, networks: Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], family: str) -> dict:
    v4, v6 = resolve_ips(host, family=family)
    ips_all: List[str] = []
    if family in ("any", "ipv4"):
        ips_all.extend(sorted(v4))
    if family in ("any", "ipv6"):
        ips_all.extend(sorted(v6))

    in_scope, matched = _any_ip_in_scope(ips_all, networks)

    return {
        "host": host,
        "ipv4": sorted(v4),
        "ipv6": sorted(v6),
        "ips": ips_all,
        "in_scope": in_scope,
        "matched_networks": sorted(set(matched)),
        "resolved": len(ips_all) > 0,
    }


def write_list(path: Optional[str], items: Iterable[str]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8", newline="") as f:
        for it in items:
            f.write(f"{it}\n")


def write_csv(path: Optional[str], rows: Iterable[dict]) -> None:
    if not path:
        return
    fieldnames = [
        "host",
        "in_scope",
        "resolved",
        "ipv4",
        "ipv6",
        "ips",
        "matched_networks",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({
                "host": r["host"],
                "in_scope": str(r["in_scope"]).lower(),
                "resolved": str(r["resolved"]).lower(),
                "ipv4": ";".join(r["ipv4"]),
                "ipv6": ";".join(r["ipv6"]),
                "ips": ";".join(r["ips"]),
                "matched_networks": ";".join(r["matched_networks"]),
            })


def run(args: argparse.Namespace) -> int:
    # Global DNS timeout for socket operations
    if args.timeout is not None and args.timeout > 0:
        try:
            socket.setdefaulttimeout(float(args.timeout))
        except Exception:
            pass

    try:
        networks = load_scope_networks(args.cidrs)
    except Exception as e:
        print(f"[!] Failed to load scope from {args.cidrs}: {e}", file=sys.stderr)
        return 1

    if not networks:
        print("[!] No valid networks parsed from scope file.", file=sys.stderr)
        return 1

    try:
        subdomains = load_subdomains(args.subdomains)
    except Exception as e:
        print(f"[!] Failed to load subdomains from {args.subdomains}: {e}", file=sys.stderr)
        return 1

    if not subdomains:
        print("[!] No subdomains loaded.", file=sys.stderr)
        return 1

    t0 = time.time()

    results: List[dict] = []
    in_scope_hosts: List[str] = []
    out_scope_hosts: List[str] = []

    workers = max(1, int(args.workers))

    # Process with a ThreadPool for concurrency
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        fut_to_host = {
            ex.submit(process_subdomain, host, networks, args.family): host for host in subdomains
        }
        processed = 0
        for fut in cf.as_completed(fut_to_host):
            host = fut_to_host[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {
                    "host": host,
                    "ipv4": [],
                    "ipv6": [],
                    "ips": [],
                    "in_scope": False,
                    "matched_networks": [],
                    "resolved": False,
                    "error": str(e),
                }
            results.append(res)
            if res["in_scope"]:
                in_scope_hosts.append(host)
            else:
                out_scope_hosts.append(host)
            processed += 1
            if args.progress and processed % args.progress_every == 0:
                print(f"[*] Processed {processed}/{len(subdomains)} ...", file=sys.stderr)

    # Sort outputs for stability
    in_scope_hosts = sorted(set(in_scope_hosts))
    out_scope_hosts = sorted(set(out_scope_hosts))

    write_list(args.output_in_scope, in_scope_hosts)
    write_list(args.output_out_of_scope, out_scope_hosts)
    write_csv(args.output_csv, results)

    dt = time.time() - t0
    total_resolved = sum(1 for r in results if r["resolved"]) 
    total_in_scope = sum(1 for r in results if r["in_scope"]) 

    print(
        f"[+] Done in {dt:.2f}s | subdomains: {len(subdomains)} | resolved: {total_resolved} | in-scope: {total_in_scope}",
        file=sys.stderr,
    )

    # If user didn't specify any outputs, print in-scope hosts to stdout
    if not any([args.output_in_scope, args.output_out_of_scope, args.output_csv]):
        for host in in_scope_hosts:
            print(host)

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Filter subdomains to keep only those resolving to in-scope network(s).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--cidrs", required=True, help="Path to file containing in-scope networks (CIDR, IP, or IP range)")
    p.add_argument("--subdomains", required=True, help="Path to file containing subdomains (one per line)")

    p.add_argument("--family", choices=["any", "ipv4", "ipv6"], default="any", help="Address family to consider")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS resolution timeout (seconds)")
    p.add_argument("--workers", type=int, default=50, help="Number of concurrent resolver workers")

    p.add_argument("--output-in-scope", dest="output_in_scope", default=None, help="Write in-scope subdomains to this file")
    p.add_argument("--output-out-of-scope", dest="output_out_of_scope", default=None, help="Write out-of-scope subdomains to this file")
    p.add_argument("--output-csv", dest="output_csv", default=None, help="Write detailed mapping CSV (host, ips, in_scope, matched_networks)")

    p.add_argument("--progress", action="store_true", help="Print periodic progress to stderr")
    p.add_argument("--progress-every", type=int, default=250, help="Progress print frequency (every N hosts)")

    return p


if __name__ == "__main__":
    try:
        rc = run(build_arg_parser().parse_args())
    except KeyboardInterrupt:
        print("[!] Interrupted by user", file=sys.stderr)
        rc = 130
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        rc = 2
    sys.exit(rc)
