"""
PCAP analyzer — scapy-based network packet capture analysis.

Streams a PCAP/PCAPNG file and extracts structured network facts:
  conversations, DNS (with resolved IPs), TLS SNI, plaintext HTTP,
  beaconing indicators, external IPs, and a packet summary.

Designed for Triage sandbox PCAP downloads (dump.pcapng).
"""
from __future__ import annotations

import ipaddress
import json
import statistics
from collections import defaultdict
from typing import Any

_CAP_CONVERSATIONS = 50
_CAP_DNS           = 200
_CAP_TLS           = 100
_CAP_HTTP          = 100
_CAP_EXT_IPS       = 200


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_private(ip_str: str) -> bool:
    """Return True for RFC1918, loopback, multicast, link-local, and broadcast."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (addr.is_private or addr.is_loopback or addr.is_multicast
                or addr.is_link_local or addr.is_unspecified
                or str(addr) == "255.255.255.255")
    except ValueError:
        return True


def _extract_sni(data: bytes) -> str | None:
    """
    Extract the SNI hostname from a raw TLS ClientHello TCP payload.

    TLS record structure (RFC 5246 / 8446):
      5 bytes  : TLS record header (content_type=0x16, version, length)
      4 bytes  : Handshake header (type=0x01, length-3)
      2 bytes  : ClientHello version
      32 bytes : random
      variable : session_id, cipher_suites, compression, extensions …
    """
    try:
        # Must start with TLS handshake (0x16) + any TLS version (0x03xx)
        if len(data) < 9 or data[0] != 0x16 or data[1] != 0x03:
            return None
        if data[5] != 0x01:   # must be ClientHello
            return None

        pos = 9               # past TLS record header (5) + handshake header (4)
        pos += 2 + 32         # client version + random

        if pos >= len(data):
            return None
        sid_len = data[pos];   pos += 1 + sid_len

        if pos + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[pos:pos + 2], "big");  pos += 2 + cs_len

        if pos >= len(data):
            return None
        cm_len = data[pos];    pos += 1 + cm_len

        if pos + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[pos:pos + 2], "big");  pos += 2
        ext_end   = min(pos + ext_total, len(data))

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len  = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0 and pos + 5 <= ext_end:   # SNI extension
                # SNI list: list_len(2) + name_type(1) + name_len(2) + name
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                if pos + 5 + name_len <= ext_end:
                    return data[pos + 5: pos + 5 + name_len].decode(
                        "ascii", errors="replace"
                    )
            pos += ext_len
    except Exception:
        pass
    return None


# ── main entry point ──────────────────────────────────────────────────────────

def analyze_pcap(pcap_path: str) -> dict[str, Any]:
    """
    Stream *pcap_path* (pcap or pcapng) with scapy's PcapReader and return
    a structured dict.

    Keys
    ----
    conversations : top-50 (src,dst,port,proto) flows sorted by bytes desc
    dns           : query → [resolved IPs] from DNS A/AAAA *response* records
    tls           : TLS ClientHello SNI entries (sni, dst_ip, dst_port)
    http          : plaintext HTTP requests (method, host, uri, dst_ip)
    beaconing     : repeated SYN clusters with mean/stdev interval
    external_ips  : unique non-private destination IPs seen in the capture
    summary       : packet/byte/duration totals and section counts

    On hard failure returns {"_pcap_error": "<reason>"}.
    """
    try:
        # Suppress scapy's verbose TLS-key-log warning (cosmetic only)
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, Raw
    except ImportError as exc:
        return {"_pcap_error": f"scapy not installed: {exc}"}

    # ── accumulators ─────────────────────────────────────────────────────────
    conv:      dict[tuple, dict]        = defaultdict(
        lambda: {"pkts": 0, "bytes": 0, "first_ts": None, "last_ts": None}
    )
    dns_map:   dict[str, dict]          = defaultdict(
        lambda: {"qtypes": [], "responses": []}
    )
    tls_snis:  list[dict]               = []
    tls_seen:  set[tuple]               = set()
    http_list: list[dict]               = []
    http_seen: set[str]                 = set()
    ext_ips:   set[str]                 = set()
    syn_times: dict[tuple, list[float]] = defaultdict(list)

    total_pkts  = 0
    total_bytes = 0
    first_ts:  float | None = None
    last_ts:   float | None = None

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                total_pkts  += 1
                pkt_len      = len(pkt)
                total_bytes += pkt_len
                ts           = float(pkt.time)

                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                if IP not in pkt and IPv6 not in pkt:
                    continue

                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                src      = str(ip_layer.src)
                dst      = str(ip_layer.dst)

                proto = "other"
                dport = 0
                if TCP in pkt:
                    proto = "tcp"
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "udp"
                    dport = pkt[UDP].dport

                # ── conversation tracking ─────────────────────────────────
                ck = (src, dst, dport, proto)
                c  = conv[ck]
                c["pkts"]  += 1
                c["bytes"] += pkt_len
                if c["first_ts"] is None:
                    c["first_ts"] = ts
                c["last_ts"] = ts

                # ── external IP collection ────────────────────────────────
                if not _is_private(dst):
                    ext_ips.add(dst)

                # ── beaconing: SYN packets to external destinations ───────
                if (TCP in pkt
                        and (pkt[TCP].flags & 0x02)
                        and not _is_private(dst)):
                    syn_times[(dst, dport)].append(ts)

                # ── DNS: queries AND responses ────────────────────────────
                # Track queries (qr==0) so domains appear even when the
                # response is missing (NXDOMAIN, capture truncated, C2 down).
                # Track responses (qr==1) to add resolved IPs and CNAMEs.
                if DNS in pkt:
                    try:
                        d = pkt[DNS]
                        if d.qd:
                            qname = d.qd.qname
                            if isinstance(qname, bytes):
                                qname = qname.decode(errors="replace").rstrip(".")
                            # Ensure domain is recorded regardless of qr flag
                            _ = dns_map[qname]

                            if d.qr == 1:                   # response
                                rec = d.an
                                while rec and hasattr(rec, "rrname"):
                                    if rec.type == 1:        # A record
                                        ip_str = str(rec.rdata)
                                        if ip_str not in dns_map[qname]["responses"]:
                                            dns_map[qname]["responses"].append(ip_str)
                                        if "A" not in dns_map[qname]["qtypes"]:
                                            dns_map[qname]["qtypes"].append("A")
                                        if not _is_private(ip_str):
                                            ext_ips.add(ip_str)
                                    elif rec.type == 28:     # AAAA record
                                        ip_str = str(rec.rdata)
                                        if ip_str not in dns_map[qname]["responses"]:
                                            dns_map[qname]["responses"].append(ip_str)
                                        if "AAAA" not in dns_map[qname]["qtypes"]:
                                            dns_map[qname]["qtypes"].append("AAAA")
                                        if not _is_private(ip_str):
                                            ext_ips.add(ip_str)
                                    elif rec.type == 5:      # CNAME record
                                        cval = rec.rdata
                                        if isinstance(cval, bytes):
                                            cval = cval.decode(errors="replace").rstrip(".")
                                        cval = str(cval).rstrip(".")
                                        entry = f"CNAME:{cval}"
                                        if entry not in dns_map[qname]["responses"]:
                                            dns_map[qname]["responses"].append(entry)
                                        if "CNAME" not in dns_map[qname]["qtypes"]:
                                            dns_map[qname]["qtypes"].append("CNAME")
                                    nxt = rec.payload
                                    if not hasattr(nxt, "rrname"):
                                        break
                                    rec = nxt
                    except Exception:
                        pass

                # ── TLS SNI (raw byte parsing of ClientHello) ─────────────
                # No private-IP filter: some C2 families tunnel TLS through
                # an internal proxy or use a private-IP C2 in lab captures.
                if TCP in pkt and Raw in pkt:
                    try:
                        sni = _extract_sni(bytes(pkt[Raw].load))
                        if sni:
                            tk = (sni, dst, dport)
                            if tk not in tls_seen and len(tls_snis) < _CAP_TLS:
                                tls_seen.add(tk)
                                tls_snis.append({
                                    "sni":      sni,
                                    "dst_ip":   dst,
                                    "dst_port": dport,
                                })
                    except Exception:
                        pass

                # ── plaintext HTTP requests ───────────────────────────────
                if TCP in pkt and Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load)
                        if payload[:4] in (b"GET ", b"POST", b"PUT ",
                                           b"HEAD", b"DELE", b"OPTI", b"PATC"):
                            lines    = payload.split(b"\r\n")
                            req_line = lines[0].decode(errors="replace")
                            parts    = req_line.split(" ", 2)
                            method   = parts[0] if parts else ""
                            uri      = parts[1][:300] if len(parts) > 1 else ""
                            host     = ""
                            for ln in lines[1:]:
                                if ln.lower().startswith(b"host:"):
                                    host = ln[5:].strip().decode(errors="replace")
                                    break
                            ek = f"{method}:{host}{uri}"
                            if ek not in http_seen and len(http_list) < _CAP_HTTP:
                                http_seen.add(ek)
                                http_list.append({
                                    "method":   method,
                                    "host":     host,
                                    "uri":      uri,
                                    "dst_ip":   dst,
                                    "dst_port": dport,
                                })
                    except Exception:
                        pass

    except Exception as exc:
        return {"_pcap_error": str(exc)}

    # ── assemble results ──────────────────────────────────────────────────────

    # Conversations — sort by bytes desc, cap
    conversations = [
        {
            "src_ip":    src,
            "dst_ip":    dst,
            "dst_port":  dport,
            "protocol":  proto,
            "packets":   c["pkts"],
            "bytes":     c["bytes"],
            "first_seen": round(c["first_ts"], 3) if c["first_ts"] else None,
            "last_seen":  round(c["last_ts"],  3) if c["last_ts"]  else None,
        }
        for (src, dst, dport, proto), c in sorted(
            conv.items(), key=lambda x: x[1]["bytes"], reverse=True
        )[:_CAP_CONVERSATIONS]
    ]

    # DNS — sort by query name, cap
    dns_out = [
        {
            "query":     qname,
            "qtypes":    info["qtypes"],
            "responses": info["responses"],
        }
        for qname, info in sorted(dns_map.items())
    ][:_CAP_DNS]

    # Beaconing — clusters with >= 3 SYNs, sorted by connection count desc
    beaconing = []
    for (dst_ip, dport), times in sorted(
            syn_times.items(), key=lambda x: len(x[1]), reverse=True):
        if len(times) < 3:
            continue
        ts_sorted  = sorted(times)
        intervals  = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
        mean_iv    = statistics.mean(intervals)
        stdev_iv   = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv         = stdev_iv / mean_iv if mean_iv > 0 else 0.0
        beaconing.append({
            "dst_ip":          dst_ip,
            "dst_port":        dport,
            "connections":     len(times),
            "mean_interval_s": round(mean_iv, 2),
            "stdev_s":         round(stdev_iv, 2),
            "regularity_cv":   round(cv, 3),
            "likely_beacon":   cv < 0.3 and len(times) >= 5,
        })

    duration = round(last_ts - first_ts, 3) if (last_ts and first_ts) else 0.0
    summary  = {
        "total_packets":      total_pkts,
        "total_bytes":        total_bytes,
        "duration_s":         duration,
        "external_ip_count":  len(ext_ips),
        "conversation_count": len(conv),
        "dns_queries":        len(dns_map),
        "tls_sessions":       len(tls_snis),
        "http_requests":      len(http_list),
    }

    return {
        "conversations": conversations,
        "dns":           dns_out,
        "tls":           tls_snis,
        "http":          http_list,
        "beaconing":     beaconing,
        "external_ips":  sorted(ext_ips)[:_CAP_EXT_IPS],
        "summary":       summary,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="PCAP/PCAPNG network analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m backend.app.services.pcap_analyzer \\\n"
            "      --pcap /tmp/triage_260620-s5c9jag12y.pcapng\n"
        ),
    )
    parser.add_argument("--pcap", required=True, metavar="PATH",
                        help="Path to PCAP or PCAPNG file to analyze.")
    args = parser.parse_args()

    result = analyze_pcap(args.pcap)

    if result.get("_pcap_error"):
        print(f"[!] PCAP error: {result['_pcap_error']}", file=sys.stderr)
        sys.exit(1)

    # Pretty summary to stderr, full JSON to stdout
    s = result["summary"]
    print(f"[+] {s['total_packets']:,} packets  "
          f"{s['total_bytes']:,} bytes  "
          f"{s['duration_s']}s duration",
          file=sys.stderr)
    print(f"    {s['dns_queries']} DNS queries  "
          f"{s['external_ip_count']} external IPs  "
          f"{s['tls_sessions']} TLS SNIs  "
          f"{s['http_requests']} HTTP reqs",
          file=sys.stderr)

    print(json.dumps(result, indent=2, default=str))
