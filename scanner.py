import asyncio
import json
import os
import re
import time

from dotenv import load_dotenv
from db import insert_result, update_scan_status

load_dotenv()

WORDLIST = os.getenv("WORDLIST_PATH", "wordlists/common.txt")
TIMEOUT  = int(os.getenv("SCAN_TIMEOUT", "1800"))

TOOLS_INFO = {
    "whois": {
        "name": "WHOIS",
        "description": "Domain registration & ownership lookup",
        "depends": [],
        "order": 1,
    },
    "dig": {
        "name": "DNS Records",
        "description": "DNS enumeration (A, MX, NS, TXT, CNAME)",
        "depends": [],
        "order": 2,
    },
    "httpx": {
        "name": "HTTPX",
        "description": "Subdomain discovery & HTTP probing",
        "depends": [],
        "order": 3,
    },
    "wafw00f": {
        "name": "WAFw00f",
        "description": "Web Application Firewall detection",
        "depends": ["httpx"],
        "order": 4,
    },
    "whatweb": {
        "name": "WhatWeb",
        "description": "Web technology fingerprinting",
        "depends": ["httpx"],
        "order": 5,
    },
    "ffuf": {
        "name": "FFUF",
        "description": "Directory & file fuzzing",
        "depends": ["httpx"],
        "order": 6,
    },
    "nmap": {
        "name": "Nmap",
        "description": "Port scanning & service detection",
        "depends": [],
        "order": 7,
    },
}

DEFAULT_TOOLS = ["httpx", "ffuf", "whatweb", "wafw00f"]

_lock   = asyncio.Lock()
_queues: dict[str, list[asyncio.Queue]] = {}
_procs:  dict[str, asyncio.subprocess.Process] = {}


def get_tools_info() -> dict:
    return TOOLS_INFO


def resolve_tools(selected: list[str]) -> list[str]:
    resolved = set(selected)
    changed = True
    while changed:
        changed = False
        for tool in list(resolved):
            for dep in TOOLS_INFO.get(tool, {}).get("depends", []):
                if dep not in resolved:
                    resolved.add(dep)
                    changed = True
    return sorted(resolved, key=lambda t: TOOLS_INFO.get(t, {}).get("order", 99))


def validate_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain)) and len(domain) <= 253


async def _broadcast(scan_id: str, event: dict):
    for q in _queues.get(scan_id, []):
        await q.put(event)


def subscribe(scan_id: str) -> asyncio.Queue:
    q = asyncio.Queue()
    _queues.setdefault(scan_id, []).append(q)
    return q


def unsubscribe(scan_id: str, q: asyncio.Queue):
    if scan_id in _queues:
        _queues[scan_id] = [x for x in _queues[scan_id] if x is not q]
        if not _queues[scan_id]:
            del _queues[scan_id]


async def _run_tool(
    scan_id: str,
    tool: str,
    cmd: list[str],
    timeout: float,
    parser=None,
    broadcast: bool = True,
    emit_steps: bool = True,
) -> list[dict]:
    if broadcast and emit_steps:
        await _broadcast(scan_id, {"type": "step_start", "tool": tool})
        ev = await insert_result(scan_id, "system", f"Running {tool}...")
        await _broadcast(scan_id, {"type": "line", **ev})

    collected = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _procs[scan_id] = proc

        async def _read():
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                text = raw.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                line, data = parser(text) if parser else (text, {})
                collected.append({"line": line, "data": data, "raw": text})
                if broadcast:
                    ev = await insert_result(scan_id, tool, line, data)
                    await _broadcast(scan_id, {"type": "line", **ev})

        try:
            await asyncio.wait_for(_read(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            if broadcast:
                ev = await insert_result(
                    scan_id, "system", f"{tool} timed out after {int(timeout)}s"
                )
                await _broadcast(scan_id, {"type": "line", **ev})

        await proc.wait()

    except FileNotFoundError:
        if broadcast:
            ev = await insert_result(
                scan_id, "system", f"{tool} not found in PATH — skipping"
            )
            await _broadcast(scan_id, {"type": "line", **ev})
    finally:
        _procs.pop(scan_id, None)

    if broadcast and emit_steps:
        count = len(collected)
        await _broadcast(scan_id, {"type": "step_done", "tool": tool, "count": count})
        ev = await insert_result(
            scan_id, "system", f"{tool} finished — {count} results",
            {"summary": True, "count": count},
        )
        await _broadcast(scan_id, {"type": "line", **ev})

    return collected


async def _subfinder(scan_id: str, domain: str, timeout: float) -> list[str]:
    results = await _run_tool(
        scan_id, "subfinder",
        ["subfinder", "-d", domain, "-silent"],
        timeout=timeout,
        parser=_parse_subfinder,
        broadcast=False,
    )
    return [r["data"].get("subdomain", r["line"]) for r in results if r["line"]]


def _parse_whois(line: str) -> tuple[str, dict]:
    data = {}
    if ":" in line:
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if any(k in key for k in [
            "registrar", "creation", "expir", "name server",
            "registrant", "org", "country", "dnssec", "updated",
        ]):
            data = {"field": key, "value": val}
    return line, data


def _parse_dig(line: str) -> tuple[str, dict]:
    data = {}
    m = re.match(r"^(\S+)\s+(\d+)\s+IN\s+(\w+)\s+(.+)$", line)
    if m:
        data = {
            "name": m.group(1), "ttl": int(m.group(2)),
            "type": m.group(3), "value": m.group(4).strip(),
        }
    return line, data


def _parse_subfinder(line: str) -> tuple[str, dict]:
    s = line.strip()
    return s, {"subdomain": s}


def _parse_httpx_json(line: str) -> tuple[str, dict]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return line, {}

    url    = obj.get("url", "")
    status = obj.get("status_code") or obj.get("status-code", 0)
    title  = obj.get("title", "")
    tech   = obj.get("tech") or obj.get("technologies") or []
    server = obj.get("webserver") or obj.get("web-server", "")
    cl     = obj.get("content_length") or obj.get("content-length", 0)
    final  = obj.get("final_url", "")
    host   = obj.get("host", "")
    scheme = obj.get("scheme", "")
    port   = obj.get("port", "")

    tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
    parts = [url]
    if status:  parts.append(f"[{status}]")
    if title:   parts.append(f"[{title}]")
    if tech_str: parts.append(f"[{tech_str}]")
    if server:  parts.append(f"[{server}]")
    if cl:      parts.append(f"[{cl} bytes]")

    data = {
        "url": url,
        "status_code": int(status) if status else 0,
        "title": title,
        "tech": tech if isinstance(tech, list) else [],
        "server": server,
        "content_length": int(cl) if cl else 0,
        "host": host,
        "scheme": scheme,
        "port": port,
    }
    if final and final != url:
        data["redirect_to"] = final

    return "  ".join(parts), data


def _parse_wafw00f(line: str) -> tuple[str, dict]:
    m = re.search(r"(https?://\S+)\s+is behind\s+(.+?)(?:\s*\((.+?)\))?$", line)
    if m:
        return line, {
            "url": m.group(1),
            "waf_detected": True,
            "waf_name": m.group(2).strip(),
            "waf_vendor": (m.group(3) or "").strip(),
        }
    m2 = re.search(r"(https?://\S+)\s+.*[Nn]o WAF", line)
    if m2:
        return line, {
            "url": m2.group(1), "waf_detected": False,
            "waf_name": "", "waf_vendor": "",
        }
    return line, {}


def _parse_whatweb(line: str) -> tuple[str, dict]:
    m = re.match(r"(https?://\S+)\s+\[(\d+)\s*([^\]]*)\]\s*(.*)", line)
    if m:
        techs = re.findall(r"([A-Za-z0-9_\-]+(?:\[.*?\])?)", m.group(4))
        return line, {
            "url": m.group(1),
            "status_code": int(m.group(2)),
            "technologies": techs,
        }
    return line, {}


def _parse_ffuf(line: str) -> tuple[str, dict]:
    m = re.match(
        r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)",
        line,
    )
    if m:
        return line, {
            "path": m.group(1),
            "status_code": int(m.group(2)),
            "size": int(m.group(3)),
            "words": int(m.group(4)),
            "lines": int(m.group(5)),
        }
    if line.startswith(("http://", "https://")):
        return line, {"url": line, "path": line}
    return line, {}


def _parse_nmap(line: str) -> tuple[str, dict]:
    m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)", line)
    if m:
        return line, {
            "port": int(m.group(1)),
            "protocol": m.group(2),
            "state": m.group(3),
            "service": m.group(4),
            "version": m.group(5).strip(),
        }
    if "scan report for" in line:
        m2 = re.search(r"for\s+(\S+)\s*(?:\(([^)]+)\))?", line)
        if m2:
            return line, {"host": m2.group(1), "ip": (m2.group(2) or "").strip()}
    return line, {}


async def run_scan(
    scan_id: str, domain: str, selected_tools: list[str], wordlist: str = "default"
):
    async with _lock:
        await update_scan_status(scan_id, "running")
        await _broadcast(scan_id, {"type": "status", "status": "running"})

        plan = resolve_tools(selected_tools)
        await _broadcast(scan_id, {
            "type": "plan",
            "tools": plan,
            "tools_info": {t: TOOLS_INFO[t] for t in plan},
        })

        t0 = time.time()
        def time_left() -> float:
            return max(60.0, TIMEOUT - (time.time() - t0))

        wl  = WORDLIST if wordlist == "default" else wordlist
        ctx = {"domain": domain, "subdomains": [], "live_hosts": [], "sub_file": None}

        try:
            for tool in plan:

                if tool == "httpx":
                    await _broadcast(scan_id, {"type": "step_start", "tool": "httpx"})
                    ev = await insert_result(scan_id, "system", "Enumerating subdomains...")
                    await _broadcast(scan_id, {"type": "line", **ev})

                    subs = await _subfinder(scan_id, domain, timeout=time_left())
                    ctx["subdomains"] = subs

                    ev = await insert_result(
                        scan_id, "system",
                        f"Discovered {len(subs)} subdomains — probing with httpx...",
                        {"summary": True, "count": len(subs)},
                    )
                    await _broadcast(scan_id, {"type": "line", **ev})

                    if not subs:
                        ev = await insert_result(
                            scan_id, "system", "No subdomains found — skipping HTTP probing"
                        )
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_done", "tool": "httpx", "count": 0})
                        continue

                    sub_file = os.path.join(
                        os.environ.get("TEMP", "/tmp"), f"argus_{scan_id}_subs.txt"
                    )
                    with open(sub_file, "w") as f:
                        f.write("\n".join(subs))
                    ctx["sub_file"] = sub_file

                    probe_results = await _run_tool(
                        scan_id, "httpx",
                        ["httpx", "-l", sub_file, "-json", "-tech-detect", "-follow-redirects"],
                        timeout=time_left(), parser=_parse_httpx_json,
                        broadcast=True, emit_steps=False,
                    )

                    live = [r["data"]["url"].rstrip("/") for r in probe_results if r["data"].get("url")]
                    ctx["live_hosts"] = live

                    ev = await insert_result(
                        scan_id, "system",
                        f"httpx finished — {len(subs)} subdomains, {len(live)} live hosts",
                        {"summary": True, "subdomains": len(subs), "live_hosts": len(live)},
                    )
                    await _broadcast(scan_id, {"type": "line", **ev})
                    await _broadcast(scan_id, {"type": "step_done", "tool": "httpx", "count": len(live)})

                elif tool == "ffuf":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        ev = await insert_result(scan_id, "system", "ffuf skipped — no live hosts")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "ffuf"})
                        continue

                    await _broadcast(scan_id, {"type": "step_start", "tool": "ffuf"})
                    ev = await insert_result(
                        scan_id, "system",
                        f"Fuzzing {min(len(hosts), 20)} hosts with {os.path.basename(wl)}..."
                    )
                    await _broadcast(scan_id, {"type": "line", **ev})

                    ffuf_results = []
                    for host in hosts[:20]:
                        results = await _run_tool(
                            scan_id, "ffuf",
                            ["ffuf", "-u", f"{host}/FUZZ", "-w", wl, "-mc", "all", "-fc", "404", "-se"],
                            timeout=time_left(), parser=_parse_ffuf, broadcast=True,
                        )
                        for r in results:
                            if r["data"].get("status_code"):
                                r["data"]["host"] = host
                        ffuf_results.extend(results)

                    ev = await insert_result(
                        scan_id, "system",
                        f"ffuf finished — {len(ffuf_results)} results across {min(len(hosts), 20)} hosts",
                        {"summary": True, "count": len(ffuf_results)},
                    )
                    await _broadcast(scan_id, {"type": "line", **ev})
                    await _broadcast(scan_id, {"type": "step_done", "tool": "ffuf", "count": len(ffuf_results)})

                elif tool == "wafw00f":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        ev = await insert_result(scan_id, "system", "wafw00f skipped — no live hosts")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "wafw00f"})
                        continue
                    await _run_tool(
                        scan_id, "wafw00f", ["wafw00f"] + hosts[:30],
                        timeout=time_left(), parser=_parse_wafw00f,
                    )

                elif tool == "whatweb":
                    hosts = ctx.get("live_hosts", [])
                    if not hosts:
                        ev = await insert_result(scan_id, "system", "whatweb skipped — no live hosts")
                        await _broadcast(scan_id, {"type": "line", **ev})
                        await _broadcast(scan_id, {"type": "step_skip", "tool": "whatweb"})
                        continue
                    await _run_tool(
                        scan_id, "whatweb",
                        ["whatweb", "--color=never", "-q"] + hosts[:30],
                        timeout=time_left(), parser=_parse_whatweb,
                    )

                elif tool == "whois":
                    await _run_tool(
                        scan_id, "whois", ["whois", domain],
                        timeout=time_left(), parser=_parse_whois,
                    )

                elif tool == "dig":
                    await _run_tool(
                        scan_id, "dig",
                        ["dig", domain, "ANY", "+noall", "+answer"],
                        timeout=time_left(), parser=_parse_dig,
                    )

                elif tool == "nmap":
                    await _run_tool(
                        scan_id, "nmap",
                        ["nmap", "-sV", "--top-ports", "100", "-T4", "--open", domain],
                        timeout=time_left(), parser=_parse_nmap,
                    )

            sub_file = ctx.get("sub_file")
            if sub_file:
                try:
                    os.remove(sub_file)
                except OSError:
                    pass

            await update_scan_status(scan_id, "completed")
            await _broadcast(scan_id, {"type": "status", "status": "completed"})

        except asyncio.CancelledError:
            await update_scan_status(scan_id, "error")
            await _broadcast(scan_id, {"type": "status", "status": "error"})
        except Exception as exc:
            ev = await insert_result(scan_id, "system", f"Error: {exc}")
            await _broadcast(scan_id, {"type": "line", **ev})
            await update_scan_status(scan_id, "error")
            await _broadcast(scan_id, {"type": "status", "status": "error"})
        finally:
            await _broadcast(scan_id, {"type": "done"})
