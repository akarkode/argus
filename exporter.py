import csv
import io
import json
import time
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

STATUS_COLORS = {
    "2xx": colors.HexColor("#22c55e"),
    "3xx": colors.HexColor("#60a5fa"),
    "4xx": colors.HexColor("#fb923c"),
    "5xx": colors.HexColor("#f87171"),
}


def _status_color(code: int) -> colors.Color:
    if 200 <= code < 300:
        return STATUS_COLORS["2xx"]
    if 300 <= code < 400:
        return STATUS_COLORS["3xx"]
    if 400 <= code < 500:
        return STATUS_COLORS["4xx"]
    if 500 <= code < 600:
        return STATUS_COLORS["5xx"]
    return colors.HexColor("#6b7280")


def _status_bg(code: int) -> colors.Color:
    c = _status_color(code)
    # Light tinted background
    return colors.Color(c.red, c.green, c.blue, alpha=0.08)


# ---------------------------------------------------------------------------
# Statistics builder
# ---------------------------------------------------------------------------

def _build_stats(results: list[dict]) -> dict:
    stats = {
        "total_results": 0,
        "by_tool": {},
        "status_codes": {},
        "technologies": set(),
        "waf_detected": [],
        "open_ports": [],
        "subdomains": 0,
        "live_hosts": 0,
    }

    for r in results:
        tool = r["tool"]
        if tool == "system":
            continue
        stats["total_results"] += 1
        stats["by_tool"][tool] = stats["by_tool"].get(tool, 0) + 1

        data = r.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                data = {}

        sc = data.get("status_code")
        if sc:
            stats["status_codes"][sc] = stats["status_codes"].get(sc, 0) + 1

        if tool == "subfinder":
            stats["subdomains"] += 1

        if tool == "httpx" and data.get("url"):
            stats["live_hosts"] += 1
            for t in data.get("tech", []):
                stats["technologies"].add(t)

        if data.get("waf_detected"):
            stats["waf_detected"].append(data.get("waf_name", "Unknown"))

        if data.get("port") and data.get("state") == "open":
            stats["open_ports"].append(f"{data['port']}/{data.get('protocol', 'tcp')} ({data.get('service', '')})")

    stats["technologies"] = sorted(stats["technologies"])
    return stats


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def export_csv(scan: dict, results: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "tool", "timestamp", "output",
        "url", "status_code", "title", "server", "technologies",
        "content_length", "path", "size", "words",
        "waf_detected", "waf_name",
        "port", "protocol", "service", "version",
        "dns_type", "dns_value",
    ])

    for r in results:
        if r["tool"] == "system":
            continue

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        data = r.get("data", {})
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                data = {}

        writer.writerow([
            r["tool"],
            ts,
            r["line"],
            data.get("url", ""),
            data.get("status_code", ""),
            data.get("title", ""),
            data.get("server", ""),
            "; ".join(data.get("tech", data.get("technologies", []))),
            data.get("content_length", ""),
            data.get("path", ""),
            data.get("size", ""),
            data.get("words", ""),
            data.get("waf_detected", ""),
            data.get("waf_name", ""),
            data.get("port", ""),
            data.get("protocol", ""),
            data.get("service", ""),
            data.get("version", ""),
            data.get("type", ""),
            data.get("value", ""),
        ])

    return output.getvalue()


# ---------------------------------------------------------------------------
# PDF Export
# ---------------------------------------------------------------------------

def export_pdf(scan: dict, results: list[dict]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
        leftMargin=18 * mm, rightMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    W = A4[0] - 36 * mm  # usable width

    # Custom styles
    s_title = ParagraphStyle("STitle", parent=styles["Title"], fontSize=24,
                             spaceAfter=4, textColor=colors.HexColor("#6366f1"))
    s_subtitle = ParagraphStyle("SSub", parent=styles["Normal"], fontSize=10,
                                textColor=colors.HexColor("#6b7280"), spaceAfter=16)
    s_h2 = ParagraphStyle("SH2", parent=styles["Heading2"], fontSize=14,
                           spaceBefore=14, spaceAfter=8,
                           textColor=colors.HexColor("#1a1a2e"))
    s_h3 = ParagraphStyle("SH3", parent=styles["Heading3"], fontSize=11,
                           spaceBefore=10, spaceAfter=6,
                           textColor=colors.HexColor("#374151"))
    s_body = ParagraphStyle("SBody", parent=styles["Normal"], fontSize=9,
                             leading=13, textColor=colors.HexColor("#333333"))
    s_small = ParagraphStyle("SSmall", parent=styles["Normal"], fontSize=8,
                              leading=11, textColor=colors.HexColor("#6b7280"))

    elements = []
    stats = _build_stats(results)

    # ---- COVER ----
    elements.append(Spacer(1, 30 * mm))
    elements.append(Paragraph("SARA", s_title))
    elements.append(Paragraph("Simple Automated Recon App — Scan Report", s_subtitle))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#6366f1")))
    elements.append(Spacer(1, 10 * mm))

    created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan["created_at"]))
    finished = ""
    duration = ""
    if scan.get("finished_at"):
        finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan["finished_at"]))
        dur_s = int(scan["finished_at"] - scan["created_at"])
        duration = f"{dur_s // 60}m {dur_s % 60}s"

    tools_used = scan.get("tools", [])
    if isinstance(tools_used, str):
        try:
            tools_used = json.loads(tools_used)
        except (json.JSONDecodeError, TypeError):
            tools_used = []

    meta_data = [
        ["Target Domain", scan["domain"]],
        ["Scan ID", scan["id"]],
        ["Status", scan["status"].upper()],
        ["Tools Used", ", ".join(tools_used) if tools_used else "All"],
        ["Started", created],
        ["Finished", finished or "In progress"],
        ["Duration", duration or "N/A"],
    ]
    mt = Table(meta_data, colWidths=[90, W - 90])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(mt)

    # ---- EXECUTIVE SUMMARY ----
    elements.append(Spacer(1, 10 * mm))
    elements.append(Paragraph("Executive Summary", s_h2))

    summary_data = [
        ["Metric", "Count"],
        ["Total Results", str(stats["total_results"])],
        ["Subdomains Discovered", str(stats["subdomains"])],
        ["Live Hosts", str(stats["live_hosts"])],
        ["Open Ports", str(len(stats["open_ports"]))],
        ["Technologies Detected", str(len(stats["technologies"]))],
        ["WAF Detections", str(len(stats["waf_detected"]))],
    ]
    st = Table(summary_data, colWidths=[W * 0.6, W * 0.4])
    st.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f8fc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(st)

    # Status code breakdown
    if stats["status_codes"]:
        elements.append(Spacer(1, 6 * mm))
        elements.append(Paragraph("HTTP Status Code Distribution", s_h3))
        sc_data = [["Status Code", "Count", "Category"]]
        for code in sorted(stats["status_codes"].keys()):
            cat = "Success" if 200 <= code < 300 else \
                  "Redirect" if 300 <= code < 400 else \
                  "Client Error" if 400 <= code < 500 else \
                  "Server Error" if 500 <= code < 600 else "Other"
            sc_data.append([str(code), str(stats["status_codes"][code]), cat])
        sct = Table(sc_data, colWidths=[W * 0.3, W * 0.3, W * 0.4])
        style_cmds = [
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]
        # Color-code rows by status
        for i, code in enumerate(sorted(stats["status_codes"].keys()), 1):
            bg = _status_bg(code)
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
        sct.setStyle(TableStyle(style_cmds))
        elements.append(sct)

    # Technologies
    if stats["technologies"]:
        elements.append(Spacer(1, 6 * mm))
        elements.append(Paragraph(f"Technologies Detected ({len(stats['technologies'])})", s_h3))
        elements.append(Paragraph(", ".join(stats["technologies"]), s_body))

    # WAF
    if stats["waf_detected"]:
        elements.append(Spacer(1, 4 * mm))
        elements.append(Paragraph("WAF Detections", s_h3))
        elements.append(Paragraph(", ".join(set(stats["waf_detected"])), s_body))

    # Open ports
    if stats["open_ports"]:
        elements.append(Spacer(1, 4 * mm))
        elements.append(Paragraph("Open Ports", s_h3))
        elements.append(Paragraph(", ".join(stats["open_ports"][:50]), s_body))

    # ---- PER-TOOL SECTIONS ----
    elements.append(PageBreak())

    tool_order = ["whois", "dig", "subfinder", "httpx", "wafw00f", "whatweb", "ffuf", "nmap"]
    tool_labels = {
        "whois": "WHOIS Lookup", "dig": "DNS Records", "subfinder": "Subdomain Enumeration",
        "httpx": "HTTP Probing", "wafw00f": "WAF Detection", "whatweb": "Technology Fingerprinting",
        "ffuf": "Directory Fuzzing", "nmap": "Port Scanning",
    }

    grouped = {}
    for r in results:
        if r["tool"] != "system":
            grouped.setdefault(r["tool"], []).append(r)

    for tool in tool_order:
        if tool not in grouped:
            continue
        tool_results = grouped[tool]
        label = tool_labels.get(tool, tool.upper())
        elements.append(Paragraph(f"{label} ({len(tool_results)} results)", s_h2))

        # Build tool-specific tables
        if tool == "httpx":
            _add_httpx_table(elements, tool_results, W, s_small)
        elif tool == "ffuf":
            _add_ffuf_table(elements, tool_results, W, s_small)
        elif tool == "nmap":
            _add_nmap_table(elements, tool_results, W, s_small)
        elif tool == "subfinder":
            _add_simple_table(elements, tool_results, W, "Subdomain")
        else:
            _add_raw_table(elements, tool_results, W)

        elements.append(Spacer(1, 4 * mm))

    # Footer
    elements.append(Spacer(1, 10 * mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb")))
    elements.append(Spacer(1, 2 * mm))
    elements.append(Paragraph(
        f"Generated by SARA v1.0 on {time.strftime('%Y-%m-%d %H:%M:%S')} — "
        "For authorized security testing only.",
        s_small,
    ))

    doc.build(elements)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# PDF table builders
# ---------------------------------------------------------------------------

def _parse_data(r: dict) -> dict:
    data = r.get("data", {})
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            data = {}
    return data


def _add_httpx_table(elements, results, W, style):
    header = ["URL", "Status", "Title", "Server", "Tech"]
    rows = [header]
    status_rows = {}
    for i, r in enumerate(results, 1):
        d = _parse_data(r)
        url = d.get("url", r["line"])[:60]
        sc = d.get("status_code", "")
        title = d.get("title", "")[:30]
        server = d.get("server", "")[:20]
        tech = ", ".join(d.get("tech", []))[:30]
        rows.append([url, str(sc), title, server, tech])
        if sc:
            status_rows[i] = int(sc)

    t = Table(rows, colWidths=[W * 0.30, W * 0.10, W * 0.22, W * 0.16, W * 0.22])
    style_cmds = _base_table_style()
    for row_idx, code in status_rows.items():
        style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), _status_color(code)))
        style_cmds.append(("FONTNAME", (1, row_idx), (1, row_idx), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    elements.append(t)


def _add_ffuf_table(elements, results, W, style):
    header = ["Path / URL", "Status", "Size", "Words"]
    rows = [header]
    status_rows = {}
    for i, r in enumerate(results, 1):
        d = _parse_data(r)
        path = d.get("path", r["line"])[:70]
        sc = d.get("status_code", "")
        size = d.get("size", "")
        words = d.get("words", "")
        rows.append([path, str(sc), str(size), str(words)])
        if sc:
            status_rows[i] = int(sc)

    t = Table(rows, colWidths=[W * 0.50, W * 0.15, W * 0.17, W * 0.18])
    style_cmds = _base_table_style()
    for row_idx, code in status_rows.items():
        style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), _status_color(code)))
        style_cmds.append(("FONTNAME", (1, row_idx), (1, row_idx), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    elements.append(t)


def _add_nmap_table(elements, results, W, style):
    header = ["Port", "Protocol", "State", "Service", "Version"]
    rows = [header]
    for r in results:
        d = _parse_data(r)
        if d.get("port"):
            rows.append([
                str(d.get("port", "")), d.get("protocol", ""),
                d.get("state", ""), d.get("service", ""),
                d.get("version", "")[:40],
            ])

    if len(rows) > 1:
        t = Table(rows, colWidths=[W * 0.12, W * 0.13, W * 0.13, W * 0.22, W * 0.40])
        t.setStyle(TableStyle(_base_table_style()))
        elements.append(t)
    else:
        _add_raw_table(elements, results, W)


def _add_simple_table(elements, results, W, col_name):
    header = ["#", col_name, "Time"]
    rows = [header]
    for i, r in enumerate(results, 1):
        ts = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        rows.append([str(i), r["line"][:80], ts])

    t = Table(rows, colWidths=[W * 0.08, W * 0.72, W * 0.20])
    t.setStyle(TableStyle(_base_table_style()))
    elements.append(t)


def _add_raw_table(elements, results, W):
    header = ["#", "Output", "Time"]
    rows = [header]
    for i, r in enumerate(results, 1):
        ts = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        rows.append([str(i), r["line"][:100], ts])

    t = Table(rows, colWidths=[W * 0.06, W * 0.76, W * 0.18])
    t.setStyle(TableStyle(_base_table_style()))
    elements.append(t)


def _base_table_style() -> list:
    return [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e8")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
