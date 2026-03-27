import csv
import io
import json
import time

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)
from reportlab.pdfgen import canvas as pdfcanvas



C_NAVY      = colors.HexColor("#0f1623")
C_INDIGO    = colors.HexColor("#3b5bdb")
C_INDIGO_LO = colors.HexColor("#eef2ff")
C_SLATE     = colors.HexColor("#334155")
C_MUTED     = colors.HexColor("#64748b")
C_BORDER    = colors.HexColor("#e2e8f0")
C_ROW_ALT   = colors.HexColor("#f8fafc")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#0f172a")

C_GREEN     = colors.HexColor("#16a34a")
C_GREEN_LO  = colors.HexColor("#f0fdf4")
C_BLUE      = colors.HexColor("#2563eb")
C_BLUE_LO   = colors.HexColor("#eff6ff")
C_AMBER     = colors.HexColor("#d97706")
C_AMBER_LO  = colors.HexColor("#fffbeb")
C_RED       = colors.HexColor("#dc2626")
C_RED_LO    = colors.HexColor("#fef2f2")

TOOL_COLORS = {
    "httpx":   colors.HexColor("#059669"),
    "nmap":    colors.HexColor("#dc2626"),
    "dig":     colors.HexColor("#0891b2"),
    "whois":   colors.HexColor("#0891b2"),
    "wafw00f": colors.HexColor("#d97706"),
    "whatweb": colors.HexColor("#7c3aed"),
    "ffuf":    colors.HexColor("#b45309"),
}

PAGE_W, PAGE_H = A4
MARGIN_L = 18 * mm
MARGIN_R = 18 * mm
MARGIN_T = 20 * mm
MARGIN_B = 18 * mm
BODY_W   = PAGE_W - MARGIN_L - MARGIN_R



def _styles():
    mono = "Courier"
    sans = "Helvetica"

    return {
        "cover_title": ParagraphStyle("ct", fontName=sans+"-Bold", fontSize=32,
                                      textColor=C_WHITE, leading=36, spaceAfter=4),
        "cover_sub":   ParagraphStyle("cs", fontName=sans, fontSize=11,
                                      textColor=colors.HexColor("#a5b4fc"), leading=15),
        "cover_meta":  ParagraphStyle("cm", fontName=sans, fontSize=10,
                                      textColor=colors.HexColor("#cbd5e1"), leading=14),
        "h1":   ParagraphStyle("h1", fontName=sans+"-Bold", fontSize=15,
                               textColor=C_BLACK, spaceBefore=0, spaceAfter=6, leading=18),
        "h2":   ParagraphStyle("h2", fontName=sans+"-Bold", fontSize=11,
                               textColor=C_SLATE, spaceBefore=10, spaceAfter=5, leading=14),
        "body": ParagraphStyle("body", fontName=sans, fontSize=9,
                               textColor=C_SLATE, leading=12),
        "body_mono": ParagraphStyle("bm", fontName=mono, fontSize=8,
                                    textColor=C_SLATE, leading=11),
        "small": ParagraphStyle("sm", fontName=sans, fontSize=8,
                                textColor=C_MUTED, leading=10),
        "small_mono": ParagraphStyle("smm", fontName=mono, fontSize=8,
                                     textColor=C_SLATE, leading=11),
        "th":   ParagraphStyle("th", fontName=sans+"-Bold", fontSize=8,
                               textColor=C_WHITE, leading=10),
        "td":   ParagraphStyle("td", fontName=sans, fontSize=8,
                               textColor=C_BLACK, leading=10),
        "td_mono": ParagraphStyle("tdm", fontName=mono, fontSize=8,
                                  textColor=C_BLACK, leading=11),
        "td_muted": ParagraphStyle("tdmt", fontName=sans, fontSize=8,
                                   textColor=C_MUTED, leading=10),
        "label": ParagraphStyle("lbl", fontName=sans+"-Bold", fontSize=7,
                                textColor=C_MUTED, leading=9),
        "value": ParagraphStyle("val", fontName=mono, fontSize=9,
                                textColor=C_BLACK, leading=12),
        "footer": ParagraphStyle("ft", fontName=sans, fontSize=7,
                                 textColor=C_MUTED, leading=9, alignment=TA_CENTER),
        "url": ParagraphStyle("url", fontName=mono, fontSize=8,
                              textColor=C_INDIGO, leading=11),
    }



class _PageTemplate:
    """Draws page number footer and thin header rule on every page after cover."""

    def __init__(self, domain: str, scan_id: str):
        self.domain   = domain
        self.scan_id  = scan_id

    def __call__(self, canv: pdfcanvas.Canvas, doc):
        page = doc.page
        if page == 1:
            return  # cover has its own decoration

        canv.saveState()
        # Top rule
        canv.setStrokeColor(C_BORDER)
        canv.setLineWidth(0.5)
        canv.line(MARGIN_L, PAGE_H - MARGIN_T + 4*mm,
                  PAGE_W - MARGIN_R, PAGE_H - MARGIN_T + 4*mm)

        # Header text
        canv.setFont("Helvetica-Bold", 7)
        canv.setFillColor(C_INDIGO)
        canv.drawString(MARGIN_L, PAGE_H - MARGIN_T + 5.5*mm, "ARGUS")
        canv.setFont("Helvetica", 7)
        canv.setFillColor(C_MUTED)
        canv.drawString(MARGIN_L + 24, PAGE_H - MARGIN_T + 5.5*mm,
                        f"Recon Report — {self.domain}")

        # Page number right
        canv.drawRightString(PAGE_W - MARGIN_R, PAGE_H - MARGIN_T + 5.5*mm,
                             f"Page {page}")

        # Bottom rule + footer
        canv.setStrokeColor(C_BORDER)
        canv.line(MARGIN_L, MARGIN_B - 4*mm,
                  PAGE_W - MARGIN_R, MARGIN_B - 4*mm)
        canv.setFont("Helvetica", 7)
        canv.setFillColor(C_MUTED)
        canv.drawCentredString(PAGE_W / 2, MARGIN_B - 6.5*mm,
                               "For authorized security testing only. CONFIDENTIAL.")
        canv.restoreState()



def _parse_data(r: dict) -> dict:
    d = r.get("data", {})
    if isinstance(d, str):
        try:
            d = json.loads(d)
        except Exception:
            d = {}
    return d or {}


def _status_color(code: int):
    if 200 <= code < 300: return C_GREEN
    if 300 <= code < 400: return C_BLUE
    if 400 <= code < 500: return C_AMBER
    if 500 <= code < 600: return C_RED
    return C_MUTED


def _status_bg(code: int):
    if 200 <= code < 300: return C_GREEN_LO
    if 300 <= code < 400: return C_BLUE_LO
    if 400 <= code < 500: return C_AMBER_LO
    if 500 <= code < 600: return C_RED_LO
    return C_ROW_ALT


def _p(text, style) -> Paragraph:
    """Safely create a Paragraph, escaping XML-unsafe chars."""
    s = str(text) if text is not None else ""
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(s, style)


def _section_header(label: str, tool: str, count: int, styles: dict):
    """Returns a KeepTogether block with colored left-border section header."""
    color = TOOL_COLORS.get(tool, C_INDIGO)
    # Color bar + title in a table
    bar = Table(
        [[_p(f"{label.upper()}  ·  {count} result{'s' if count != 1 else ''}", styles["h1"])]],
        colWidths=[BODY_W],
    )
    bar.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("BACKGROUND",   (0, 0), (-1, -1), colors.Color(color.red, color.green, color.blue, alpha=0.07)),
        ("LINEONSIDES",  (0, 0), (-1, -1), 0, C_BORDER),
        ("LINEBEFORE",   (0, 0), (0, -1),  4, color),
        ("LINEBELOW",    (0, 0), (-1, -1), 0.5, C_BORDER),
    ]))
    return KeepTogether([bar, Spacer(1, 4)])


def _base_th_style(header_color=None):
    hc = header_color or C_NAVY
    return [
        ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("BACKGROUND",     (0, 0), (-1,  0), hc),
        ("TEXTCOLOR",      (0, 0), (-1,  0), C_WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]


def _build_table(rows, col_widths, header_color=None, extra_style=None):
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    cmds = _base_th_style(header_color)
    if extra_style:
        cmds.extend(extra_style)
    t.setStyle(TableStyle(cmds))
    return t



def _build_stats(results: list[dict]) -> dict:
    stats = {
        "total": 0, "by_tool": {},
        "status_dist": {},
        "technologies": set(),
        "wafs": [],
        "open_ports": [],
        "live_hosts": 0,
    }
    for r in results:
        tool = r.get("tool", "")
        if tool == "system":
            continue
        stats["total"] += 1
        stats["by_tool"][tool] = stats["by_tool"].get(tool, 0) + 1
        d = _parse_data(r)
        sc = d.get("status_code")
        if sc:
            stats["status_dist"][int(sc)] = stats["status_dist"].get(int(sc), 0) + 1
        if tool == "httpx" and d.get("url"):
            stats["live_hosts"] += 1
            for t in d.get("tech", []):
                stats["technologies"].add(t)
        if tool == "whatweb":
            for t in d.get("technologies", []):
                stats["technologies"].add(t)
        if d.get("waf_detected"):
            stats["wafs"].append(d.get("waf_name") or "Unknown")
        if d.get("port") and d.get("state") == "open":
            stats["open_ports"].append({
                "port": d["port"], "proto": d.get("protocol", "tcp"),
                "service": d.get("service", ""), "version": d.get("version", ""),
            })
    stats["technologies"] = sorted(stats["technologies"])
    return stats



def _build_cover(elements, scan, styles):
    # Dark header block
    created  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(scan["created_at"]))
    finished = ""
    duration = ""
    if scan.get("finished_at"):
        finished = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(scan["finished_at"]))
        dur_s    = int(scan["finished_at"] - scan["created_at"])
        duration = f"{dur_s // 60}m {dur_s % 60}s"

    tools_used = scan.get("tools", [])
    if isinstance(tools_used, str):
        try:
            tools_used = json.loads(tools_used)
        except Exception:
            tools_used = []

    # Big dark block simulated with a Table
    header_rows = [
        [_p("ARGUS", styles["cover_title"])],
        [_p("Automated Recon &amp; Gathering Utility System", styles["cover_sub"])],
        [Spacer(1, 8)],
        [_p("SCAN REPORT", ParagraphStyle("sr", fontName="Helvetica-Bold", fontSize=11,
                                          textColor=colors.HexColor("#818cf8"), leading=13))],
    ]
    hdr_table = Table(header_rows, colWidths=[BODY_W])
    hdr_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (0, 0),  20),
        ("BOTTOMPADDING", (0, 3), (-1, 3), 22),
    ]))
    elements.append(hdr_table)
    elements.append(Spacer(1, 10))

    # Meta card
    meta_rows = [
        [_p("TARGET DOMAIN", styles["label"]),   _p(scan["domain"], styles["value"])],
        [_p("SCAN ID",       styles["label"]),   _p(scan["id"],     styles["small_mono"])],
        [_p("STATUS",        styles["label"]),   _p(scan.get("status", "").upper(), styles["body"])],
        [_p("TOOLS USED",    styles["label"]),   _p(", ".join(tools_used) if tools_used else "All", styles["body"])],
        [_p("STARTED",       styles["label"]),   _p(created,   styles["body_mono"])],
        [_p("FINISHED",      styles["label"]),   _p(finished or "—", styles["body_mono"])],
        [_p("DURATION",      styles["label"]),   _p(duration or "—",  styles["body"])],
    ]
    meta_t = Table(meta_rows, colWidths=[38 * mm, BODY_W - 38 * mm])
    meta_t.setStyle(TableStyle([
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
        ("LINEBELOW",      (0, 0), (-1, -2), 0.4, C_BORDER),
        ("LINEBEFORE",     (0, 0), (0, -1),  3, C_INDIGO),
        ("BACKGROUND",     (0, 0), (-1, -1), colors.HexColor("#f8faff")),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(meta_t)
    elements.append(Spacer(1, 8))

    # Confidentiality notice
    notice = Table(
        [[_p("⚠  CONFIDENTIAL — For authorized security testing only. "
             "Do not distribute without permission.", styles["small"])]],
        colWidths=[BODY_W],
    )
    notice.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_AMBER_LO),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LINEBEFORE",    (0, 0), (0, -1),  3, C_AMBER),
    ]))
    elements.append(notice)



def _build_summary(elements, scan, results, stats, styles):
    elements.append(Spacer(1, 12))
    elements.append(_p("Executive Summary", styles["h1"]))
    elements.append(Spacer(1, 6))

    # KPI row
    kpis = [
        ("Live Hosts",    str(stats["live_hosts"])),
        ("Open Ports",    str(len(stats["open_ports"]))),
        ("Technologies",  str(len(stats["technologies"]))),
        ("WAF Detections",str(len(stats["wafs"]))),
        ("Total Results", str(stats["total"])),
    ]
    kpi_cells = []
    for label, val in kpis:
        cell = Table([
            [_p(val, ParagraphStyle("kv", fontName="Helvetica-Bold", fontSize=20,
                                    textColor=C_INDIGO, leading=22, alignment=TA_CENTER))],
            [_p(label, ParagraphStyle("kl", fontName="Helvetica", fontSize=8,
                                      textColor=C_MUTED, leading=10, alignment=TA_CENTER))],
        ], colWidths=[BODY_W / len(kpis) - 2])
        cell.setStyle(TableStyle([
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BACKGROUND",    (0, 0), (-1, -1), C_INDIGO_LO),
            ("BOX",           (0, 0), (-1, -1), 0.4, C_BORDER),
        ]))
        kpi_cells.append(cell)

    kpi_row = Table([kpi_cells], colWidths=[BODY_W / len(kpis)] * len(kpis))
    kpi_row.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))
    elements.append(kpi_row)
    elements.append(Spacer(1, 10))

    # Status code distribution
    if stats["status_dist"]:
        elements.append(_p("HTTP Status Code Distribution", styles["h2"]))
        elements.append(Spacer(1, 3))
        sc_header = [_p(h, styles["th"]) for h in ["Status Code", "Count", "Category"]]
        sc_rows   = [sc_header]
        extra     = []
        for i, code in enumerate(sorted(stats["status_dist"].keys()), 1):
            cat = ("2xx Success" if 200 <= code < 300 else
                   "3xx Redirect" if 300 <= code < 400 else
                   "4xx Client Error" if 400 <= code < 500 else
                   "5xx Server Error" if 500 <= code < 600 else "Other")
            sc_rows.append([
                _p(str(code), styles["td_mono"]),
                _p(str(stats["status_dist"][code]), styles["td"]),
                _p(cat, styles["td"]),
            ])
            extra.append(("BACKGROUND", (0, i), (-1, i), _status_bg(code)))
            extra.append(("TEXTCOLOR",  (0, i), (0,  i), _status_color(code)))
            extra.append(("FONTNAME",   (0, i), (0,  i), "Courier-Bold"))
        elements.append(_build_table(sc_rows, [30*mm, 25*mm, BODY_W-55*mm],
                                     header_color=C_SLATE, extra_style=extra))
        elements.append(Spacer(1, 8))

    # Technologies
    if stats["technologies"]:
        elements.append(_p("Technologies Detected", styles["h2"]))
        elements.append(Spacer(1, 3))
        elements.append(_p("  ·  ".join(stats["technologies"]), styles["body"]))
        elements.append(Spacer(1, 8))

    # WAF summary
    if stats["wafs"]:
        elements.append(_p("WAF Detections", styles["h2"]))
        elements.append(Spacer(1, 3))
        waf_list = sorted(set(stats["wafs"]))
        elements.append(_p(",  ".join(waf_list), styles["body"]))
        elements.append(Spacer(1, 8))



def _section_httpx(elements, tool_results, styles):
    header = [_p(h, styles["th"]) for h in ["URL", "Status", "Title", "Server", "Tech Stack"]]
    rows   = [header]
    extra  = []
    for i, r in enumerate(tool_results, 1):
        d  = _parse_data(r)
        sc = d.get("status_code", 0) or 0
        rows.append([
            _p(d.get("url", ""), styles["url"]),
            _p(str(sc) if sc else "—", styles["td_mono"]),
            _p(d.get("title", ""), styles["td"]),
            _p(d.get("server", ""), styles["td_mono"]),
            _p(", ".join(d.get("tech", [])), styles["small"]),
        ])
        if sc:
            bg = _status_bg(sc)
            fg = _status_color(sc)
            extra += [
                ("BACKGROUND", (1, i), (1, i), bg),
                ("TEXTCOLOR",  (1, i), (1, i), fg),
                ("FONTNAME",   (1, i), (1, i), "Courier-Bold"),
            ]
    t = _build_table(rows,
                     [BODY_W*0.32, BODY_W*0.09, BODY_W*0.20, BODY_W*0.18, BODY_W*0.21],
                     header_color=TOOL_COLORS["httpx"], extra_style=extra)
    elements.append(t)


def _section_nmap(elements, tool_results, styles):
    port_rows   = []
    host_info   = {}
    for r in tool_results:
        d = _parse_data(r)
        if d.get("port"):
            port_rows.append(d)
        elif d.get("host") or d.get("ip"):
            host_info = d

    if host_info:
        info = f"Host: {host_info.get('host', '')}   IP: {host_info.get('ip', '')}"
        elements.append(_p(info, styles["body_mono"]))
        elements.append(Spacer(1, 4))

    if not port_rows:
        elements.append(_p("No open ports found.", styles["small"]))
        return

    header = [_p(h, styles["th"]) for h in ["Port", "Protocol", "State", "Service", "Version"]]
    rows   = [header]
    extra  = []
    for i, d in enumerate(port_rows, 1):
        state = d.get("state", "")
        rows.append([
            _p(str(d.get("port", "")), styles["td_mono"]),
            _p(d.get("protocol", ""), styles["td"]),
            _p(state, styles["td"]),
            _p(d.get("service", ""), styles["td"]),
            _p(d.get("version", ""), styles["td_mono"]),
        ])
        if state == "open":
            extra += [
                ("TEXTCOLOR",  (2, i), (2, i), C_GREEN),
                ("FONTNAME",   (2, i), (2, i), "Helvetica-Bold"),
                ("BACKGROUND", (0, i), (-1, i), C_GREEN_LO),
            ]
        elif state == "closed":
            extra.append(("TEXTCOLOR", (2, i), (2, i), C_RED))
    t = _build_table(rows,
                     [BODY_W*0.11, BODY_W*0.11, BODY_W*0.11, BODY_W*0.17, BODY_W*0.50],
                     header_color=TOOL_COLORS["nmap"], extra_style=extra)
    elements.append(t)


def _section_dig(elements, tool_results, styles):
    # Group by DNS record type
    by_type: dict[str, list] = {}
    for r in tool_results:
        d = _parse_data(r)
        t = d.get("type", "OTHER")
        by_type.setdefault(t, []).append(d)

    type_order = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "OTHER"]
    sorted_types = sorted(by_type.keys(), key=lambda x: type_order.index(x) if x in type_order else 99)

    for rtype in sorted_types:
        records = by_type[rtype]
        type_hdr = Table(
            [[_p(rtype, ParagraphStyle("rth", fontName="Helvetica-Bold", fontSize=8,
                                       textColor=TOOL_COLORS["dig"], leading=10))]],
            colWidths=[BODY_W],
        )
        type_hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), colors.Color(0.03, 0.54, 0.71, alpha=0.07)),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LINEBEFORE",    (0,0),(0,-1),  3, TOOL_COLORS["dig"]),
        ]))
        elements.append(type_hdr)

        header = [_p(h, styles["th"]) for h in ["Name", "TTL", "Value"]]
        rows   = [header]
        for d in records:
            rows.append([
                _p(d.get("name", ""), styles["td_mono"]),
                _p(str(d.get("ttl", "")), styles["small_mono"]),
                _p(d.get("value", ""), styles["td_mono"]),
            ])
        t = _build_table(rows,
                         [BODY_W*0.35, BODY_W*0.10, BODY_W*0.55],
                         header_color=C_SLATE)
        elements.append(t)
        elements.append(Spacer(1, 6))


def _section_whois(elements, tool_results, styles):
    fields: dict = {}
    ns_list: list = []
    for r in tool_results:
        d = _parse_data(r)
        f = d.get("field", "")
        v = d.get("value", "")
        if not f or not v:
            continue
        if f == "name server":
            if v not in ns_list:
                ns_list.append(v)
        else:
            fields[f] = v

    display_order = [
        ("registrar",  "Registrar"),
        ("creation",   "Created"),
        ("expiration", "Expires"),
        ("updated",    "Last Updated"),
        ("registrant", "Registrant"),
        ("org",        "Organization"),
        ("country",    "Country"),
        ("dnssec",     "DNSSEC"),
    ]
    rows = []
    for key, label in display_order:
        if key in fields:
            rows.append([
                _p(label, styles["label"]),
                _p(fields[key], styles["value"]),
            ])

    if ns_list:
        rows.append([
            _p("Name Servers", styles["label"]),
            _p("\n".join(ns_list), styles["td_mono"]),
        ])

    if not rows:
        elements.append(_p("No WHOIS data available.", styles["small"]))
        return

    t = Table(rows, colWidths=[35*mm, BODY_W - 35*mm])
    t.setStyle(TableStyle([
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
        ("LINEBELOW",      (0, 0), (-1, -2), 0.4, C_BORDER),
        ("LINEBEFORE",     (0, 0), (0, -1),  3, TOOL_COLORS["whois"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f0f9ff"), C_WHITE]),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(t)


def _section_wafw00f(elements, tool_results, styles):
    header = [_p(h, styles["th"]) for h in ["URL", "WAF Detected", "WAF Name / Vendor"]]
    rows   = [header]
    extra  = []
    for i, r in enumerate(tool_results, 1):
        d         = _parse_data(r)
        detected  = d.get("waf_detected", False)
        waf_name  = d.get("waf_name") or ""
        waf_vendor= d.get("waf_vendor") or ""
        label     = f"{waf_name}" + (f" ({waf_vendor})" if waf_vendor and waf_vendor != waf_name else "")
        rows.append([
            _p(d.get("url", ""), styles["url"]),
            _p("YES" if detected else "NO", styles["td"]),
            _p(label if detected else "—", styles["td"]),
        ])
        if detected:
            extra += [
                ("BACKGROUND", (0, i), (-1, i), C_RED_LO),
                ("TEXTCOLOR",  (1, i), (1, i),  C_RED),
                ("FONTNAME",   (1, i), (1, i),  "Helvetica-Bold"),
            ]
        else:
            extra += [
                ("TEXTCOLOR",  (1, i), (1, i), C_GREEN),
                ("FONTNAME",   (1, i), (1, i), "Helvetica-Bold"),
            ]
    t = _build_table(rows,
                     [BODY_W*0.42, BODY_W*0.15, BODY_W*0.43],
                     header_color=TOOL_COLORS["wafw00f"], extra_style=extra)
    elements.append(t)


def _section_whatweb(elements, tool_results, styles):
    header = [_p(h, styles["th"]) for h in ["URL", "Status", "Technologies"]]
    rows   = [header]
    extra  = []
    for i, r in enumerate(tool_results, 1):
        d    = _parse_data(r)
        sc   = d.get("status_code", 0) or 0
        tech = ", ".join(d.get("technologies", []))
        rows.append([
            _p(d.get("url", ""), styles["url"]),
            _p(str(sc) if sc else "—", styles["td_mono"]),
            _p(tech, styles["small"]),
        ])
        if sc:
            bg = _status_bg(sc)
            fg = _status_color(sc)
            extra += [
                ("BACKGROUND", (1, i), (1, i), bg),
                ("TEXTCOLOR",  (1, i), (1, i), fg),
                ("FONTNAME",   (1, i), (1, i), "Courier-Bold"),
            ]
    t = _build_table(rows,
                     [BODY_W*0.35, BODY_W*0.10, BODY_W*0.55],
                     header_color=TOOL_COLORS["whatweb"], extra_style=extra)
    elements.append(t)


def _section_ffuf(elements, tool_results, styles):
    # Group by host
    by_host: dict[str, list] = {}
    for r in tool_results:
        d    = _parse_data(r)
        host = d.get("host", "unknown")
        by_host.setdefault(host, []).append(d)

    for host, records in by_host.items():
        host_lbl = Table(
            [[_p(f"Fuzzing:  {host}", ParagraphStyle(
                "fh", fontName="Courier-Bold", fontSize=8,
                textColor=TOOL_COLORS["ffuf"], leading=10))]],
            colWidths=[BODY_W],
        )
        host_lbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), colors.Color(0.71, 0.31, 0.04, alpha=0.06)),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LINEBEFORE",    (0,0),(0,-1),  3, TOOL_COLORS["ffuf"]),
        ]))
        elements.append(host_lbl)

        header = [_p(h, styles["th"]) for h in ["Full URL", "Status", "Size (B)", "Words", "Lines"]]
        rows   = [header]
        extra  = []
        for i, d in enumerate(records, 1):
            h_base  = (d.get("host") or "").rstrip("/")
            path    = d.get("path", "")
            fullurl = h_base + (path if path.startswith("/") else "/" + path)
            sc      = d.get("status_code", 0) or 0
            rows.append([
                _p(fullurl, styles["url"]),
                _p(str(sc) if sc else "—", styles["td_mono"]),
                _p(str(d.get("size", "")),  styles["td_mono"]),
                _p(str(d.get("words", "")), styles["td_mono"]),
                _p(str(d.get("lines", "")), styles["td_mono"]),
            ])
            if sc:
                bg = _status_bg(sc)
                fg = _status_color(sc)
                extra += [
                    ("BACKGROUND", (1, i), (1, i), bg),
                    ("TEXTCOLOR",  (1, i), (1, i), fg),
                    ("FONTNAME",   (1, i), (1, i), "Courier-Bold"),
                ]
        t = _build_table(rows,
                         [BODY_W*0.46, BODY_W*0.11, BODY_W*0.14, BODY_W*0.14, BODY_W*0.15],
                         header_color=C_SLATE, extra_style=extra)
        elements.append(t)
        elements.append(Spacer(1, 6))



TOOL_ORDER  = ["whois", "dig", "httpx", "wafw00f", "whatweb", "ffuf", "nmap"]
TOOL_LABELS = {
    "whois":   "WHOIS Lookup",
    "dig":     "DNS Records",
    "httpx":   "HTTP Probing & Subdomains",
    "wafw00f": "WAF Detection",
    "whatweb": "Technology Fingerprinting",
    "ffuf":    "Directory Fuzzing",
    "nmap":    "Port Scanning",
}
SECTION_BUILDERS = {
    "httpx":   _section_httpx,
    "nmap":    _section_nmap,
    "dig":     _section_dig,
    "whois":   _section_whois,
    "wafw00f": _section_wafw00f,
    "whatweb": _section_whatweb,
    "ffuf":    _section_ffuf,
}


def export_pdf(scan: dict, results: list[dict]) -> bytes:
    buf = io.BytesIO()
    styles = _styles()
    tmpl   = _PageTemplate(scan.get("domain", ""), scan.get("id", ""))

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=MARGIN_T, bottomMargin=MARGIN_B,
        leftMargin=MARGIN_L, rightMargin=MARGIN_R,
        onFirstPage=tmpl, onLaterPages=tmpl,
    )

    elements = []
    stats    = _build_stats(results)

    # Cover + summary (page 1)
    _build_cover(elements, scan, styles)
    _build_summary(elements, scan, results, stats, styles)
    elements.append(PageBreak())

    # Per-tool sections
    grouped: dict[str, list] = {}
    for r in results:
        if r.get("tool") != "system":
            grouped.setdefault(r["tool"], []).append(r)

    tools_present = [t for t in TOOL_ORDER if t in grouped]
    # Also catch any tool not in TOOL_ORDER
    for t in grouped:
        if t not in tools_present:
            tools_present.append(t)

    for tool in tools_present:
        tool_results = grouped[tool]
        label        = TOOL_LABELS.get(tool, tool.upper())
        elements.append(_section_header(label, tool, len(tool_results), styles))
        elements.append(Spacer(1, 4))

        builder = SECTION_BUILDERS.get(tool)
        if builder:
            builder(elements, tool_results, styles)
        else:
            # Fallback: plain key-value for unknown tools
            for r in tool_results:
                d = _parse_data(r)
                if d:
                    for k, v in d.items():
                        elements.append(_p(f"{k}: {v}", styles["body_mono"]))
                else:
                    elements.append(_p(r.get("line", ""), styles["body_mono"]))

        elements.append(Spacer(1, 10))

    doc.build(elements)
    return buf.getvalue()



def export_csv(scan: dict, results: list[dict]) -> str:
    """
    Multi-section CSV: one clearly labelled block per tool,
    with tool-appropriate columns and no empty filler columns.
    """
    output = io.StringIO()
    # UTF-8 BOM for Excel compatibility
    output.write("\ufeff")
    writer = csv.writer(output, lineterminator="\r\n")

    created  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan["created_at"]))
    finished = ""
    if scan.get("finished_at"):
        finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan["finished_at"]))

    tools_used = scan.get("tools", [])
    if isinstance(tools_used, str):
        try:
            tools_used = json.loads(tools_used)
        except Exception:
            tools_used = []

    # ── Scan metadata header
    writer.writerow(["ARGUS — Automated Recon & Gathering Utility System"])
    writer.writerow(["Scan Report"])
    writer.writerow([])
    writer.writerow(["Target",   scan.get("domain", "")])
    writer.writerow(["Scan ID",  scan.get("id", "")])
    writer.writerow(["Status",   scan.get("status", "").upper()])
    writer.writerow(["Tools",    ", ".join(tools_used)])
    writer.writerow(["Started",  created])
    writer.writerow(["Finished", finished or "—"])
    writer.writerow([])

    # Group results
    grouped: dict[str, list] = {}
    for r in results:
        t = r.get("tool", "")
        if t != "system":
            grouped.setdefault(t, []).append(r)

    order = [t for t in TOOL_ORDER if t in grouped]
    for t in grouped:
        if t not in order:
            order.append(t)

    # ── Per-tool sections
    for tool in order:
        tool_results = grouped[tool]
        label        = TOOL_LABELS.get(tool, tool.upper())

        writer.writerow([f"── {label.upper()} ({len(tool_results)} results) ──"])

        if tool == "httpx":
            writer.writerow(["URL", "Host", "Status Code", "Title", "Server",
                              "Content Length", "Tech Stack", "Redirect To"])
            for r in tool_results:
                d = _parse_data(r)
                writer.writerow([
                    d.get("url", ""),
                    d.get("host", ""),
                    d.get("status_code", ""),
                    d.get("title", ""),
                    d.get("server", ""),
                    d.get("content_length", ""),
                    "; ".join(d.get("tech", [])),
                    d.get("redirect_to", ""),
                ])

        elif tool == "nmap":
            writer.writerow(["Port", "Protocol", "State", "Service", "Version"])
            for r in tool_results:
                d = _parse_data(r)
                if d.get("port"):
                    writer.writerow([
                        d.get("port", ""), d.get("protocol", ""),
                        d.get("state", ""), d.get("service", ""),
                        d.get("version", ""),
                    ])
                elif d.get("host") or d.get("ip"):
                    writer.writerow([f"# Host: {d.get('host','')}  IP: {d.get('ip','')}"])

        elif tool == "dig":
            writer.writerow(["Type", "Name", "TTL", "Value"])
            for r in tool_results:
                d = _parse_data(r)
                writer.writerow([
                    d.get("type", ""), d.get("name", ""),
                    d.get("ttl", ""),  d.get("value", ""),
                ])

        elif tool == "whois":
            writer.writerow(["Field", "Value"])
            ns_seen = []
            for r in tool_results:
                d = _parse_data(r)
                f = d.get("field", "")
                v = d.get("value", "")
                if f == "name server":
                    if v not in ns_seen:
                        ns_seen.append(v)
                        writer.writerow(["Name Server", v])
                elif f and v:
                    writer.writerow([f.title(), v])

        elif tool == "wafw00f":
            writer.writerow(["URL", "WAF Detected", "WAF Name", "WAF Vendor"])
            for r in tool_results:
                d = _parse_data(r)
                writer.writerow([
                    d.get("url", ""),
                    "YES" if d.get("waf_detected") else "NO",
                    d.get("waf_name", ""),
                    d.get("waf_vendor", ""),
                ])

        elif tool == "whatweb":
            writer.writerow(["URL", "Status Code", "Technologies"])
            for r in tool_results:
                d = _parse_data(r)
                writer.writerow([
                    d.get("url", ""),
                    d.get("status_code", ""),
                    "; ".join(d.get("technologies", [])),
                ])

        elif tool == "ffuf":
            writer.writerow(["Full URL", "Host", "Path", "Status Code",
                              "Size (bytes)", "Words", "Lines"])
            for r in tool_results:
                d     = _parse_data(r)
                h     = (d.get("host") or "").rstrip("/")
                path  = d.get("path", "")
                fullurl = h + (path if path.startswith("/") else "/" + path)
                writer.writerow([
                    fullurl, d.get("host", ""), path,
                    d.get("status_code", ""), d.get("size", ""),
                    d.get("words", ""), d.get("lines", ""),
                ])

        else:
            writer.writerow(["#", "Timestamp", "Field", "Value"])
            for i, r in enumerate(tool_results, 1):
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("ts", 0)))
                d  = _parse_data(r)
                if d:
                    for k, v in d.items():
                        writer.writerow([i, ts, k, v])
                else:
                    writer.writerow([i, ts, "output", r.get("line", "")])

        writer.writerow([])  # blank separator between sections

    return output.getvalue()
