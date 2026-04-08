import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# ---------------------------
# Service Map (extend freely)
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=200):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []            # list[(port, service)]
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            # Still count it so progress bar stays accurate
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            s.close()
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service))
                self.result_queue.put(('open', port, service))
        except OSError as e:
            self.result_queue.put(('error', port, str(e)))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        """Resolve hostname to IP. Raises socket.gaierror on failure."""
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()


# ---------------------------
# Tkinter GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Port Scanner")
        self.geometry("780x580")
        self.minsize(700, 520)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 40
        self._elapsed_after_id = None   # track after() ID for elapsed timer

        self._build_ui()

    # ---------------------------
    # UI Construction
    # ---------------------------
    def _build_ui(self):
        # --- Top Frame: Scan Settings ---
        frm_top = ttk.LabelFrame(self, text="Scan Settings")
        frm_top.pack(fill="x", padx=10, pady=10)

        # Row 0 – Target / Port range
        ttk.Label(frm_top, text="Target (IP / Hostname):").grid(
            row=0, column=0, padx=8, pady=8, sticky="e")
        self.ent_target = ttk.Entry(frm_top, width=32)
        self.ent_target.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="Start Port:").grid(
            row=0, column=2, padx=8, pady=8, sticky="e")
        self.ent_start = ttk.Entry(frm_top, width=8)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="End Port:").grid(
            row=0, column=4, padx=8, pady=8, sticky="e")
        self.ent_end = ttk.Entry(frm_top, width=8)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=8, pady=8, sticky="w")

        # Row 1 – Timeout / Threads (now user-configurable)
        ttk.Label(frm_top, text="Timeout (s):").grid(
            row=1, column=0, padx=8, pady=4, sticky="e")
        self.ent_timeout = ttk.Entry(frm_top, width=8)
        self.ent_timeout.insert(0, "0.5")
        self.ent_timeout.grid(row=1, column=1, padx=8, pady=4, sticky="w")

        ttk.Label(frm_top, text="Threads (max 500):").grid(
            row=1, column=2, padx=8, pady=4, sticky="e")
        self.ent_threads = ttk.Entry(frm_top, width=8)
        self.ent_threads.insert(0, "200")
        self.ent_threads.grid(row=1, column=3, padx=8, pady=4, sticky="w")

        # Start / Stop buttons
        self.btn_start = ttk.Button(frm_top, text="▶  Start Scan", command=self.start_scan)
        self.btn_start.grid(row=1, column=4, padx=8, pady=4, sticky="e")

        self.btn_stop = ttk.Button(frm_top, text="■  Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=1, column=5, padx=8, pady=4, sticky="w")

        for i in range(6):
            frm_top.grid_columnconfigure(i, weight=1)

        # --- Status Bar ---
        frm_status = ttk.LabelFrame(self, text="Status")
        frm_status.pack(fill="x", padx=10, pady=(0, 6))

        self.var_status = tk.StringVar(value="Idle")
        self.lbl_status = ttk.Label(frm_status, textvariable=self.var_status, anchor="w")
        self.lbl_status.pack(side="left", padx=10, pady=6)

        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        ttk.Label(frm_status, textvariable=self.var_elapsed).pack(
            side="right", padx=10, pady=6)

        self.progress = ttk.Progressbar(frm_status, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 8))

        # --- Results Table via Treeview ---
        frm_results = ttk.LabelFrame(self, text="Open Ports")
        frm_results.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        cols = ("port", "service", "status")
        self.tree = ttk.Treeview(frm_results, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("port",    text="Port")
        self.tree.heading("service", text="Service")
        self.tree.heading("status",  text="Status")
        self.tree.column("port",    width=90,  anchor="center")
        self.tree.column("service", width=160, anchor="center")
        self.tree.column("status",  width=120, anchor="center")

        yscroll = ttk.Scrollbar(frm_results, orient="vertical",   command=self.tree.yview)
        xscroll = ttk.Scrollbar(frm_results, orient="horizontal",  command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        yscroll.pack(side="right", fill="y")
        xscroll.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True, padx=(6, 0), pady=6)

        # --- Log / Info area ---
        frm_log = ttk.LabelFrame(self, text="Log")
        frm_log.pack(fill="x", padx=10, pady=(0, 6))

        self.txt_log = tk.Text(frm_log, height=4, wrap="none", state="disabled")
        log_scroll = ttk.Scrollbar(frm_log, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side="right", fill="y")
        self.txt_log.pack(fill="x", padx=6, pady=4)

        # --- Bottom Buttons ---
        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(fill="x", padx=10, pady=(0, 10))

        self.btn_clear = ttk.Button(frm_bottom, text="Clear", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=(0, 6))

        self.btn_save = ttk.Button(
            frm_bottom, text="Save Results", command=self.save_results, state="disabled")
        self.btn_save.pack(side="right")

    # ---------------------------
    # Input Validation
    # ---------------------------
    def _validate_inputs(self):
        """Return (target, start_port, end_port, timeout, threads) or raise ValueError."""
        target = self.ent_target.get().strip()
        if not target or len(target) > 253:
            raise ValueError("Please enter a valid target IP or hostname (max 253 chars).")

        try:
            start_port = int(self.ent_start.get().strip())
            end_port   = int(self.ent_end.get().strip())
        except ValueError:
            raise ValueError("Start Port and End Port must be integers.")

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
            raise ValueError("Ports must be in the range 0–65535.")
        if start_port > end_port:
            raise ValueError("Start Port must be ≤ End Port.")

        try:
            timeout = float(self.ent_timeout.get().strip())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            raise ValueError("Timeout must be a positive number (e.g. 0.5).")

        try:
            threads = int(self.ent_threads.get().strip())
            if not (1 <= threads <= 500):
                raise ValueError
        except ValueError:
            raise ValueError("Thread count must be an integer between 1 and 500.")

        return target, start_port, end_port, timeout, threads

    # ---------------------------
    # Scan Control
    # ---------------------------
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        try:
            target, start_port, end_port, timeout, threads = self._validate_inputs()
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return

        self.scanner = PortScanner(
            target, start_port, end_port, timeout=timeout, max_workers=threads)

        # Resolve DNS on a background thread to avoid blocking the UI
        self._set_inputs_state("disabled")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self.var_status.set("Resolving hostname...")
        self._log(f"Resolving '{target}'…")

        resolve_thread = threading.Thread(
            target=self._resolve_and_start, args=(target, start_port, end_port), daemon=True)
        resolve_thread.start()

    def _resolve_and_start(self, target, start_port, end_port):
        """Run in a background thread. Resolve DNS then kick off the scan."""
        try:
            resolved_ip = self.scanner.resolve_target()
        except Exception as e:
            # Marshal the error back to the main thread
            self.after(0, self._on_resolve_error, target, e)
            return
        self.after(0, self._on_resolve_success, target, resolved_ip, start_port, end_port)

    def _on_resolve_error(self, target, error):
        messagebox.showerror("Resolution Error",
                             f"Failed to resolve '{target}'.\n{error}")
        self._reset_ui_after_scan()
        self.scanner = None

    def _on_resolve_success(self, target, resolved_ip, start_port, end_port):
        self._log(f"Target: {target} → {resolved_ip} | Range: {start_port}–{end_port}")
        self.clear_progress()
        self.start_time = time.time()
        self.var_status.set("Scanning…")
        self._start_elapsed_timer()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Stopping…")

    # ---------------------------
    # Results Polling
    # ---------------------------
    def poll_results(self):
        if not self.scanner:
            return

        scan_done = False
        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()

                if msg_type == 'open':
                    port, service = a, b
                    self.tree.insert("", "end", values=(port, service, "Open"))

                elif msg_type == 'progress':
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    self.var_status.set(f"Scanning… {scanned}/{total}")

                elif msg_type == 'error':
                    # Silently ignore connection errors (expected for closed ports)
                    pass

                elif msg_type == 'done':
                    scan_done = True

        except queue.Empty:
            pass

        if scan_done or (self.scanner_thread and not self.scanner_thread.is_alive()):
            # Drain any remaining items that arrived before 'done'
            self._drain_queue()
            self._finish_scan()
            return

        self.after(self.poll_after_ms, self.poll_results)

    def _drain_queue(self):
        """Consume any leftover messages after the scan thread finishes."""
        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()
                if msg_type == 'open':
                    self.tree.insert("", "end", values=(a, b, "Open"))
                elif msg_type == 'progress':
                    self.progress.configure(maximum=max(b, 1), value=a)
        except queue.Empty:
            pass

    def _finish_scan(self):
        total_open = len(self.scanner.open_ports) if self.scanner else 0
        self._log(f"Scan complete. Open ports found: {total_open}")
        self.var_status.set(
            f"Completed — {total_open} open port{'s' if total_open != 1 else ''} found.")
        self._reset_ui_after_scan()
        if total_open:
            self.btn_save.configure(state="normal")

    # ---------------------------
    # UI Helpers
    # ---------------------------
    def _reset_ui_after_scan(self):
        self._set_inputs_state("normal")
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.start_time = None           # stops the elapsed timer

    def _set_inputs_state(self, state):
        """Lock/unlock all input widgets during a scan."""
        for widget in (self.ent_target, self.ent_start, self.ent_end,
                       self.ent_timeout, self.ent_threads):
            widget.configure(state=state)

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.txt_log.configure(state="normal")
        self.txt_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.txt_log.see(tk.END)
        self.txt_log.configure(state="disabled")

    def clear_progress(self):
        self.progress.configure(value=0, maximum=100)

    def _start_elapsed_timer(self):
        if self._elapsed_after_id:
            self.after_cancel(self._elapsed_after_id)
        self._tick_elapsed()

    def _tick_elapsed(self):
        if self.start_time is not None:
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self._elapsed_after_id = self.after(200, self._tick_elapsed)
        else:
            self._elapsed_after_id = None

    def clear_results(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.configure(state="disabled")
        self.clear_progress()
        self.var_status.set("Idle")
        self.var_elapsed.set("Elapsed: 0.00s")
        self.btn_save.configure(state="disabled")

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save Results", "No open ports to save.")
            return

        default_name = f"open_ports_{int(time.time())}.txt"
        file_path = filedialog.asksaveasfilename(
            title="Save results",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"# Network Port Scan Results\n")
                f.write(f"# Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Target   : {self.scanner.target}\n")
                f.write(f"# Range    : {self.scanner.start_port}–{self.scanner.end_port}\n")
                f.write(f"# Timeout  : {self.scanner.timeout}s\n\n")
                f.write(f"{'Port':<10}{'Service':<20}Status\n")
                f.write("-" * 40 + "\n")
                for port, service in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                    f.write(f"{port:<10}{service:<20}Open\n")
            messagebox.showinfo("Saved", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file.\n{e}")


# ---------------------------
# Entry Point
# ---------------------------
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
