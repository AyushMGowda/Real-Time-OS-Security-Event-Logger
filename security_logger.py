from os import name
import sys
import psutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import csv
from collections import defaultdict, deque
from windows_event_monitor import WindowsSecurityMonitor


class SecurityLogger:
    def __init__(self, root):
        
        self.failed_login_window = deque(maxlen=50)
        self.bruteforce_threshold = 5
        self.bruteforce_window_seconds = 60

        self.root = root
        self.root.title("OS Event Security Logger")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e1e")

        # ===== Core State =====
        self.logs = []
        self.process_history = defaultdict(lambda: deque(maxlen=5))
        self.known_pids = set()
        self.ignored_processes = {"system idle process", "idle", "system"}
        self.system_alert_active = False
        self.alert_cooldown = {}
        self.cooldown_seconds = 15

        self.alert_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}

        self.suspicious_processes = {
            "powershell.exe": "T1059.001 - PowerShell Execution",
            "cmd.exe": "T1059 - Command Execution",
            "wmic.exe": "T1047 - WMI Execution",
            "rundll32.exe": "T1218 - Signed Binary Proxy Execution",
            "regsvr32.exe": "T1218.010 - Regsvr32 Execution",
        }

        # ===== Styling =====
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Main.TFrame", background="#1e1e1e")
        style.configure("Header.TLabel", background="#1e1e1e", foreground="white", font=("Segoe UI", 18, "bold"))
        style.configure("Status.TLabel", background="#111111", foreground="gray")

        # ===== Main Frame =====
        main_frame = ttk.Frame(self.root, style="Main.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ===== Header =====
        header = ttk.Label(main_frame, text="REAL-TIME SECURITY MONITOR", style="Header.TLabel")
        header.pack(pady=15)

        # ===== Alert Counters =====
        counter_frame = tk.Frame(main_frame, bg="#2a2a2a")
        counter_frame.pack(fill=tk.X, padx=20, pady=5)

        self.counter_label = tk.Label(
            counter_frame,
            text="CRITICAL: 0   HIGH: 0   MEDIUM: 0   INFO: 0",
            bg="#2a2a2a",
            fg="white",
            font=("Segoe UI", 12)
        )
        self.counter_label.pack(pady=5)

        # ===== Log Panel =====
        log_frame = tk.Frame(main_frame, bg="#1e1e1e")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.log_display = tk.Text(
            log_frame,
            bg="#121212",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 10)
        )
        self.log_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(log_frame, command=self.log_display.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_display.config(yscrollcommand=scrollbar.set)

        # ===== Severity Colors =====
        self.log_display.tag_config("INFO", foreground="lightgray")
        self.log_display.tag_config("MEDIUM", foreground="yellow")
        self.log_display.tag_config("HIGH", foreground="orange")
        self.log_display.tag_config("CRITICAL", foreground="red")

        # ===== Controls =====
        control_frame = tk.Frame(main_frame, bg="#1e1e1e")
        control_frame.pack(fill=tk.X, padx=20, pady=5)

        self.filter_var = tk.StringVar(value="Security Alerts")

        filter_menu = ttk.Combobox(
            control_frame,
            textvariable=self.filter_var,
            values=["All Events", "Process Events", "Resource Usage", "Security Alerts"],
            state="readonly"
        )
        filter_menu.pack(side=tk.LEFT, padx=5)
        filter_menu.bind("<<ComboboxSelected>>", self.filter_logs)

        tk.Button(
            control_frame,
            text="Export Logs",
            command=self.export_logs,
            bg="#333333",
            fg="white",
            activebackground="#555555",
            relief="flat",
            padx=10
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            control_frame,
            text="Clear Logs",
            command=self.clear_logs,
            bg="#333333",
            fg="white",
            activebackground="#555555",
            relief="flat",
            padx=10
        ).pack(side=tk.LEFT, padx=5)

        # ===== Status Bar =====
        self.status_var = tk.StringVar(value="Monitoring system events...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, style="Status.TLabel")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # ===== Security Monitor Engine =====
        self.win_monitor = WindowsSecurityMonitor(self.log_event)

        # Start monitoring loop
        self.monitor_system()

        self.suspicious_processes = {
            "powershell.exe": "T1059.001 - PowerShell Execution",
            "cmd.exe": "T1059 - Command Execution",
            "wmic.exe": "T1047 - WMI Execution",
            "rundll32.exe": "T1218 - Signed Binary Proxy Execution",
            "regsvr32.exe": "T1218.010 - Regsvr32 Execution",
        }

    # ================= BRUTE-FORCE DETECTION =================
    def detect_bruteforce(self, message, severity, category):
        now = datetime.now()

        # Track failed login attempts
        if category == "AUTH" and "Failed login" in message:
            self.failed_login_window.append(now)

            # Count recent failures
            recent_failures = [
                t for t in self.failed_login_window
                if (now - t).total_seconds() < self.bruteforce_window_seconds
            ]

            if len(recent_failures) >= self.bruteforce_threshold:
                self.log_event(
                    "Brute-force attack suspected (multiple failed logins detected)",
                    "CRITICAL",
                    "CORRELATION"
                )

                # Reset window to avoid infinite trigger
                self.failed_login_window.clear()



    # ================= MONITOR LOOP =================
    def monitor_system(self):
        self.win_monitor.check_events()
        current_pids = set()

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    name = proc.info['name']
                    pid = proc.info['pid']
                    cpu = proc.info['cpu_percent'] or 0
                    mem = proc.info['memory_percent'] or 0

                    current_pids.add(pid)

                    if pid not in self.known_pids:
                        self.known_pids.add(pid)

                        process_name_lower = name.lower()

                        if process_name_lower in self.suspicious_processes:
                            technique = self.suspicious_processes[process_name_lower]

                            self.log_event(
                                f"Suspicious process started: {name} (PID: {pid}) | {technique}",
                                "HIGH",
                                "PROCESS"
                            )
                        else:
                            self.log_event(
                                f"Process Created: {name} (PID: {pid})",
                                "INFO",
                                "PROCESS"
                        )

                    self.process_history[name].append({'cpu': cpu, 'mem': mem})

                    from time import time

                    current_timestamp = time()

                    if (len(self.process_history[name]) >= 5 and
                        max(p['cpu'] for p in self.process_history[name]) > 80 and
                        pid != 0 and name.lower() not in self.ignored_processes):

                        last_alert = self.alert_cooldown.get(name, 0)

                        if current_timestamp - last_alert > self.cooldown_seconds:
                            self.alert_cooldown[name] = current_timestamp

                            self.log_event(
                                f"Sustained high CPU usage detected for {name} (PID: {pid})",
                                "HIGH",
                                "PROCESS"
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            cpu_percent = psutil.cpu_percent()
            mem_percent = psutil.virtual_memory().percent

            if cpu_percent > 85 or mem_percent > 85:
                if not self.system_alert_active:
                    self.log_event(
                        f"System resource threshold exceeded (CPU: {cpu_percent}%, Memory: {mem_percent}%)",
                        "MEDIUM",
                        "SYSTEM"
                    )
                    self.system_alert_active = True
            else:
                if self.system_alert_active:
                    self.log_event(
                        "System resource usage returned to normal levels",
                        "INFO",
                        "SYSTEM"
                    )
                    self.system_alert_active = False

            self.known_pids.intersection_update(current_pids)

        except Exception as e:
            self.log_event(f"Monitoring Error: {str(e)}", "CRITICAL", "SYSTEM")

        self.root.after(1000, self.monitor_system)

    # ================= LOGGER =================
    def log_event(self, message, severity="INFO", category="SYSTEM"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{severity}] [{category}] {message}"

        self.logs.append({
            "time": timestamp,
            "severity": severity,
            "category": category,
            "message": message
        })

        self.log_display.insert(tk.END, entry + "\n", severity)
        self.log_display.see(tk.END)

        if severity in self.alert_counts:
            self.alert_counts[severity] += 1

        self.counter_label.config(
            text=f"CRITICAL: {self.alert_counts['CRITICAL']}   "
                f"HIGH: {self.alert_counts['HIGH']}   "
                f"MEDIUM: {self.alert_counts['MEDIUM']}   "
                f"INFO: {self.alert_counts['INFO']}"
        )
        self.detect_bruteforce(message, severity, category)

    def _display_log(self, log):
        entry = f"[{log['time']}] [{log['severity']}] [{log['category']}] {log['message']}"
        self.log_display.insert(tk.END, entry + "\n", log['severity'])

    # ================= FILTER =================
    def filter_logs(self, event=None):
        self.log_display.delete("1.0", tk.END)
        keyword = self.filter_var.get()

        for log in self.logs:
            if keyword == "All Events":
                self._display_log(log)

            elif keyword == "Process Events" and log["category"] == "PROCESS":
                self._display_log(log)

            elif keyword == "Resource Usage" and log["category"] == "SYSTEM":
                self._display_log(log)

            elif keyword == "Security Alerts" and log["severity"] in ("HIGH", "CRITICAL"):
                self._display_log(log)

    # ================= EXPORT =================
    def export_logs(self):
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file:
            try:
                with open(file, "w", newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Timestamp", "Severity", "Category", "Message"])
                    for log in self.logs:
                        writer.writerow([log["time"], log["severity"], log["category"], log["message"]])

                messagebox.showinfo("Success", "Logs exported successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")

    # ================= CLEAR =================
    def clear_logs(self):
        self.logs.clear()
        self.log_display.delete("1.0", tk.END)
        self.process_history.clear()
        self.known_pids.clear()
        self.status_var.set("Logs cleared.")


if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityLogger(root)
    root.mainloop()
