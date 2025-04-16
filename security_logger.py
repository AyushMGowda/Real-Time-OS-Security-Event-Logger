import sys
import psutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import csv
from collections import defaultdict, deque

class SecurityLogger:
    def __init__(self, root):
        self.root = root
        self.root.title("OS Event Security Logger")
        self.root.geometry("800x600")

        self.logs = []
        self.process_history = defaultdict(lambda: deque(maxlen=5))
        self.known_pids = set()
        self.ignored_processes = {"system idle process", "idle", "system"}

        self.root.configure(bg='#353535')
        style = ttk.Style()
        style.configure("Dark.TFrame", background='#353535')
        style.configure("Dark.TLabel", background='#353535', foreground='white')
        style.configure("Dark.TButton", background='#353535', foreground='white')
        style.configure("Dark.TCombobox", fieldbackground='#353535', foreground='white', background='#353535')

        main_frame = ttk.Frame(root, style="Dark.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        header = ttk.Label(main_frame, text="Real-Time Security Event Logger",
                           font=('Arial', 16, 'bold'), style="Dark.TLabel")
        header.pack(pady=10)

        control_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(control_frame, text="Filter:", style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="All Events")
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var,
                                    values=["All Events", "Process Events", "Resource Usage", "Security Alerts"],
                                    state="readonly", style="Dark.TCombobox")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)

        ttk.Button(control_frame, text="Export Logs", command=self.export_logs, style="Dark.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs, style="Dark.TButton").pack(side=tk.LEFT, padx=5)

        self.log_display = scrolledtext.ScrolledText(main_frame, height=20, bg='#252525', fg='white')
        self.log_display.pack(fill=tk.BOTH, expand=True, pady=5)

        self.status_var = tk.StringVar(value="Monitoring system events...")
        ttk.Label(main_frame, textvariable=self.status_var, style="Dark.TLabel").pack(fill=tk.X, pady=5)

        self.monitor_system()

    def monitor_system(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                        self.log_event(f"Process Created: {name} (PID: {pid})")

                    self.process_history[name].append({'cpu': cpu, 'mem': mem})

                    if (len(self.process_history[name]) >= 5 and
                        max(p['cpu'] for p in self.process_history[name]) > 80 and
                        pid != 0 and name.lower() not in self.ignored_processes):
                        self.log_event(f"Security Alert: High CPU usage by {name} (PID: {pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            cpu_percent = psutil.cpu_percent()
            mem_percent = psutil.virtual_memory().percent

            if cpu_percent > 85 or mem_percent > 85:
                self.log_event(f"System Alert: High resource usage (CPU: {cpu_percent}%, Memory: {mem_percent}%)")

            self.known_pids.intersection_update(current_pids)

        except Exception as e:
            self.log_event(f"Monitoring Error: {str(e)}")

        self.root.after(1000, self.monitor_system)

    def log_event(self, event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {event}"
        self.logs.append(entry)
        self.log_display.insert(tk.END, entry + "\n")
        self.log_display.see(tk.END)

    def filter_logs(self, event=None):
        self.log_display.delete("1.0", tk.END)
        keyword = self.filter_var.get()
        for log in self.logs:
            if keyword == "All Events":
                self.log_display.insert(tk.END, log + "\n")
            elif keyword == "Process Events" and "Process Created" in log:
                self.log_display.insert(tk.END, log + "\n")
            elif keyword == "Resource Usage" and "resource usage" in log.lower():
                self.log_display.insert(tk.END, log + "\n")
            elif keyword == "Security Alerts" and "Security Alert" in log:
                self.log_display.insert(tk.END, log + "\n")

    def export_logs(self):
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file:
            try:
                with open(file, "w", newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Timestamp", "Event"])
                    for log in self.logs:
                        writer.writerow([log[1:20], log[22:]])
                messagebox.showinfo("Success", "Logs exported successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")

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
