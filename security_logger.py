import sys
import psutil
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import csv
from collections import defaultdict

class SecurityLogger:
    def __init__(self, root):
        self.root = root
        self.root.title("OS Event Security Logger")
        self.root.geometry("800x600")
        
        # Initialize variables
        self.logs = []
        self.process_history = defaultdict(list)
        self.anomaly_threshold = 5  # Threshold for anomaly detection
        
        # Configure dark theme
        self.root.configure(bg='#353535')
        style = ttk.Style()
        style.configure("Dark.TFrame", background='#353535')
        style.configure("Dark.TLabel", background='#353535', foreground='white')
        style.configure("Dark.TButton", background='#353535', foreground='white')
        style.configure("Dark.TCombobox", background='#353535', foreground='white')
        
        # Create main frame
        main_frame = ttk.Frame(root, style="Dark.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        header = ttk.Label(main_frame, text="Real-Time Security Event Logger", 
                          font=('Arial', 16, 'bold'), style="Dark.TLabel")
        header.pack(pady=10)
        
        # Create control panel
        control_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Filter dropdown
        ttk.Label(control_frame, text="Filter:", style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="All Events")
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var, 
                                  values=["All Events", "Process Events", "Resource Usage", "Security Alerts"],
                                  state="readonly", style="Dark.TCombobox")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)
        
        # Export button
        export_btn = ttk.Button(control_frame, text="Export Logs", 
                               command=self.export_logs, style="Dark.TButton")
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        clear_btn = ttk.Button(control_frame, text="Clear Logs", 
                              command=self.clear_logs, style="Dark.TButton")
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Create log display
        self.log_display = scrolledtext.ScrolledText(main_frame, height=20, 
                                                    bg='#252525', fg='white')
        self.log_display.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create status bar
        self.status_var = tk.StringVar(value="Monitoring system events...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              style="Dark.TLabel")
        status_bar.pack(fill=tk.X, pady=5)
        
        # Start monitoring
        self.monitor_system()
        
    def monitor_system(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Monitor processes
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    name = proc.info['name']
                    cpu_percent = proc.info['cpu_percent'] or 0
                    memory_percent = proc.info['memory_percent'] or 0
                    pid = proc.info['pid']
                    
                    if name not in self.process_history:
                        self.process_history[name] = []
                    
                    self.process_history[name].append({
                        'time': current_time,
                        'cpu': cpu_percent,
                        'memory': memory_percent
                    })
                    
                    # Detect anomalies
                    if len(self.process_history[name]) > self.anomaly_threshold:
                        recent_usage = [p['cpu'] for p in self.process_history[name][-self.anomaly_threshold:]]
                        if max(recent_usage) > 80:  # High CPU usage
                            self.log_event(f"Security Alert: High CPU usage detected for {name} (PID: {pid})")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Monitor system resources
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 80 or memory_percent > 80:
                self.log_event(f"System Alert: High resource usage detected (CPU: {cpu_percent}%, Memory: {memory_percent}%)")
        
        except Exception as e:
            self.log_event(f"Error monitoring system: {str(e)}")
        
        # Schedule next update
        self.root.after(1000, self.monitor_system)
    
    def log_event(self, event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}"
        self.logs.append(log_entry)
        self.log_display.insert(tk.END, log_entry + '\n')
        self.log_display.see(tk.END)
    
    def filter_logs(self, event=None):
        self.log_display.delete('1.0', tk.END)
        filter_text = self.filter_var.get()
        for log in self.logs:
            if filter_text == "All Events":
                self.log_display.insert(tk.END, log + '\n')
            elif filter_text == "Process Events" and "Process" in log:
                self.log_display.insert(tk.END, log + '\n')
            elif filter_text == "Resource Usage" and "resource" in log.lower():
                self.log_display.insert(tk.END, log + '\n')
            elif filter_text == "Security Alerts" and "Security Alert" in log:
                self.log_display.insert(tk.END, log + '\n')
    
    def export_logs(self):
        file_name = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Export Logs"
        )
        if file_name:
            try:
                with open(file_name, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Timestamp', 'Event'])
                    for log in self.logs:
                        timestamp = log[1:20]  # Extract timestamp
                        event = log[22:]  # Extract event message
                        writer.writerow([timestamp, event])
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def clear_logs(self):
        self.logs.clear()
        self.log_display.delete('1.0', tk.END)
        self.process_history.clear()
        self.status_var.set("Logs cleared")

if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityLogger(root)
    root.mainloop()