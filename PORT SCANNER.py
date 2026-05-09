import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, messagebox

# ================= CONFIG =================

TOP_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3389,3306,8080]

PORT_ANALYSIS = {
    21: ("FTP", "HIGH"),
    22: ("SSH", "MEDIUM"),
    23: ("Telnet", "CRITICAL"),
    80: ("HTTP", "MEDIUM"),
    443: ("HTTPS", "LOW"),
    445: ("SMB", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "CRITICAL"),
}

RISK_WEIGHT = {"CRITICAL":20,"HIGH":10,"MEDIUM":5,"LOW":1}

# ================= SCAN =================

def scan_port(host, port, timeout=1, retries=2):
    for _ in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except:
            pass
    return False

def analyze(port):
    if port in PORT_ANALYSIS:
        service, risk = PORT_ANALYSIS[port]
    else:
        service, risk = "Unknown", "LOW"
    return {"port": port, "service": service, "risk": risk}

def calculate_score(results):
    return min(sum(RISK_WEIGHT[r["risk"]] for r in results), 100)

# ================= GUI =================

class PortLensApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PortLens")
        self.root.geometry("1000x650")
        self.root.configure(bg="#0d1117")

        self.results = []
        self.total_ports = 0
        self.scanned = 0
        self.stop_scan = False  # STOP FLAG

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#0d1117",
                        foreground="white",
                        fieldbackground="#0d1117",
                        rowheight=28)
        style.map('Treeview', background=[('selected', '#238636')])

        # ===== HEADER =====
        header = tk.Frame(root, bg="#0d1117")
        header.pack(fill="x", pady=10)

        tk.Label(header, text="PORTLENS",
                 font=("Consolas", 22, "bold"),
                 fg="#00ff9c", bg="#0d1117").pack()

        tk.Label(header, text="Network Port Visibility Tool",
                 fg="gray", bg="#0d1117").pack()

        # ===== INPUT CARD =====
        card = tk.Frame(root, bg="#161b22")
        card.pack(padx=15, pady=10, fill="x")

        tk.Label(card, text="Target",
                 fg="white", bg="#161b22").grid(row=0, column=0, padx=10, pady=10)

        self.entry = tk.Entry(card, width=40,
                              bg="#0d1117", fg="white",
                              insertbackground="white", bd=0)
        self.entry.grid(row=0, column=1, padx=10)

        tk.Button(card, text="Top Ports",
                  bg="#238636", fg="white",
                  command=self.start_top_scan).grid(row=0, column=2, padx=5)

        tk.Button(card, text="Full Scan",
                  bg="#da3633", fg="white",
                  command=self.start_full_scan).grid(row=0, column=3, padx=5)

        tk.Button(card, text="Stop",
                  bg="#f85149", fg="white",
                  command=self.confirm_stop).grid(row=0, column=4, padx=5)

        # ===== PROGRESS =====
        progress_frame = tk.Frame(root, bg="#0d1117")
        progress_frame.pack(fill="x", padx=20)

        self.progress = ttk.Progressbar(progress_frame, length=800)
        self.progress.pack(pady=5)

        self.progress_label = tk.Label(progress_frame,
                                       text="0%",
                                       fg="gray", bg="#0d1117")
        self.progress_label.pack()

        self.status = tk.Label(root, text="Status: Idle",
                               fg="gray", bg="#0d1117")
        self.status.pack(pady=5)

        # ===== TABLE =====
        table_frame = tk.Frame(root, bg="#0d1117")
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)

        columns = ("Port", "Service", "Risk")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.pack(fill="both", expand=True)

        # ===== SUMMARY =====
        self.summary = tk.Label(root, text="",
                                font=("Consolas", 12),
                                bg="#0d1117")
        self.summary.pack(pady=10)

    def resolve(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            self.status.config(text="❌ Host resolution failed", fg="red")
            return None

    def confirm_stop(self):
        confirm = messagebox.askyesno(
            "Stop Scan",
            "Are you sure you want to stop the scan?\nPartial results will be shown."
        )
        if confirm:
            self.stop_scan = True

    def start_top_scan(self):
        threading.Thread(target=self.scan, args=(TOP_PORTS,), daemon=True).start()

    def start_full_scan(self):
        threading.Thread(target=self.scan, args=(range(0,65536),), daemon=True).start()

    def scan(self, ports):
        host = self.entry.get().strip()
        ip = self.resolve(host)
        if not ip:
            return

        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.total_ports = len(ports)
        self.scanned = 0
        self.stop_scan = False  # reset flag

        self.status.config(text=f"Scanning {ip}...", fg="yellow")

        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(scan_port, ip, p): p for p in ports}

            for future in futures:
                if self.stop_scan:
                    self.status.config(text="⚠️ Scan Stopped by User", fg="orange")
                    break

                port = futures[future]
                is_open = future.result()
                self.scanned += 1

                percent = int((self.scanned / self.total_ports) * 100)
                self.progress["value"] = percent
                self.progress_label.config(text=f"{percent}%")
                self.root.update_idletasks()

                if is_open:
                    data = analyze(port)
                    self.results.append(data)

                    self.tree.insert("", "end",
                                     values=(data["port"], data["service"], data["risk"]))

        self.finish()

    def finish(self):
        score = calculate_score(self.results)

        if score > 70:
            level = "HIGH RISK 🚨"
            color = "red"
        elif score > 40:
            level = "MEDIUM RISK ⚠️"
            color = "orange"
        else:
            level = "LOW RISK ✅"
            color = "green"

        self.summary.config(text=f"Risk Score: {score}/100 | {level}", fg=color)
        self.status.config(text="Scan Complete", fg="green")

# ================= RUN =================

if __name__ == "__main__":
    root = tk.Tk()
    app = PortLensApp(root)
    root.mainloop()