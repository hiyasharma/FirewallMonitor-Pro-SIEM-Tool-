import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os
import threading
import time

# Sample Report Data (Template)
report_data = []

# Function to monitor the firewall log
def monitor_firewall_log_ui(log_file_path, log_display, alert_display, status_label, stop_event):
    try:
        if not os.path.exists(log_file_path):
            messagebox.showerror("Error", f"Log file '{log_file_path}' not found.")
            return

        log_display.insert(tk.END, f"Monitoring firewall log file: {log_file_path}\n")
        status_label.config(text="Status: Monitoring", fg="lightgreen")
        processed_lines = 0

        while not stop_event.is_set():
            with open(log_file_path, 'r') as log_file:
                lines = log_file.readlines()
                new_entries = lines[processed_lines:]

                for line in new_entries:
                    log_display.insert(tk.END, line + '\n')
                    log_display.see(tk.END)

                    try:
                        parsed_entry = parse_firewall_log_entry(line)
                        if is_suspicious_entry(parsed_entry):
                            alert = generate_alert(parsed_entry)
                            alert_display.insert(tk.END, alert + '\n')
                            alert_display.see(tk.END)
                            add_to_report_data(line, parsed_entry, alert)
                    except Exception as e:
                        log_display.insert(tk.END, f"Error processing log entry: {line} - {e}\n")

                processed_lines = len(lines)

            time.sleep(5)

    except Exception as e:
        log_display.insert(tk.END, f"Error: {e}\n")
        status_label.config(text="Status: Error", fg="red")

# Parse a single log entry into a dictionary
def parse_firewall_log_entry(log_entry):
    fields = [
        'Date', 'Time', 'Action', 'Protocol', 'SourceIP', 'DestinationIP',
        'SourcePort', 'DestinationPort', 'Size', 'TCPFlags', 'TCPSYN', 'TCPACK',
        'TCPWin', 'ICMPType', 'ICMPCode'
    ]
    return dict(zip(fields, log_entry.split()))

# Check if a log entry is suspicious
def is_suspicious_entry(log_entry):
    return log_entry.get('Action') == 'Block' and log_entry.get('Protocol') == 'UDP'

# Generate an alert message for a suspicious log
def generate_alert(log_entry):
    source_ip = log_entry['SourceIP']
    destination_ip = log_entry['DestinationIP']
    return f"ALERT: Suspicious traffic from {source_ip} to {destination_ip}"

# Add alert details to report data
def add_to_report_data(log_entry, parsed_entry, alert):
    report_data.append({
        "incident_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log_entry": log_entry.strip(),
        "parsed_log": parsed_entry,
        "alert_details": alert,
        "investigation": {
            "traffic_analysis": {
                "suspicious_packet_size": f"Large packet size detected: {parsed_entry.get('Size', 'Unknown')} bytes"
            }
        }
    })

# Function to generate a text report
def generate_text_report():
    report_path = "firewall_report.txt"
    try:
        with open(report_path, "w") as file:
            file.write("=== Firewall Incident Report ===\n\n")
            for index, alert in enumerate(report_data, 1):
                file.write(f"Alert #{index}\n")
                file.write(f"Incident Time: {alert['incident_time']}\n")
                file.write(f"Log Entry: {alert['log_entry']}\n\n")
                file.write("=== Parsed Log Details ===\n")
                for key, value in alert['parsed_log'].items():
                    file.write(f"{key}: {value}\n")
                file.write("\n=== Alert Details ===\n")
                file.write(f"{alert['alert_details']}\n\n")
                file.write("=== Investigation Details ===\n")
                for section, details in alert['investigation'].items():
                    file.write(f"{section.replace('_', ' ').capitalize()}:\n")
                    for key, value in details.items():
                        file.write(f"  {key.replace('_', ' ').capitalize()}: {value}\n")
                    file.write("\n")
        messagebox.showinfo("Success", f"Text report generated: {report_path}")
        os.startfile(report_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate text report: {e}")

# Function to generate an HTML report
def generate_html_report():
    report_path = "firewall_report.html"
    try:
        with open(report_path, "w") as file:
            file.write("<html><head><title>Firewall Incident Report</title></head><body>")
            file.write("<h1>Firewall Incident Report</h1>")
            for index, alert in enumerate(report_data, 1):
                file.write(f"<h2>Alert #{index}</h2>")
                file.write(f"<p><strong>Incident Time:</strong> {alert['incident_time']}</p>")
                file.write(f"<p><strong>Log Entry:</strong> {alert['log_entry']}</p>")
                file.write("<h3>Parsed Log Details</h3><ul>")
                for key, value in alert['parsed_log'].items():
                    file.write(f"<li><strong>{key}:</strong> {value}</li>")
                file.write("</ul>")
                file.write(f"<h3>Alert Details</h3><p>{alert['alert_details']}</p>")
                file.write("<h3>Investigation Details</h3><ul>")
                for section, details in alert['investigation'].items():
                    file.write(f"<li><strong>{section.replace('_', ' ').capitalize()}:</strong>")
                    for key, value in details.items():
                        file.write(f"<ul><li>{key.replace('_', ' ').capitalize()}: {value}</li></ul>")
                    file.write("</li>")
                file.write("</ul>")
            file.write("</body></html>")
        messagebox.showinfo("Success", f"HTML report generated: {report_path}")
        os.startfile(report_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate HTML report: {e}")

# UI Setup
app = tk.Tk()
app.title("Firewall Monitor Pro")
app.geometry("900x750")
app.configure(bg="#00274D")

# Tool Name Label
tool_name_label = tk.Label(
    app, text="Firewall Monitor Pro", font=("Helvetica", 24, "bold"), fg="#FF4500", bg="#00274D"
)
tool_name_label.pack(pady=10)

# Status Label
status_label = tk.Label(
    app, text="Status: Not Monitoring", font=("Helvetica", 14), fg="white", bg="#00274D"
)
status_label.pack(pady=5)

# UI Components
frame = tk.Frame(app, bg="#00274D")
frame.pack(pady=10)

start_button = tk.Button(
    frame, text="Start Monitoring", command=lambda: start_monitoring(), bg="#32CD32", fg="white", font=("Helvetica", 12)
)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(
    frame, text="Stop Monitoring", command=lambda: stop_monitoring(), bg="#FF0000", fg="white", font=("Helvetica", 12)
)
stop_button.pack(side=tk.LEFT, padx=5)

generate_text_button = tk.Button(
    frame, text="Generate Text Report", command=generate_text_report, bg="#1E90FF", fg="white", font=("Helvetica", 12)
)
generate_text_button.pack(side=tk.LEFT, padx=5)

generate_html_button = tk.Button(
    frame, text="Generate HTML Report", command=generate_html_report, bg="#FFD700", fg="black", font=("Helvetica", 12)
)
generate_html_button.pack(side=tk.LEFT, padx=5)

# Logs Section Title
logs_title_label = tk.Label(
    app, text="Logs", font=("Helvetica", 16, "bold"), fg="black", bg="white"
)
logs_title_label.pack(pady=5)

log_display = scrolledtext.ScrolledText(
    app, height=18, wrap=tk.WORD, bg="white", fg="black", font=("Consolas", 10)
)
log_display.pack(padx=10, pady=5, fill=tk.BOTH)

alerts_title_label = tk.Label(
    app, text="Alerts", font=("Helvetica", 16, "bold"), fg="black", bg="#FFB6C1"
)
alerts_title_label.pack(pady=5)

alert_display = scrolledtext.ScrolledText(
    app, height=10, wrap=tk.WORD, bg="#FFDDDD", fg="red", font=("Consolas", 10)
)
alert_display.pack(padx=10, pady=5, fill=tk.BOTH)

stop_event = threading.Event()

# Start Monitoring
def start_monitoring():
    log_file_path = filedialog.askopenfilename(
        title="Select Firewall Log File", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not log_file_path:
        return
    stop_event.clear()
    log_display.delete("1.0", tk.END)
    alert_display.delete("1.0", tk.END)
    threading.Thread(
        target=monitor_firewall_log_ui,
        args=(log_file_path, log_display, alert_display, status_label, stop_event),
        daemon=True
    ).start()

def stop_monitoring():
    stop_event.set()
    status_label.config(text="Status: Not Monitoring", fg="white")

app.mainloop()
