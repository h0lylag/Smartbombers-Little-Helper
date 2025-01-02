import os
import time
import re
import winsound
import json
import requests
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, Menu
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Constants
LOG_DIR = os.path.expanduser("~/Documents/EVE/logs/Gamelogs")
CONFIG_FILE = "settings.json"
CAPITAL_REGEX = r"\(combat\).*(Dreadnought|Titan)"
ALERT_SOUND_FILE = "alarm.wav"
COOLDOWN_SECONDS = 90

# Global Variables
last_alert_timestamp = None
processed_lines = set()
monitoring_active = False
monitoring_started = False
webhook_enabled = False
webhook_url = ""

# Load and save config
def load_config():
    global webhook_enabled, webhook_url
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
            webhook_enabled = config.get("webhook_enabled", False)
            webhook_url = config.get("webhook_url", "")

def save_config():
    config = {
        "webhook_enabled": webhook_enabled,
        "webhook_url": webhook_url
    }
    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)

# Utility to parse timestamp from a log line
def parse_timestamp(line):
    match = re.match(r"\[\s*(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2})\s*\]", line)
    if match:
        dt = datetime.strptime(match.group(1), "%Y.%m.%d %H:%M:%S")
        return int(dt.timestamp())
    return None

# Event handler for log file changes
class CapitalLogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global last_alert_timestamp, monitoring_started
        if event.src_path.endswith(".txt") and monitoring_active:
            try:
                with open(event.src_path, "r", encoding="utf-8", errors="ignore") as file:
                    lines = file.readlines()

                    if not monitoring_started:
                        # On first start, update last_alert_timestamp to avoid stale alerts
                        for line in reversed(lines):
                            timestamp = parse_timestamp(line)
                            if timestamp and re.search(CAPITAL_REGEX, line):
                                last_alert_timestamp = timestamp
                                break
                        monitoring_started = True
                        return

                    for line in lines:
                        line_id = hash(line)  # Unique identifier for each log line

                        if line_id in processed_lines:
                            continue  # Skip already processed lines

                        processed_lines.add(line_id)  # Mark line as processed

                        timestamp = parse_timestamp(line)
                        if timestamp is None:
                            continue  # Skip lines without valid timestamps

                        if re.search(CAPITAL_REGEX, line):
                            if last_alert_timestamp is not None:
                                time_since_last_alert = timestamp - last_alert_timestamp
                                if time_since_last_alert < COOLDOWN_SECONDS:
                                    continue
                            if alert_var.get() and os.path.exists(ALERT_SOUND_FILE):
                                winsound.PlaySound(ALERT_SOUND_FILE, winsound.SND_FILENAME)
                            elif alert_var.get():
                                winsound.MessageBeep()
                            if webhook_enabled and webhook_url:
                                send_webhook_notification("Capital ship Detected!")
                            last_alert_timestamp = timestamp
            except Exception as e:
                update_status(f"Error reading log file: {e}")

# Send notification to Discord webhook
def send_webhook_notification(message):
    payload = {"content": message}
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        update_status("Webhook notification sent.")
    except Exception as e:
        update_status(f"Failed to send webhook: {e}")

# Start monitoring logs
def start_monitoring():
    global monitoring_active, monitoring_started, observer
    if monitoring_active:
        return
    monitoring_active = True
    monitoring_started = False
    update_status("Monitoring started.")
    event_handler = CapitalLogHandler()
    observer = Observer()
    observer.schedule(event_handler, LOG_DIR, recursive=False)
    observer.start()

# Stop monitoring logs
def stop_monitoring():
    global monitoring_active, monitoring_started, observer
    if not monitoring_active:
        return
    monitoring_active = False
    monitoring_started = False
    observer.stop()
    observer.join()
    update_status("Monitoring stopped.")

# Update status label
def update_status(message):
    status_label.config(text=message)

# GUI Interface
def create_gui():
    global status_label, alert_var
    def toggle_monitoring():
        if monitor_button["text"] == "Start Monitoring":
            start_monitoring()
            monitor_button["text"] = "Stop Monitoring"
        else:
            stop_monitoring()
            monitor_button["text"] = "Start Monitoring"

    def toggle_webhook():
        global webhook_enabled, webhook_url
        webhook_enabled = webhook_var.get()
        webhook_url = webhook_entry.get()
        webhook_entry.config(state="normal" if webhook_enabled else "disabled")

    def save_settings():
        global webhook_enabled, webhook_url
        webhook_enabled = webhook_var.get()
        webhook_url = webhook_entry.get()
        save_config()

    root = tk.Tk()
    root.title("Smartbombers Little Helper - v0.0.2")
    root.resizable(False, False)

    # Main Frame
    frame = ttk.Frame(root, padding=10)
    frame.grid(row=0, column=0, sticky="nsew")

    # Alert Checkbox
    alert_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(frame, text="Audible Capital Spawn Alert", variable=alert_var).grid(row=0, column=0, sticky="w")

    # Webhook Checkbox and Entry
    global webhook_var, webhook_entry
    webhook_var = tk.BooleanVar(value=webhook_enabled)
    ttk.Checkbutton(frame, text="Discord Webhook", variable=webhook_var, command=toggle_webhook).grid(row=1, column=0, sticky="w")

    webhook_entry = ttk.Entry(frame, width=40)
    webhook_entry.grid(row=1, column=1, columnspan=2, sticky="we", pady=5)
    webhook_entry.insert(0, webhook_url)
    webhook_entry.config(state="normal" if webhook_enabled else "disabled")

    # Save Button
    save_button = ttk.Button(frame, text="Apply Settings", command=save_settings)
    save_button.grid(row=3, column=2, sticky="w", pady=10)

    # Start/Stop Monitoring Button
    global monitor_button
    monitor_button = ttk.Button(frame, text="Start Monitoring", command=toggle_monitoring)
    monitor_button.grid(row=3, column=0, sticky="w", pady=10)

    # Status Label
    status_label = ttk.Label(frame, text="Ready", relief="sunken", anchor="w")
    status_label.grid(row=4, column=0, columnspan=3, sticky="we", pady=5)

    root.mainloop()

if __name__ == "__main__":
    load_config()
    if os.path.exists(LOG_DIR):
        create_gui()
    else:
        print(f"Error: Log directory not found at {LOG_DIR}. Ensure EVE game logs are correctly configured.")
