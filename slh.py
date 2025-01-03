import os
import time
import re
import winsound
import json
import requests
import sys
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, Menu
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Get the base directory where the script or exe resides
if getattr(sys, 'frozen', False):  # Running as a PyInstaller bundle
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Constants
VERSION_NUMBER = "v0.0.3"
LOG_DIR = os.path.expanduser("~/Documents/EVE/logs/Gamelogs")
CONFIG_FILE = os.path.join(BASE_DIR, "settings.json")
CAPITAL_REGEX = r"\(combat\).*(Dreadnought|Titan)"
ALERT_SOUND_FILE = "alarm.wav"
DEFAULT_COOLDOWN_SECONDS = 90

# Global Variables
last_alert_timestamp = None
processed_lines = set()
monitoring_active = False
monitoring_started = False
webhook_enabled = False
webhook_url = ""
mention_everyone = False
mention_here = False
mention_role = False
mention_user = False
role_id = ""
user_id = ""
custom_message = "Capital ship detected!"
custom_message_enabled = False
custom_cooldown_seconds = DEFAULT_COOLDOWN_SECONDS

# Load and save config
def load_config():
    global webhook_enabled, webhook_url, mention_everyone, mention_here, mention_role, mention_user, role_id, user_id, custom_message, custom_message_enabled, custom_cooldown_seconds
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
            webhook_enabled = config.get("webhook_enabled", False)
            webhook_url = config.get("webhook_url", "")
            mention_everyone = config.get("mention_everyone", False)
            mention_here = config.get("mention_here", False)
            mention_role = config.get("mention_role", False)
            mention_user = config.get("mention_user", False)
            role_id = config.get("role_id", "")
            user_id = config.get("user_id", "")
            custom_message = config.get("custom_message", "Capital ship detected!")
            custom_message_enabled = config.get("custom_message_enabled", False)
            custom_cooldown_seconds = config.get("custom_cooldown_seconds", DEFAULT_COOLDOWN_SECONDS)

def save_config():
    config = {
        "webhook_enabled": webhook_enabled,
        "webhook_url": webhook_url,
        "mention_everyone": mention_everyone,
        "mention_here": mention_here,
        "mention_role": mention_role,
        "mention_user": mention_user,
        "role_id": role_id,
        "user_id": user_id,
        "custom_message": custom_message,
        "custom_message_enabled": custom_message_enabled,
        "custom_cooldown_seconds": custom_cooldown_seconds
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
                            time_since_last_alert = timestamp - last_alert_timestamp if last_alert_timestamp else None
                            if last_alert_timestamp and time_since_last_alert < custom_cooldown_seconds:
                                continue
                            send_discord_notification()
                            if audible_alert_enabled.get() and os.path.exists(ALERT_SOUND_FILE):
                                winsound.PlaySound(ALERT_SOUND_FILE, winsound.SND_FILENAME)
                            elif audible_alert_enabled.get():
                                winsound.MessageBeep()
                            last_alert_timestamp = timestamp
            except Exception as e:
                update_status(f"Error reading log file: {e}")

# Send notification to Discord webhook
def send_discord_notification():
    mentions = []
    if mention_everyone:
        mentions.append("@everyone")
    if mention_here:
        mentions.append("@here")
    if mention_role and role_id:
        mentions.append(f"<@&{role_id}>")
    if mention_user and user_id:
        mentions.append(f"<@{user_id}>")

    mention_text = " ".join(mentions)
    message = custom_message if custom_message_enabled else "Capital ship detected!"
    message = f"{mention_text} {message}" if mention_text else message

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
    update_status(f"Monitoring: {os.path.abspath(LOG_DIR)}")
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
    update_status("Stopped.")

# Update status label
def update_status(message):
    status_label.config(text=message)

# GUI Interface
def create_gui():
    global status_label, audible_alert_enabled
    def toggle_monitoring():
        if monitor_button["text"] == "Start Monitoring":
            start_monitoring()
            monitor_button["text"] = "Stop Monitoring"
        else:
            stop_monitoring()
            monitor_button["text"] = "Start Monitoring"

    def toggle_webhook():
        global webhook_enabled, webhook_url
        webhook_enabled = webhook_checkbox_var.get()
        webhook_url = webhook_entry.get()
        webhook_entry.config(state="normal" if webhook_enabled else "disabled")

    def toggle_entry_state(entry, checkbox_var):
        entry.config(state="normal" if checkbox_var.get() else "disabled")

    def save_settings():
        global webhook_enabled, webhook_url, mention_everyone, mention_here, mention_role, mention_user, role_id, user_id, custom_message, custom_message_enabled, custom_cooldown_seconds
        webhook_enabled = webhook_checkbox_var.get()
        webhook_url = webhook_entry.get()
        mention_everyone = mention_everyone_var.get()
        mention_here = mention_here_var.get()
        mention_role = mention_role_var.get()
        mention_user = mention_user_var.get()
        role_id = role_entry.get()
        user_id = user_entry.get()
        custom_message_enabled = custom_message_checkbox_var.get()
        custom_message = custom_message_entry.get()
        custom_cooldown_seconds = int(cooldown_spinbox.get())
        save_config()

    root = tk.Tk()
    root.title(f"Smartbomber's Little Helper - {VERSION_NUMBER}")
    root.resizable(False, False)

    # Main Frame
    frame = ttk.Frame(root, padding=10)
    frame.grid(row=0, column=0, sticky="nsew")

    # Main Settings Label
    ttk.Label(frame, text="Main Settings", font=("Arial", 10, "bold")).grid(row=0, column=0, columnspan=1, sticky="w")

    # Alert and Cooldown Settings
    audible_alert_enabled = tk.BooleanVar(value=True)
    ttk.Checkbutton(frame, text="Audible Alert", variable=audible_alert_enabled).grid(row=1, column=0, sticky="w", pady=(0, 0))
    ttk.Label(frame, text="Alert Cooldown (s): ").grid(row=1, column=1, sticky="w", pady=(0, 0))
    cooldown_spinbox = ttk.Spinbox(frame, from_=0, to=9999, width=6, increment=1)
    cooldown_spinbox.grid(row=1, column=1, sticky="e", pady=(0, 0))
    cooldown_spinbox.delete(0, "end")
    cooldown_spinbox.insert(0, str(custom_cooldown_seconds))

    # Discord Settings
    ttk.Label(frame, text="Discord Settings", font=("Arial", 10, "bold")).grid(row=2, column=0, columnspan=1, sticky="w", pady=(10, 5))

    # Webhook URL
    global webhook_checkbox_var, webhook_entry
    webhook_checkbox_var = tk.BooleanVar(value=webhook_enabled)
    ttk.Checkbutton(frame, text="Webhook: ", variable=webhook_checkbox_var, command=toggle_webhook).grid(row=3, column=0, sticky="w", pady=(0, 0))
    webhook_entry = ttk.Entry(frame, width=50)
    webhook_entry.grid(row=3, column=1, columnspan=1, sticky="we", pady=(0, 0))
    webhook_entry.insert(0, webhook_url)
    webhook_entry.config(state="normal" if webhook_enabled else "disabled")

    # Mentions
    mention_everyone_var = tk.BooleanVar(value=mention_everyone)
    ttk.Checkbutton(frame, text="@everyone", variable=mention_everyone_var).grid(row=4, column=0, sticky="w")

    mention_here_var = tk.BooleanVar(value=mention_here)
    ttk.Checkbutton(frame, text="@here", variable=mention_here_var).grid(row=4, column=1, sticky="w")

    mention_role_var = tk.BooleanVar(value=mention_role)
    role_check = ttk.Checkbutton(frame, text="@role (ID):", variable=mention_role_var, command=lambda: toggle_entry_state(role_entry, mention_role_var))
    role_check.grid(row=5, column=0, sticky="w")
    role_entry = ttk.Entry(frame, width=40)
    role_entry.grid(row=5, column=1, sticky="we")
    role_entry.insert(0, role_id)
    role_entry.config(state="normal" if mention_role else "disabled")

    mention_user_var = tk.BooleanVar(value=mention_user)
    user_check = ttk.Checkbutton(frame, text="@user (ID):", variable=mention_user_var, command=lambda: toggle_entry_state(user_entry, mention_user_var))
    user_check.grid(row=6, column=0, sticky="w")
    user_entry = ttk.Entry(frame, width=40)
    user_entry.grid(row=6, column=1, sticky="we")
    user_entry.insert(0, user_id)
    user_entry.config(state="normal" if mention_user else "disabled")

    # Custom Message
    custom_message_checkbox_var = tk.BooleanVar(value=custom_message_enabled)
    custom_message_check = ttk.Checkbutton(frame, text="Custom Message: ", variable=custom_message_checkbox_var, command=lambda: toggle_entry_state(custom_message_entry, custom_message_checkbox_var))
    custom_message_check.grid(row=7, column=0, sticky="w", pady=(0, 0))
    custom_message_entry = ttk.Entry(frame, width=50)
    custom_message_entry.grid(row=7, column=1, columnspan=1, sticky="we", pady=(0, 0))
    custom_message_entry.insert(0, custom_message)
    custom_message_entry.config(state="normal" if custom_message_enabled else "disabled")

    # Save Button
    save_button = ttk.Button(frame, text="Apply Settings", command=save_settings)
    save_button.grid(row=8, column=1, sticky="e", pady=10)

    # Start/Stop Monitoring Button
    global monitor_button
    monitor_button = ttk.Button(frame, text="Start Monitoring", command=toggle_monitoring)
    monitor_button.grid(row=8, column=0, sticky="w", pady=10)

    # Status Label
    global status_label
    status_label = ttk.Label(frame, text="Ready", relief="sunken", anchor="w")
    status_label.grid(row=9, column=0, columnspan=2, sticky="we", pady=(0, 0))

    root.mainloop()

if __name__ == "__main__":
    load_config()
    if os.path.exists(LOG_DIR):
        create_gui()
    else:
        print(f"Error: Log directory not found at {LOG_DIR}. Ensure EVE game logs are correctly configured.")
