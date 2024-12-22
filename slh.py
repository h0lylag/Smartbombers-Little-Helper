import os
import time
import re
import winsound
import json
import tkinter as tk
from tkinter import ttk, messagebox, Menu, StringVar, Listbox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Constants
LOG_DIR = os.path.expanduser("~/Documents/EVE/logs/Gamelogs")
CONFIG_FILE = "settings.json"
DREAD_REGEX = r"\(combat\).*Angel Dreadnought"
ALERT_SOUND_FILE = "alarm-2s.wav"
COOLDOWN_SECONDS = 45
last_alert_time = 0
monitoring_active = False
webhook_enabled = False
webhook_url = ""
config_data = {"groups": []}

# Load and save config
def load_config():
    global webhook_enabled, webhook_url, config_data
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
            webhook_enabled = config.get("webhook_enabled", False)
            webhook_url = config.get("webhook_url", "")
            config_data["groups"] = config.get("groups", [])

def save_config():
    global config_data
    config = {
        "webhook_enabled": webhook_enabled,
        "webhook_url": webhook_url,
        "groups": config_data["groups"]
    }
    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)
    print("Settings saved.")

# Event handler for log file changes
class DreadLogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global last_alert_time
        if event.src_path.endswith(".txt") and monitoring_active:
            current_time = time.time()
            if current_time - last_alert_time < COOLDOWN_SECONDS:
                return  # Skip if within cooldown
            with open(event.src_path, "r", encoding="utf-8", errors="ignore") as file:
                lines = file.readlines()
                for line in reversed(lines):
                    if re.search(DREAD_REGEX, line):
                        print("Dreadnought detected! Alerting...")
                        if os.path.exists(ALERT_SOUND_FILE):
                            winsound.PlaySound(ALERT_SOUND_FILE, winsound.SND_FILENAME)
                        else:
                            print(f"Warning: {ALERT_SOUND_FILE} not found. Beep fallback.")
                            winsound.MessageBeep()
                        if webhook_enabled and webhook_url:
                            send_webhook_notification("Dreadnought Detected!")
                        last_alert_time = current_time
                        return

# Send notification to Discord webhook
def send_webhook_notification(message):
    import requests
    payload = {"content": message}
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Webhook notification sent.")
    except Exception as e:
        print(f"Failed to send webhook: {e}")

# Start monitoring logs
def start_monitoring():
    global monitoring_active, observer
    if monitoring_active:
        return
    monitoring_active = True
    print("Monitoring started.")
    event_handler = DreadLogHandler()
    observer = Observer()
    observer.schedule(event_handler, LOG_DIR, recursive=False)
    observer.start()

# Stop monitoring logs
def stop_monitoring():
    global monitoring_active, observer
    if not monitoring_active:
        return
    monitoring_active = False
    observer.stop()
    observer.join()
    print("Monitoring stopped.")

# GUI Interface
def create_gui():
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

    def open_groups():
        group_window = tk.Toplevel(root)
        group_window.title("Groups Management")
        group_window.geometry("800x400")

        group_listbox = Listbox(group_window)
        group_listbox.pack(side="left", fill="y", padx=5, pady=5)

        group_details_frame = ttk.Frame(group_window, padding=10)
        group_details_frame.pack(side="right", fill="both", expand=True)

        ttk.Label(group_details_frame, text="Group Name:").grid(row=0, column=0, sticky="w")
        group_name_var = StringVar()
        group_name_entry = ttk.Entry(group_details_frame, textvariable=group_name_var, width=40)
        group_name_entry.grid(row=0, column=1, pady=5)

        ttk.Label(group_details_frame, text="Sniper Name:").grid(row=1, column=0, sticky="w")
        sniper_name_var = StringVar()
        sniper_name_entry = ttk.Entry(group_details_frame, textvariable=sniper_name_var, width=40)
        sniper_name_entry.grid(row=1, column=1, pady=5)

        ttk.Label(group_details_frame, text="Smartbombing Ships (one per line):").grid(row=2, column=0, sticky="nw")
        ships_text = tk.Text(group_details_frame, height=8, width=40)
        ships_text.grid(row=2, column=1, pady=5)

        def load_group(event):
            selected_index = group_listbox.curselection()
            if selected_index:
                group = config_data["groups"][selected_index[0]]
                group_name_var.set(group["group_name"])
                sniper_name_var.set(group["sniper_name"])
                ships_text.delete("1.0", "end")
                ships_text.insert("1.0", "\n".join(group["smartbombing_ships"]))

        def save_group():
            selected_index = group_listbox.curselection()
            group = {
                "group_name": group_name_var.get(),
                "sniper_name": sniper_name_var.get(),
                "smartbombing_ships": ships_text.get("1.0", "end").strip().splitlines()
            }
            if selected_index:
                config_data["groups"][selected_index[0]] = group
            else:
                config_data["groups"].append(group)
            save_config()
            refresh_group_list()

        def delete_group():
            selected_index = group_listbox.curselection()
            if selected_index:
                del config_data["groups"][selected_index[0]]
                save_config()
                refresh_group_list()

        def refresh_group_list():
            group_listbox.delete(0, "end")
            for group in config_data["groups"]:
                group_listbox.insert("end", group["group_name"])

        ttk.Button(group_details_frame, text="Save Group", command=save_group).grid(row=3, column=0, pady=5)
        ttk.Button(group_details_frame, text="Delete Group", command=delete_group).grid(row=3, column=1, pady=5)

        group_listbox.bind("<<ListboxSelect>>", load_group)
        refresh_group_list()

    def show_about():
        about_text = (
            "Smartbombers Little Helper\n"
            "Version: 0.01\n\n"
            "A tool for detecting dreadnoughts in EVE Online logs and alerting you."
        )
        messagebox.showinfo("About", about_text)

    root = tk.Tk()
    root.title("Smartbombers Little Helper")
    root.resizable(False, False)

    # Menu
    menubar = Menu(root)
    menubar.add_command(label="Groups", command=open_groups)
    menubar.add_command(label="About", command=show_about)
    root.config(menu=menubar)

    # Main Frame
    frame = ttk.Frame(root, padding=10)
    frame.grid(row=0, column=0, sticky="nsew")

    # Alert Checkbox
    alert_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(frame, text="Dread Spawn Alert", variable=alert_var).grid(row=0, column=0, sticky="w")

    # Webhook Checkbox and Entry
    global webhook_var, webhook_entry
    webhook_var = tk.BooleanVar(value=webhook_enabled)
    ttk.Checkbutton(frame, text="Discord Webhook", variable=webhook_var, command=toggle_webhook).grid(row=1, column=0, sticky="w")

    webhook_entry = ttk.Entry(frame, width=40)
    webhook_entry.grid(row=1, column=1, columnspan=2, sticky="we", pady=5)
    webhook_entry.insert(0, webhook_url)
    webhook_entry.config(state="normal" if webhook_enabled else "disabled")

    # Save Button
    save_button = ttk.Button(frame, text="Save Settings", command=save_settings)
    save_button.grid(row=3, column=2, sticky="w", pady=10)

    # Start/Stop Monitoring Button
    global monitor_button
    monitor_button = ttk.Button(frame, text="Start Monitoring", command=toggle_monitoring)
    monitor_button.grid(row=3, column=0, sticky="w", pady=10)

    root.mainloop()

if __name__ == "__main__":
    load_config()
    if os.path.exists(LOG_DIR):
        create_gui()
    else:
        print(f"Error: Log directory not found at {LOG_DIR}. Ensure EVE game logs are correctly configured.")
