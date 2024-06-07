
"""
Pomodoro Timer Application with Encryption and Notification Features

This Python script implements a Pomodoro timer with functionality for sound notifications, 
encrypted settings and session management, and a graphical user interface (GUI) using the 
Tkinter library. The script includes functions for encryption and decryption of settings 
and session data, sound notifications, and UI handling. You are able to change timer values in settings.

Modules used:
- time: for time-related functions
- csv: for logging session data
- tkinter: for GUI elements
- math: for mathematical operations
- winsound: for playing sound notifications (Windows only)
- json: for handling JSON data
- plyer: for desktop notifications
- cryptography.fernet: for encryption and decryption

Constants:
- Color constants for UI elements
- Timer settings
- File paths for settings, session, log, and encryption key files
"""

import time
import csv
from tkinter import *
import math
import winsound
import json
from plyer import notification
import cryptography
from cryptography.fernet import Fernet

# ---------------------------- CONSTANTS ------------------------------- #
PINK = "#e2979c"
RED = "#e7305b"
GREEN = "#9bdeac"
YELLOW = "#f7f5dd"
FONT_NAME = "Courier"
WORK_MIN = 25
SHORT_BREAK_MIN = 5
LONG_BREAK_MIN = 20
SETTING_FILE = "insert your path\\settings_pomodoro.json"
SESSION_FILE = "insert your path\\session.json"
LOG_FILE = "insert your path\\session_log.csv"
KEY_FILE = "insert your path\\secret.key"
SETTINGS_FILE_ENCRYPTED = "insert your path\\settings_pomodoro_encrypted.json"

# Global variables to store the current countdown timer and repetitions
current_timer = None
reps = 0
session_count = 0

#----------------------------- CRYPTOGRAPHY ----------------------------#

def generate_key():
    """
    Generates a new encryption key and saves it to the key file.
    """
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

def load_key():
    """
    Loads the encryption key from the key file. Generates a new key if the file does not exist.
    """
    try:
        return open(KEY_FILE, 'rb').read()
    except FileNotFoundError:
        generate_key()
        return open(KEY_FILE, 'rb').read()

def encrypt_data(data):
    """
    Encrypts the given data using the Fernet symmetric encryption.
    
    Args:
        data (str): The data to be encrypted.
    
    Returns:
        bytes: The encrypted data.
    """
    key = load_key()
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data):
    """
    Decrypts the given encrypted data using the Fernet symmetric encryption.
    
    Args:
        encrypted_data (bytes): The data to be decrypted.
    
    Returns:
        str: The decrypted data.
    """
    key = load_key()
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data
    except cryptography.fernet.InvalidToken:
        print("Invalid token - unable to decrypt data.")
        return None

#------------------------------ SOUND ----------------------------------#

def play_sound():
    """
    Plays a beep sound notification.
    """
    frequency = 2500  # Set Frequency To 2500 Hertz
    duration = 1000   # Set Duration To 1000 ms == 1 second
    winsound.Beep(frequency, duration)

def notify(title, message):
    """
    Sends a desktop notification.
    
    Args:
        title (str): The title of the notification.
        message (str): The message content of the notification.
    """
    notification.notify(
        title=title,
        message=message,
        app_name='Pomodoro Timer',
        timeout=5
    )

# ---------------------------- SETTINGS HANDLING ------------------------------- #

def save_settings():
    """
    Saves the current timer settings to an encrypted JSON file.
    """
    settings = {
        "WORK_MIN": WORK_MIN,
        "SHORT_BREAK_MIN": SHORT_BREAK_MIN,
        "LONG_BREAK_MIN": LONG_BREAK_MIN
    }
    encrypted_settings = encrypt_data(json.dumps(settings))
    with open(SETTINGS_FILE_ENCRYPTED, "wb") as file:
        file.write(encrypted_settings)

def load_settings():
    """
    Loads the timer settings from the encrypted JSON file.
    """
    global WORK_MIN, SHORT_BREAK_MIN, LONG_BREAK_MIN
    try:
        with open(SETTINGS_FILE_ENCRYPTED, "rb") as file:
            encrypted_settings = file.read()
            decrypted_settings = decrypt_data(encrypted_settings)
            if decrypted_settings:
                settings = json.loads(decrypted_settings)
                WORK_MIN = settings.get("WORK_MIN", 25)
                SHORT_BREAK_MIN = settings.get("SHORT_BREAK_MIN", 5)
                LONG_BREAK_MIN = settings.get("LONG_BREAK_MIN", 20)
    except FileNotFoundError:
        generate_key()
    except json.JSONDecodeError:
        pass

load_settings()

# ---------------------------- SESSION HANDLING ------------------------------- #

def save_session():
    """
    Saves the current session count to an encrypted JSON file.
    """
    session = {"session_count": session_count}
    encrypted_session = encrypt_data(json.dumps(session))
    with open(SESSION_FILE, 'wb') as file:
        file.write(encrypted_session)

def load_session():
    """
    Loads the session count from the encrypted JSON file.
    """
    global session_count
    try:
        with open(SESSION_FILE, 'rb') as file:
            encrypted_session = file.read()
            decrypted_session = decrypt_data(encrypted_session)
            if decrypted_session:
                session = json.loads(decrypted_session)
                session_count = session.get("session_count", 0)
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        pass

load_session()

# ---------------------------- TIMER RESET ------------------------------- #
def reset_timer():
    """
    Resets the current timer, repetitions, and UI elements.
    """
    global current_timer
    global reps
    # Stop the current timer if it's running
    if current_timer is not None:
        window.after_cancel(current_timer)
    reps = 0
    # Reset the UI elements
    if title_label:
        title_label.config(text="Timer", fg=GREEN)
    if canvas:
        canvas.itemconfig(timer_text, text="00:00")
    # Re-enable the start button
    button_start.config(state=NORMAL)

# ---------------------------- TIMER MECHANISM ------------------------------- #
def start_timer():
    """
    Starts the Pomodoro timer and manages the work/break cycles.
    """
    global reps
    global current_timer

    # Stop the current timer if it's running
    if current_timer is not None:
        window.after_cancel(current_timer)
    
    reps += 1
    start_time = time.strftime("%Y-%m-%d %H:%M:%S")

    work_sec = WORK_MIN * 60
    short_break_sec = SHORT_BREAK_MIN * 60
    long_break_sec = LONG_BREAK_MIN * 60

    if reps % 8 == 0:
        count_down(long_break_sec)
        title_label.config(text="Break", fg=RED)
        notify("Pomodoro Timer", "Time for a long break!")
        log_session(start_time, time.strftime("%Y-%m-%d %H:%M:%S"), "Long Break")
    elif reps % 2 == 0:
        count_down(short_break_sec)
        title_label.config(text="Break", fg=PINK)
        notify("Pomodoro Timer", "Time for a short break!")
        log_session(start_time, time.strftime("%Y-%m-%d %H:%M:%S"), "Short Break")
    else:
        count_down(work_sec)
        title_label.config(text="Work", fg=GREEN)
        notify("Pomodoro Timer", "Time to work!")
        log_session(start_time, time.strftime("%Y-%m-%d %H:%M:%S"), "Work")
    button_start.config(state=DISABLED)

# ---------------------------- COUNTDOWN MECHANISM ------------------------------- #
def count_down(count):
    """
    Manages the countdown mechanism and updates the timer display.
    
    Args:
        count (int): The countdown time in seconds.
    """
    global current_timer
    count_min = math.floor(count // 60)
    count_sec = math.floor(count % 60)
    canvas.itemconfig(timer_text, text=f"{count_min:02d}:{count_sec:02d}")
    if count > 0:
        current_timer = window.after(1000, count_down, count - 1)
    else:
        play_sound()
        update_stats()
        # When countdown is complete, start the next timer
        start_timer()

# ---------------------------- LOGGING SESSION ------------------------------- #
def log_session(start_time, end_time, session_type):
    """
    Logs the session details to a CSV file.
    
    Args:
        start_time (str): The start time of the session.
        end_time (str): The end time of the session.
        session_type (str): The type of the session (e.g., Work, Short Break, Long Break).
    """
    with open(LOG_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([start_time, end_time, session_type])

# ---------------------------- UI SETUP ------------------------------- #
window = Tk()
window.title("Pomodoro")
window.config(padx=100, pady=50, bg=YELLOW)

title_label = Label(text="Timer", font=(FONT_NAME, 35, "bold"), fg=GREEN, bg=YELLOW)
title_label.grid(column=1, row=0)

button_start = Button(window, text="Start", font=(FONT_NAME, 16, "bold"), command=start_timer)
button_start.grid(column=0, row=2)

button_reset = Button(window, text="Reset", font=(FONT_NAME, 16, "bold"), command=reset_timer)
button_reset.grid(column=2, row=2)

canvas = Canvas(window, width=200, height=224, bg=YELLOW, highlightthickness=0)
try:
    tomato_img = PhotoImage(file="Pomodoro_timer/tomato.png")
except Exception as e:
    tomato_img = None
    print(f"Error loading image: {e}")

if tomato_img:
    canvas.create_image(100, 112, image=tomato_img)
else:
    canvas.create_text(100, 112, text="No Image", fill="white", font=(FONT_NAME, 35, "bold"))

timer_text = canvas.create_text(100, 130, text="00:00", fill="white", font=(FONT_NAME, 35, "bold"))
canvas.grid(column=1, row=1)

def on_closing():
    """
    Handles the window closing event, saves the session, and closes the application.
    """
    if current_timer is not None:
        window.after_cancel(current_timer)
    save_session()
    window.destroy()

window.protocol("WM_DELETE_WINDOW", on_closing)

#------------------------------ SESSION STATS ------------------------------------#
def update_stats():
    """
    Updates the session count in the UI.
    """
    global session_count
    session_count += 1
    stats_label.config(text=f"Sessions: {session_count}")
    stats_label.grid(row=3, column=1)
stats_label = Label(window, text="Sessions: 0", font=(FONT_NAME, 12), fg=GREEN, bg=YELLOW)

#----------------------- USER INTERFACE --------------------------#
def open_settings_window():
    """
    Opens a new window for editing timer settings.
    """
    def save_new_settings():
        """
        Saves the new settings entered by the user and updates the global settings.
        """
        global WORK_MIN, SHORT_BREAK_MIN, LONG_BREAK_MIN, PINK, RED, GREEN, YELLOW
        try:
            WORK_MIN = int(entry_work.get())
            SHORT_BREAK_MIN = int(entry_short_break.get())
            LONG_BREAK_MIN = int(entry_long_break.get())
            if WORK_MIN <= 0 or SHORT_BREAK_MIN <= 0 or LONG_BREAK_MIN <= 0:
                raise ValueError
            save_settings()
            settings_window.destroy()
        except ValueError:
            error_label.config(text="Please enter positive integers for all time values.")

    settings_window = Toplevel(window)
    settings_window.title("Settings")
    settings_window.config(padx=20, pady=20, bg=YELLOW)

    Label(settings_window, text="Work Time (min)", bg=YELLOW).grid(row=0, column=0)
    Label(settings_window, text="Short Break (min)", bg=YELLOW).grid(row=1, column=0)
    Label(settings_window, text="Long Break (min)", bg=YELLOW).grid(row=2, column=0)


    entry_work = Entry(settings_window)
    entry_work.grid(row=0, column=1)
    entry_work.insert(END, str(WORK_MIN))

    entry_short_break = Entry(settings_window)
    entry_short_break.grid(row=1, column=1)
    entry_short_break.insert(END, str(SHORT_BREAK_MIN))

    entry_long_break = Entry(settings_window)
    entry_long_break.grid(row=2, column=1)
    entry_long_break.insert(END, str(LONG_BREAK_MIN))


    Button(settings_window, text="Save", command=save_new_settings).grid(row=7, column=0, columnspan=2)
    error_label = Label(settings_window, text="", fg="red", bg=YELLOW)
    error_label.grid(row=8, column=0, columnspan=2)

menu_bar = Menu(window)
window.config(menu=menu_bar)
settings_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Settings", menu=settings_menu)
settings_menu.add_command(label="Edit", command=open_settings_window)

window.mainloop()
save_settings()
