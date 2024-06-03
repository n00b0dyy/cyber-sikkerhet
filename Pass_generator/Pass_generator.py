"""
Password Generator
Programming Language: Python
Difficulty (1 to 10): 3

This program allows users to generate random passwords of specified length and save them to a file. It provides options for customizing password generation and supports multiple password generation at once. The generated passwords are hashed using SHA-256 before being saved to the specified file. Users can copy the generated passwords to the clipboard for easy usage.

Functions:
- generate_password(length, custom_characters=None):
    Generates a random password of the specified length using custom characters if provided. If no custom characters are provided, it uses a default set of characters, including uppercase and lowercase letters, digits, and punctuation.
- hash_password(password):
    Hashes the given password using the SHA-256 algorithm and returns the hexadecimal digest.
- save_hashed_password_to_file(password, filename):
    Saves the hashed password to a specified file. If the file already exists, it prompts the user to confirm overwriting. The function returns the absolute path of the saved file.
- password_strength(password):
    Evaluates and returns the strength of the password based on its length, categorizing it as "Weak", "Moderate", or "Strong".
- copy_to_clipboard(password):
    Copies the given password to the clipboard and displays a message confirming the action.
- generate_multiple_passwords(length, count, custom_characters=None):
    Generates multiple passwords of the specified length. The number of passwords generated is limited by a predefined maximum count.
- save_hashed_passwords_with_category(passwords, category, filename):
    Saves hashed passwords with the specified category to a file. If the file already exists, it prompts the user to confirm overwriting and allows clearing the existing file. The function returns the absolute path of the saved file.
- generate_passwords_and_save():
    Validates user input for password length, number of passwords, and filename. Generates the specified number of passwords, hashes them using SHA-256, and saves them to the specified file along with their categories. Displays the strengths of each generated password.

Usage:
1. Enter the desired password length, number of passwords, and filename.
2. Optionally, specify custom characters for password generation.
3. Select a category from the provided options.
4. Click on the "Generate and Save Passwords" button.
5. Generated passwords are hashed with SHA-256 and saved to the specified file, and their strengths are displayed.

Dependencies:
- random: Python module for generating pseudo-random numbers and selecting random elements from a sequence.
- string: A module that contains sets of fixed characters such as letters of the alphabet, numbers, and special characters.
- hashlib: Provides implementations of various cryptographic hash function algorithms, such as SHA-1, SHA-256, and MD5, enabling the creation of hashes for input data.
- os: A Python module that provides an interface to various operating system-dependent functions, such as file operations and process control.
- tkinter: Python library for creating graphical user interfaces (GUIs).
- filedialog from tkinter: A module that provides dialog boxes for selecting and saving files.
- messagebox from tkinter: A module that provides functions for displaying messages and message dialogs.
- pyperclip: Python module for copying and pasting text to/from the system clipboard.

Constants:
- MAX_PASSWORD_LENGTH: Maximum allowed length for generated passwords.
- MAX_PASSWORD_COUNT: Maximum number of passwords that can be generated at once.
"""

# Importing required modules
import random
import string
import os
import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import pyperclip  # Module for copying to clipboard

# Constants
MAX_PASSWORD_LENGTH = 40
MAX_PASSWORD_COUNT = 10

# Function to generate a random password
def generate_password(length, custom_characters=None):
    """Generates a random password of specified length using custom characters if provided."""
    if custom_characters:
        characters = custom_characters
    else:
        characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.sample(characters, k=min(length, MAX_PASSWORD_LENGTH)))
    return password

# Function to hash a password using SHA-256
def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# Function to save the hashed password to a file
def save_hashed_password_to_file(password, filename):
    """Saves the hashed password to a file."""
    hashed_password = hash_password(password)
    if os.path.exists(filename):
        choice = messagebox.askyesno("File Exists", "File already exists. Do you want to overwrite it?")
        if not choice:
            filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    with open(filename, 'w') as file:
        file.write(hashed_password)
    full_path = os.path.abspath(filename)
    return full_path

# Function to verify password strength
def password_strength(password):
    """Verifies the strength of the password."""
    if len(password) < 8:
        return "Weak"
    elif len(password) < 12:
        return "Moderate"
    else:
        return "Strong"

# Function to copy password to clipboard
def copy_to_clipboard(password):
    """Copies the password to the clipboard."""
    pyperclip.copy(password)
    messagebox.showinfo("Copied", "Password copied to clipboard.")

# Function to generate multiple passwords
def generate_multiple_passwords(length, count, custom_characters=None):
    """Generates multiple passwords."""
    passwords = [generate_password(length, custom_characters) for _ in range(min(count, MAX_PASSWORD_COUNT))]
    return passwords

# Function to save hashed passwords to a file with category
def save_hashed_passwords_with_category(passwords, category, filename):
    """Saves hashed passwords with category to a file."""
    if os.path.exists(filename):
        choice = messagebox.askyesno("File Exists", "File already exists. Do you want to overwrite it and remove previous passwords?")
        if not choice:
            return
        else:
            with open(filename, 'w') as file:
                pass  # Clearing the file by not writing anything
    with open(filename, 'a') as file:
        for password in passwords:
            hashed_password = hash_password(password)
            file.write(f"category: {category} ||| password: {hashed_password}\n")
    full_path = os.path.abspath(filename)
    return full_path

# Function to generate passwords and save them
def generate_passwords_and_save():
    """Generates passwords and saves their hashed versions to a file."""
    length = length_entry.get()
    try:
        length = int(length)
        if length <= 0 or length > MAX_PASSWORD_LENGTH:
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", f"Please enter a valid positive integer less than or equal to {MAX_PASSWORD_LENGTH} for password length.")
        return

    count = count_entry.get()
    try:
        count = int(count)
        if count <= 0 or count > MAX_PASSWORD_COUNT:
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", f"Please enter a valid positive integer less than or equal to {MAX_PASSWORD_COUNT} for number of passwords.")
        return

    category = category_var.get()
    custom_characters = custom_characters_entry.get()  # Get custom characters

    passwords = generate_multiple_passwords(length, count, custom_characters)  # Pass custom characters to the generator

    filename = filename_entry.get()
    if not filename:
        messagebox.showerror("Error", "Please enter a filename.")
        return
    saved_path = save_hashed_passwords_with_category(passwords, category, filename)
    if not saved_path:
        return

    saved_password_label.config(text="Passwords saved at: " + saved_path)
    # Clear previous password strength labels
    for widget in strength_frame.winfo_children():
        widget.destroy()

    # Display password strengths
    for i, password in enumerate(passwords, start=1):
        strength = password_strength(password)
        strength_label = tk.Label(strength_frame, text=f"Password {i} Strength: {strength}")
        strength_label.pack()
    copy_to_clipboard(password)


# Function to create the main GUI window
def main():
    global length_entry, count_entry, filename_entry, saved_password_label, strength_frame, custom_characters_entry, category_var

    root = tk.Tk()
    root.title("Password Generator")

    length_label = tk.Label(root, text="Password Length:")
    length_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    length_entry = tk.Entry(root)
    length_entry.grid(row=0, column=1, padx=5, pady=5)

    count_label = tk.Label(root, text="Number of Passwords:")
    count_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    count_entry = tk.Entry(root)
    count_entry.grid(row=1, column=1, padx=5, pady=5)

    filename_label = tk.Label(root, text="Filename to save:")
    filename_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

    filename_entry = tk.Entry(root)
    filename_entry.grid(row=2, column=1, padx=5, pady=5)

    category_label = tk.Label(root, text="Category:")
    category_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

    categories = ["Banking", "Social Media", "Email", "Other"]
    category_var = tk.StringVar(root)
    category_var.set(categories[0])  # Default value
    category_option_menu = tk.OptionMenu(root, category_var, *categories)
    category_option_menu.grid(row=3, column=1, padx=5, pady=5)

    custom_characters_label = tk.Label(root, text="Custom Characters:")
    custom_characters_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")  
    custom_characters_entry = tk.Entry(root)
    custom_characters_entry.grid(row=4, column=1, padx=5, pady=5)


    generate_button = tk.Button(root, text="Generate and Save Passwords", command=generate_passwords_and_save)
    generate_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    saved_password_label = tk.Label(root, text="")
    saved_password_label.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

    strength_frame = tk.Frame(root)
    strength_frame.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
