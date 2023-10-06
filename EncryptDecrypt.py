import tkinter as tk
from tkinter import simpledialog, messagebox
import subprocess
import os

# Function to validate the key format
def validate_key_format(key):
    return len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key)

# Function to run the C program with the specified mode
def run_c_program(mode):
    input_file = entry_input_file.get()
    key = entry_key.get()

    error_message = ""

    if not key or not input_file:
        error_message = "Input file name and key are required."
    elif not validate_key_format(key):
        error_message = "Invalid key format. Key must be 32-character hexadecimal."
    elif not os.path.exists(input_file):
        error_message = "Input file does not exist."

    if error_message:
        messagebox.showerror("Error", error_message)
    else:
        try:
            subprocess.run(["./main", mode, key, input_file, "output.txt"])
            messagebox.showinfo("Success", f"{mode.capitalize()}ion completed. Check 'output.txt' for results.")
            root.destroy()  # Close the Tkinter window after a successful run
        except FileNotFoundError:
            messagebox.showerror("Error", "The C program 'main' was not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

# Create a Tkinter window
root = tk.Tk()
root.title("AES Encryption")

# Key entry field
key_label = tk.Label(root, text="Enter the encryption key (32-character hex):")
key_label.pack()
entry_key = tk.Entry(root)
entry_key.pack()

# Input file entry field
input_file_label = tk.Label(root, text="Enter the input file name:")
input_file_label.pack()
entry_input_file = tk.Entry(root)
entry_input_file.pack()

# Error message label
error_message_label = tk.Label(root, text="", fg="red")
error_message_label.pack()

# Function to handle mode selection for encryption
def encrypt_mode():
    run_c_program("encrypt")

# Function to handle mode selection for decryption
def decrypt_mode():
    run_c_program("decrypt")

# Buttons for mode selection
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_mode)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_mode)
decrypt_button.pack()

# Start the Tkinter main loop
root.mainloop()
