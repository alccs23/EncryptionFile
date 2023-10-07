import tkinter as tk
from tkinter import simpledialog, messagebox
import subprocess
import os

# Function to validate the key format
def validate_key_format(key):
    return len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key)

# Function to convert text to hexadecimal and write in 32-bit chunks
def convert_text_to_hex(input_file, output_file):
    with open(input_file, 'r') as f:
        text = f.read()
    input_file_size = os.path.getsize(input_file)  # Get the size of the input file
    # Calculate the required padding length
    padding_length = 16 - ((len(text)) % 16)

    # Apply PKCS7 padding
    padded_text = text + chr(padding_length) * padding_length
    hex_data = padded_text.encode('utf-8').hex()  # Convert text to hexadecimal
    hex_chunks = [hex_data[i:i + 32] for i in range(0, len(hex_data), 32)]  # Split into 32-bit chunks

    with open(output_file, 'w') as f:
        f.write('\n'.join(hex_chunks))  # Write each chunk on a new line

# Function to convert hexadecimal data back to text and remove PKCS7 padding
def convert_hex_to_text(input_file, output_file):
    with open(input_file, 'r') as f:
        hex_data = f.read().replace('\n', '')  # Read the hexadecimal data from the input file

    # Convert hex data to bytes
    hex_bytes = bytes.fromhex(hex_data)

    # Determine the padding length by examining the last byte
    padding_length = hex_bytes[-1]

    # Remove the padding to get the original text
    text = hex_bytes[:-padding_length].decode('utf-8')

    with open(output_file, 'w') as f:
        f.write(text)  # Write the original text to the output file

# Function to run the C program with the specified mode
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
            if mode == "encrypt":
                convert_text_to_hex(input_file, "output.txt")  # Convert text to hexadecimal
                subprocess.run(["./main", mode, key, "output.txt", "output_encrypted.txt"])  # Use the converted file
                with open("output_encrypted.txt", 'r') as f:
                    hex_data = f.read().strip()
            
            if mode == "decrypt":
                # Call the main program again in decrypt mode to obtain the decrypted text
                subprocess.run(["./main", mode, key, input_file, "output_decrypted.txt"])
                convert_hex_to_text("output_decrypted.txt", "output_decrypted.txt")
                # Read the decrypted text from the output file
                with open("output_decrypted.txt", 'r') as f_decrypted:
                    decrypted_text = f_decrypted.read()
                
                messagebox.showinfo("Success", f"{mode.capitalize()}ion completed.\n Check output_decrypted.txt for your decrypted text!")
            else:
                messagebox.showinfo("Success", f"{mode.capitalize()}ion completed.\n Check output_encrypted.txt for your encrypted text!")
            
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
