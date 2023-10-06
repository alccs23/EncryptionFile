# AES Encryption/Decryption Program (WIP)

This program provides a user-friendly interface for encrypting and decrypting data using the Advanced Encryption Standard (AES-128 specfically) algorithm. It combines a C-based encryption/decryption core with a Python-based graphical user interface (GUI) for ease of use.

## Getting Started

Follow the steps below to set up and use the AES encryption/decryption program.

### Prerequisites

Before using the program, make sure you have the following prerequisites installed:

- [Python](https://www.python.org/downloads/) (for the GUI)
- [GCC](https://gcc.gnu.org/) (for compiling the C code)

### Installation

1. Clone or download this GitHub repository to your local machine.

   ```bash
   git clone https://github.com/yourusername/your-repository.git

### Procedure For Using the Program:

1. Compile the C code by navigating to the directory containing the C source files and running the following command:
   ```bash
   gcc -o main main.c aes_encryption.c aes_utils.c

2. Run the Python script for the program by executing the following command in your terminal:
   ```bash
   python EncryptDecrypt.py
   ```
   
   a. The GUI window should appear, allowing you to perform the following actions:
      * Enter the 32-character encryption key (in hexadecimal format).
      * Enter the input file name.
      * Choose between encryption and decryption modes.

  
   b. Follow the on-screen instructions to proceed with encryption or decryption.



   c. After running the program with valid inputs, it will perform encryption or decryption as selected and display a success message or an error message if something goes wrong.


## Contributing

Contributions are welcome! If you have any improvements, bug fixes, or new features to suggest, please feel free to open an issue or create a pull request.

## License

This project is licensed under the MIT License.

## Acknowledgments
This page was an enormous resource in the creation of this project: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

This page also made sure that my algorithm was correct: https://www.cryptool.org/en/cto/aes-step-by-step

