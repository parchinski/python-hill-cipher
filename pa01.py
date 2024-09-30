#!/usr/bin/env python3
"""============================================================================
| Assignment: pa01 - Encrypting a plaintext file using the Hill cipher
|
| Author: Bryant Parchinski
| Language: python
| To Compile: source venv/bin/activate && pip install numpy
|
| To Execute: python3 pa01.py kX.txt pX.txt
| where kX.txt is the keytext file
| and pX.txt is plaintext file
| Note:
|       All input files are simple 8 bit ASCII input
|       All execute commands above have been tested on Eustis
|
| Class: CIS3360 - Security in Computing - Fall 2024
| Instructor: McAlpin
| Due Date: 07/29/24 
+==========================================================================="""

import sys
import numpy as np
import string

def read_key_file(key_filename):
    """
    Reads the key matrix from the given key file.

    The key file format:
    - The first line contains an integer N (2 <= N <= 9), the size of the matrix.
    - The next N lines contain N integers each, representing the matrix in row-major order.
    """
    try:
        with open(key_filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            if not lines:
                sys.exit("Error: Key file is empty.")

            # Read matrix size
            size_line = lines[0].strip()
            if not size_line.isdigit():
                sys.exit("Error: First line of key file must be an integer representing matrix size.")
            size = int(size_line)
            if size < 2 or size > 9:
                sys.exit("Error: Matrix size must be between 2 and 9.")

            # Read matrix entries
            if len(lines) < size + 1:
                sys.exit(f"Error: Key file must contain {size} rows of {size} integers each.")

            matrix = []
            for i in range(1, size + 1):
                row = lines[i].strip().split()
                if len(row) != size:
                    sys.exit(f"Error: Row {i} in key file does not contain {size} integers.")
                matrix_row = []
                for num_str in row:
                    if not num_str.lstrip('-').isdigit():
                        sys.exit(f"Error: Invalid integer '{num_str}' in key matrix.")
                    num = int(num_str)
                    matrix_row.append(num)
                matrix.append(matrix_row)

            key_matrix = np.array(matrix)
            return key_matrix

    except FileNotFoundError:
        sys.exit(f"Error: Key file '{key_filename}' not found.")
    except Exception as e:
        sys.exit(f"Error reading key file: {e}")

def read_plaintext_file(plaintext_filename):
    """
    Reads and sanitizes the plaintext from the given file.

    Sanitization involves:
    - Removing non-alphabetic characters.
    - Converting all letters to lowercase.
    - Including only standard English letters (a-z).
    """
    try:
        with open(plaintext_filename, 'r', encoding='utf-8') as file:
            text = file.read()
            sanitized_chars = []
            skipped_chars = 0
            for char in text:
                if char.isalpha():
                    lower_char = char.lower()
                    if lower_char in string.ascii_lowercase:
                        sanitized_chars.append(lower_char)
                    else:
                        skipped_chars += 1
            sanitized_text = ''.join(sanitized_chars)
            if len(sanitized_text) > 9991:
                sys.exit("Error: Plaintext exceeds the maximum allowed length of 9991 characters.")
            return sanitized_text
    except FileNotFoundError:
        sys.exit(f"Error: Plaintext file '{plaintext_filename}' not found.")
    except Exception as e:
        sys.exit(f"Error reading plaintext file: {e}")

def encrypt_hill_cipher(plaintext, key_matrix):
    """
    Encrypts the plaintext using the Hill cipher with the provided key matrix.

    Steps:
    - Convert plaintext to numerical vectors.
    - Multiply by key matrix.
    - Apply modulo 26.
    - Convert back to letters.
    """
    size = key_matrix.shape[0]
    padding_length = (-len(plaintext)) % size
    if padding_length != 0:
        padded_text = plaintext + ('x' * padding_length)
    else:
        padded_text = plaintext

    # Mapping from letters to numbers (a=0, b=1, ..., z=25)
    letter_to_num = {letter: idx for idx, letter in enumerate(string.ascii_lowercase)}
    num_to_letter = {idx: letter for idx, letter in enumerate(string.ascii_lowercase)}

    # Convert plaintext to numerical vectors
    try:
        plaintext_nums = [letter_to_num[char] for char in padded_text]
    except KeyError as e:
        sys.exit(f"Error: Invalid character '{e.args[0]}' encountered during encryption.")

    # Reshape into matrix where each column is a vector
    try:
        plaintext_matrix = np.array(plaintext_nums).reshape(-1, size).T
    except ValueError:
        sys.exit("Error: Plaintext length is not compatible with the matrix size after padding.")

    # Perform matrix multiplication and modulo 26
    ciphertext_matrix = np.mod(np.dot(key_matrix, plaintext_matrix), 26)

    # Flatten the ciphertext matrix and convert back to letters
    ciphertext_nums = ciphertext_matrix.T.flatten()
    ciphertext = ''.join([num_to_letter[num] for num in ciphertext_nums])

    return ciphertext

def format_output(text):
    """
    Formats the text into lines of exactly 80 characters, except possibly the last line.
    """
    return '\n'.join([text[i:i+80] for i in range(0, len(text), 80)])

def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python3 pa01.py <key_file> <plaintext_file>")

    key_filename = sys.argv[1]
    plaintext_filename = sys.argv[2]

    # Read and process key matrix
    key_matrix = read_key_file(key_filename)

    # Read and process plaintext
    plaintext = read_plaintext_file(plaintext_filename)
    if not plaintext:
        sys.exit("Error: Plaintext is empty after sanitization.")

    # Encrypt plaintext
    ciphertext = encrypt_hill_cipher(plaintext, key_matrix)

    # newline
    print()

    # Print Key matrix
    print("Key matrix:")
    for row in key_matrix:
        # Format each number to be right-aligned within 4 spaces
        formatted_row = ''.join([f"{num:4d}" for num in row])
        print(formatted_row)
    
    size = key_matrix.shape[0]
    padding_length = (-len(plaintext)) % size
    if padding_length != 0:
        plaintext = plaintext + ('x' * padding_length)
    else:
        plaintext = plaintext
    
    # Print a newline to separate sections
    print()

    # Print Plaintext
    print("Plaintext:")
    formatted_plaintext = format_output(plaintext)
    print(formatted_plaintext)
    
    # Print a newline to separate sections
    print()

    # Print Ciphertext
    print("Ciphertext:")
    formatted_ciphertext = format_output(ciphertext)
    print(formatted_ciphertext)

if __name__ == "__main__":
    main()

"""=============================================================================
| I Bryant Parchinski (Your NID) affirm that this program is
| entirely my own work and that I have neither developed my code together with
| any another person, nor copied any code from any other person, nor permitted
| my code to be copied or otherwise used by any other person, nor have I
| copied, modified, or otherwise used programs created by others. I acknowledge
| that any violation of the above terms will be treated as academic dishonesty.
+============================================================================="""

