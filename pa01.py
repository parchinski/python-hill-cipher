#!/usr/bin/env python3

"""
============================================================================
| Assignment: pa01 - Encrypting a plaintext file using the Hill cipher
|
| Author: Bryant Parchinski
| Language: python
| To Compile: pip install numpy
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
| Due Date: 07/30/24 
===========================================================================
"""

import sys
import numpy as np
import string

def read_key_file(key_filename):
    try:
        with open(key_filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            if not lines:
                sys.exit("UHUHUH NO KEY FILE")

            # get matrix size ensuring file is correct and matrix is correct
            size_line = lines[0].strip()
            if not size_line.isdigit():
                sys.exit("UH BRO WHY IS THE FIRST LINE OF THE KEY NOT AN INT??")
            size = int(size_line)
            if size < 2 or size > 9:
                sys.exit("BRO THE MATRIX HAS TO BE 2 <= x <= 9")

            # okay maybe I'm just flexing security at this point but is that not the point of the class a lil bit in a way
            # I understand that none of this validation is really "necessary" but I'm having fun w it and it makes the code reusable for me so win win"
            # construct matrix row array and append to matrix array
            if len(lines) < size + 1:
                sys.exit("BRO THE MATRIX FILE IS MESSED UP PAST THE SIZE")             
            matrix = []
            for i in range(1, size + 1):
                row = lines[i].strip().split()
                if len(row) != size:
                    sys.exit(f"ROW {i} IN KEY DOES NOT HAVE {size} INTS")
                matrix_row = []
                for num_str in row:
                    # allow for negative numbers bc - is a character! this validation backfired a lil bit
                    if not num_str.lstrip('-').isdigit():
                        sys.exit(f"INVALID CHAR '{num_str}' IN KEY MATRIX.")
                    num = int(num_str)
                    matrix_row.append(num)
                matrix.append(matrix_row)

            # convert matrix to numpy array
            key_matrix = np.array(matrix)
            return key_matrix

    except FileNotFoundError:
        sys.exit(f"NO KEY FILE FOUND FOR: {key_filename}")
    except Exception as e:
        sys.exit(f"UNEXPECTED ERROR READING KEY FILE: {e}")

def read_plaintext_file(plaintext_filename):
    try:
        with open(plaintext_filename, 'r', encoding='utf-8') as file:
            text = file.read() # get whole file as string
            sanitized_chars = []
            for char in text:
                if char.isalpha(): # check if char is a alphabetic
                    lower_char = char.lower()
                    if lower_char in string.ascii_lowercase:
                        sanitized_chars.append(lower_char) # append a valid lowercase letter
            sanitized_text = ''.join(sanitized_chars) # turn sanitzed string array into a string
            # might change this limit if I use this script again for cyber stuff
            if len(sanitized_text) > 10000:
                sys.exit("SANITIZED TEXT HAS PAST LIMIT OF 10000 CHARS BRO MINIFY THE INPUT OR CHECK LINE 80")
            return sanitized_text 
    except FileNotFoundError:
        sys.exit(f"NO PLAINTEXT FILE FOUND FOR: {plaintext_filename}")
    except Exception as e:
        sys.exit(f"UNEXPECTED ERROR READING THE PLAINTEXT FILE: {e}")

# NUMPY IS SO GOATED FOR THIS
def encrypt_hill_cipher(plaintext, key_matrix):
    # get the size of the key matrix (is's a numpy array)
    size = key_matrix.shape[0]

    # Calculate the padding needed by using remainder of plaintext len / matrix size
    padding_length = (-len(plaintext)) % size 
    if padding_length != 0:
        padded_text = plaintext + ('x' * padding_length)
    else:
        padded_text = plaintext

    # create mappings between letters and numbers
    letter_to_num = {letter: i for i, letter in enumerate(string.ascii_lowercase)}
    num_to_letter = {i: letter for i, letter in enumerate(string.ascii_lowercase)}

    # convert plaintext to numerical vectors
    plaintext_nums = [letter_to_num[char] for char in padded_text]

    # change the numerical vectors numpy array into a numpy matrix and transpose it
    plaintext_matrix = np.array(plaintext_nums).reshape(-1, size).T

    # perform the encryption a matrix multiplication between the key matrix and plaintext matrix
    # modulo each resulting number by 26 to keep it alphabetically friendly yalll
    ciphertext_matrix = np.mod(np.dot(key_matrix, plaintext_matrix), 26)

    # convert the ciphertext matrix back into a string and boom then ciphertext
    ciphertext_nums = ciphertext_matrix.T.flatten()
    ciphertext = ''.join([num_to_letter[num] for num in ciphertext_nums])
    return ciphertext

def format_output(text):
    # split the text into chunks of 80 chars then separate them by newlines WOOOO shoutout python oneliners and stackoverflow
    return '\n'.join([text[i:i+80] for i in range(0, len(text), 80)])

def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python3 pa01.py <key_file> <plaintext_file>")

    key_filename = sys.argv[1]
    plaintext_filename = sys.argv[2]

    key_matrix = read_key_file(key_filename)
    plaintext = read_plaintext_file(plaintext_filename)
    if not plaintext:
        sys.exit("UHH SO NO VALID CHARACTERS IN THE PLAINTEXT")
    ciphertext = encrypt_hill_cipher(plaintext, key_matrix)

    print()
    print("Key matrix:")
    for row in key_matrix:
        formatted_row = ''.join([f"{num:4d}" for num in row])
        print(formatted_row)
    # least favorite section of this entire file like I really should have made a way
    # for this to be a function but OH WELL IT WORKS SORRY RAM
    size = key_matrix.shape[0]
    padding_length = (-len(plaintext)) % size
    if padding_length != 0:
        plaintext = plaintext + ('x' * padding_length)
    else:
        plaintext = plaintext
    
    print()
    print("Plaintext:")
    formatted_plaintext = format_output(plaintext)
    print(formatted_plaintext)
    print()
    print("Ciphertext:")
    formatted_ciphertext = format_output(ciphertext)
    print(formatted_ciphertext)

# allows for ./ run yippie convenience
if __name__ == "__main__":
    main()

"""
=============================================================================
| I Bryant Parchinski (br552182) affirm that this program is
| entirely my own work and that I have neither developed my code together with
| any another person, nor copied any code from any other person, nor permitted
| my code to be copied or otherwise used by any other person, nor have I
| copied, modified, or otherwise used programs created by others. I acknowledge
| that any violation of the above terms will be treated as academic dishonesty.
=============================================================================
"""
