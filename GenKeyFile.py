import argparse
import os

# Fixed RC4 key
rc4_key = [0x54, 0x48, 0xF6, 0x3D, 0xA5, 0x29, 0x19, 0xC2,
           0x8A, 0x53, 0x44, 0x7F, 0xD8, 0x20, 0xFE, 0x31]

# Fixed AES key with keysize = 32 and IV = 16
aes_key = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7,
    0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7
]
IV = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7
]

# AES settings. For AES-256, we use a 32-byte key and 16-byte IV.
AES_KEY_SIZE = 32
AES_IV_SIZE = 16

# Set up argument parser
parser = argparse.ArgumentParser(
    description="Generate a binary file containing the specified key. By default, it writes the RC4 key. "
                "Use --aes to generate a random AES key and IV adjacent to each other."
)
parser.add_argument("output_path", type=str, help="The output file path for the binary file.")
parser.add_argument("algo", type=str, help="The algorithm to use. Either 'rc4' or 'aes'.", choices=["rc4", "aes"])

args = parser.parse_args()

# Check if AES mode has been requested
if args.algo.lower() == "rc4":
    data = bytearray(rc4_key)
    print("Using fixed RC4 key.")
elif args.algo.lower() == "aes":
    data = bytearray(aes_key + IV)
    print("Using fixed AES key and IV.")

# Open the file for binary writing
with open(args.output_path, 'wb') as binary_file:
    binary_file.write(data)

print(f"Binary file '{args.output_path}' has been created.")
