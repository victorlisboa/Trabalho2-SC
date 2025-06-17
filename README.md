# Trabalho2-SC

## S-AES (Simplified AES)
Implementation of the Simplified AES (S-AES) algorithm in C++. Includes:
- Core S-AES operations (AddRoundKey, SubNibbles, ShiftRows, MixColumns, KeyExpansion)
- Encryption and decryption for 16-bit blocks
- ECB mode for multi-block messages
- Demonstration of ECB weaknesses (identical blocks produce identical ciphertext)

## AES Modes Simulation (with OpenSSL)
This project also simulates the real AES algorithm using the OpenSSL cryptographic library, supporting multiple modes of operation:
- **ECB** (Electronic Codebook)
- **CBC** (Cipher Block Chaining)
- **CFB** (Cipher Feedback)
- **OFB** (Output Feedback)
- **CTR** (Counter)

### Features
- Encrypts and decrypts the same message in all modes
- Uses randomly generated 256-bit key and 128-bit IV (where applicable)
- Measures and displays encryption time for each mode
- Outputs ciphertext in base64 for easy visualization
- Calculates and displays entropy of plaintext and ciphertext
- Demonstrates ECB mode weakness with repeated and patterned blocks
- Well-commented, modular C++ source code

### Requirements
- C++17 or newer
- OpenSSL development libraries (`libssl-dev`)
- Linux (tested on Ubuntu/WSL2)

### Build Instructions
1. **Install OpenSSL development libraries:**
   ```sh
   sudo apt-get update && sudo apt-get install -y libssl-dev
   ```

2. **Build the implementations:**
   You can build each implementation separately or both at once:
   ```sh
   # Build S-AES implementation only
   make saes
   
   # Build AES modes implementation only
   make aes
   
   # Build both implementations
   make
   ```

3. **Run the programs:**
   ```sh
   # Run S-AES implementation
   ./saes
   
   # Run AES modes implementation
   ./aes
   ```

### Output Example
The program will output, for each mode:
- Mode name
- Plaintext and ciphertext length
- Encryption time (ms)
- Entropy of plaintext and ciphertext
- Ciphertext in base64
- Decryption result and verification

It also demonstrates the weakness of ECB mode:
- Identical plaintext blocks (e.g., "AAAA") produce identical ciphertext blocks
- Repeating patterns (e.g., "ABABABAB") are visible in the ciphertext

### File Overview
- `saes.h`, `saes.cpp`, `main.cpp`: S-AES implementation and ECB demonstration
- `aes_modes.h`, `aes_modes.cpp`, `main_aes.cpp`: AES (OpenSSL) implementation and analysis for all modes
- `Makefile`: Build instructions for both implementations

### Analysis
- **Entropy**: The program calculates the Shannon entropy of both plaintext and ciphertext to analyze randomness and security.
- **Security Note**: ECB mode is insecure for most applications due to its deterministic nature; use CBC, CFB, OFB, or CTR for better security.

### Authors
- Victor Hugo França Lisboa
