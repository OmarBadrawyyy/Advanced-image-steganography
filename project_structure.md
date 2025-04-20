# Project Structure

## Core Files

- **steganography.py**: Contains all steganography-related functionality
  - LSB (Least Significant Bit) encoding/decoding
  - DCT (Discrete Cosine Transform) encoding/decoding
  - Steganalysis for detection of hidden data
  - Image capacity calculation
  - Integrity verification with HMAC

- **encryption.py**: Handles cryptographic operations
  - Fernet symmetric encryption/decryption
  - Key generation
  - Secure message handling

- **main.py**: Command-line interface and program entry point
  - Argument parsing
  - Command handling (encode, decode, analyze, capacity)
  - User interaction
  - Error handling

## Dependencies

Required libraries (see requirements.txt):
- **pillow**: Image processing
- **numpy**: Numerical operations
- **opencv-python**: Advanced image processing (for DCT method)
- **scipy**: Scientific computing (for DCT transformations)
- **cryptography**: Encryption and key management

## Steganography Methods

### LSB (Least Significant Bit)
- **Approach**: Modifies the least significant bits of pixel values
- **Files**: `encode_lsb()` and `decode_lsb()` in steganography.py
- **Advantages**: Higher capacity, simpler implementation
- **Limitations**: More vulnerable to image processing, statistical analysis

### DCT (Discrete Cosine Transform)
- **Approach**: Embeds data in frequency domain coefficients
- **Files**: `encode_dct()` and `decode_dct()` in steganography.py
- **Advantages**: Better resistance to image processing and compression
- **Limitations**: Lower capacity, more complex implementation

## Security Features

### Encryption
- **Implementation**: Fernet symmetric encryption from cryptography library
- **Files**: Functions in encryption.py
- **Purpose**: Ensures data can't be read even if steganography is detected

### Integrity Verification
- **Implementation**: HMAC with SHA-256
- **Files**: `generate_hmac()` and `verify_hmac()` in steganography.py
- **Purpose**: Detects message tampering

### Randomized Encoding
- **Implementation**: Password-based pseudorandom pixel selection
- **Files**: Embedding logic in `encode_lsb()` and `decode_lsb()`
- **Purpose**: Makes statistical analysis more difficult

## Detection Capabilities

### Steganalysis
- **Implementation**: Statistical analysis of LSB distribution
- **Files**: `detect_steganography()` in steganography.py
- **Purpose**: Demonstrates how steganography can be detected

## Command-line Interface

The application supports four main commands:
- **encode**: Hide a message in an image
- **decode**: Extract a hidden message from an image
- **analyze**: Check if an image likely contains hidden data
- **capacity**: Calculate how much data can be hidden in an image

Each command supports various arguments and options for customization. 