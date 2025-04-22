# Image Steganography Project Structure

## Architecture Overview

This project demonstrates a comprehensive implementation of steganography techniques with a focus on security best practices, cryptography integration, and ML-based steganalysis.

## Core Components

- `main.py` - Command-line interface with argparse implementation for all steganographic operations
- `steganography.py` - Algorithmic implementation of LSB/DCT steganography and ML-based steganalysis
- `encryption.py` - Cryptographic operations using Fernet symmetric encryption
- `test_image.png` - Sample image for testing and demonstration

## Technical Implementation

### Steganography Algorithms
- **LSB (Least Significant Bit)** - Bit manipulation technique that modifies the least significant bit of RGB pixel values
- **DCT (Discrete Cosine Transform)** - Frequency domain technique that embeds data in mid-frequency DCT coefficients

### Security Implementation
- Fernet symmetric encryption for message confidentiality
- SHA-256 HMAC for message integrity verification
- Seeded pseudorandom bit distribution for enhanced statistical security
- Combined cryptographic and steganographic security layers

### Encryption Key Management
- Cryptographically secure key generation using Fernet
- Runtime key presentation with deliberate non-persistence for security
- Command-line interface for key input during decoding
- Secure error handling to prevent cryptographic leaks

### Steganalysis Engine
- Statistical analysis using chi-square and histogram evaluation
- Machine Learning detection pipeline:
  - Feature extraction from spatial and frequency domains
  - Random Forest classification model
  - Training workflow with clean/stego image comparison

## CLI Architecture

```
python main.py <command> [options]
```

Command architecture follows a consistent pattern:
- `encode` - Data hiding operation with multiple security options
- `decode` - Data extraction with integrity verification
- `analyze` - Statistical steganalysis for detection
- `capacity` - Mathematical analysis of potential data capacity
- `train-model` - ML model training with configurable parameters
- `ml-analyze` - Advanced detection using trained ML models

## Machine Learning Pipeline

The steganalysis system employs the following feature engineering approach:
- Statistical features: mean, standard deviation, skewness, kurtosis
- Information theory metrics: entropy calculations, bit distribution
- Image processing features: pixel differences, neighborhood statistics
- Transform domain features: DCT coefficient statistics
- Histogram analysis: bin distribution and variance metrics

## Technical Requirements

- scikit-learn (ML pipeline)
- numpy (numerical operations)
- opencv-python (image processing)
- scipy (DCT transforms)
- Pillow (image manipulation)
- joblib (model serialization)
- cryptography (secure encryption) 