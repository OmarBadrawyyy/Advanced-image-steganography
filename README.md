# Advanced Image Steganography with Encryption

A cybersecurity tool implementing multiple steganography techniques with advanced encryption, integrity verification, and machine learning-based detection capabilities. This project demonstrates practical application of:

- **Digital Signal Processing** - Image manipulation in spatial and frequency domains
- **Cryptography** - Symmetric encryption and HMAC for confidentiality and integrity
- **Machine Learning** - Statistical modeling for steganalysis and detection
- **Security Engineering** - Defense-in-depth approach combining multiple security layers

## Technical Implementation

### Steganography Algorithms
- **LSB (Least Significant Bit)** - Spatial domain technique manipulating RGB pixel values with 0.4% capacity utilization
- **DCT (Discrete Cosine Transform)** - Frequency domain technique modifying mid-frequency coefficients for resistance against compression

### Security Architecture
- **End-to-end encryption** using Fernet implementation of AES-128 in CBC mode with PKCS7 padding
- **SHA-256 HMAC integrity verification** with constant-time comparison to prevent timing attacks
- **Pseudorandom embedding patterns** using cryptographically secure seeds to mitigate statistical analysis
- **Multi-stage steganalysis** combining classical statistics and machine learning approaches

### Performance Optimizations
- **Capacity calculation algorithm** leveraging image dimensions and color channels
- **Format-specific processing** with specialized handling for different image types
- **Command-line interface** designed for integration into automated security workflows

### Machine Learning Detection System
- **Feature engineering pipeline** extracting 31+ distinctive image characteristics
- **Random Forest classifier** optimized for high-precision steganalysis
- **Cross-validation methodology** for robust model evaluation
- **Confidence scoring** with interpretable detection thresholds

## Usage Examples

### Data Hiding with Enhanced Security
```bash
python main.py encode --image input.jpg --output hidden.png --message "Confidential information" --randomize
```

### Frequency Domain Steganography
```bash
python main.py encode --image input.jpg --output hidden.png --message "Resistant to processing" --method dct
```

### Message Extraction with Cryptographic Verification
```bash
python main.py decode --image hidden.png --key "YOUR-ENCRYPTION-KEY" --password "optional-additional-verification"
```

### Forensic Analysis
```bash
python main.py analyze --image suspicious.png
```

### Capacity Analysis
```bash
python main.py capacity --image target.png
```

### Machine Learning Model Training
```bash
python main.py train-model --clean-dir clean_images --stego-dir stego_images
```

### Advanced Steganalysis
```bash
python main.py ml-analyze --image suspicious.png
```

## Implementation Challenges & Solutions

### Technical Challenges Addressed
- **Statistical Detectability**: Mitigated through randomized bit selection and distribution
- **Image Processing Resilience**: Implemented DCT domain embedding for resistance against compression
- **Cryptographic Integration**: Combined steganography with modern cryptographic primitives
- **Detection Accuracy**: Developed composite feature sets spanning multiple domains for ML model
- **Performance Optimization**: Balanced embedding capacity with detection resistance

### Security Considerations
- **Defense-in-Depth Strategy**: Multiple layers of security including encryption, integrity verification, and randomization
- **Key Management**: Deliberate runtime-only key presentation for improved operational security
- **Statistical Attack Resistance**: Engineered to minimize detectable patterns in encoded images
- **ML Detection Competition**: Demonstrates both hiding and detection in an adversarial environment

## Architecture Documentation

See [project_structure.md](project_structure.md) for detailed technical documentation of the codebase architecture.

## Applications in Information Security

- **Secure Communications**: Covert channel establishment with encryption and integrity
- **Digital Watermarking**: Copyright and ownership verification in media
- **Security Research**: Educational demonstration of steganographic techniques and detection
- **Digital Forensics**: Tools for detection and analysis of covert communication channels