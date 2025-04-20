# Advanced Image Steganography with Encryption

A cybersecurity tool for concealing encrypted data within digital images using multiple steganography techniques. This project demonstrates practical implementation of steganography, cryptography, and digital forensics concepts.

## Features

### Steganography Techniques
- **LSB (Least Significant Bit)**: Higher capacity, suitable for most images
- **DCT (Discrete Cosine Transform)**: Better resistance to image processing and compression

### Security Features
- **End-to-end encryption** using Fernet symmetric encryption
- **HMAC integrity verification** to detect message tampering
- **Randomized bit encoding** for enhanced security against statistical analysis
- **Steganalysis capabilities** to detect hidden data in suspicious images

### Performance Features
- **Capacity calculation** to prevent message overflow
- **Multiple image format support**
- **Command-line interface** for easy integration into security workflows

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/image-steganography.git
cd image-steganography

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Hide a message in an image
```bash
python main.py encode --image input.jpg --output hidden.png --message "Top secret information" --randomize
```

### Use DCT method for better resistance to image processing
```bash
python main.py encode --image input.jpg --output hidden.png --message "Top secret" --method dct
```

### Extract a hidden message
```bash
python main.py decode --image hidden.png --key "YOUR-ENCRYPTION-KEY"
```

### Analyze an image for hidden data
```bash
python main.py analyze --image suspicious.png
```

### Check how much data can be hidden in an image
```bash
python main.py capacity --image large_image.png
```

## Testing Recommendations

### Important Notes
- **Always save to PNG format**: Always save steganography output as PNG. Using lossy formats like JPG will destroy hidden data.
- **Testing sequence**: 
  1. Check image capacity first
  2. Try basic encoding and decoding without encryption
  3. Test with encryption, saving the key
  4. Experiment with randomization using passwords
  5. Test steganalysis to detect hidden data
  6. Compare original and encoded images

### Common Issues
- **Decoding failures**: Ensure you're using the same method (LSB/DCT) for encoding and decoding
- **Randomization**: When using randomized encoding, the same password must be used for decoding
- **Key management**: Always save encryption keys securely; they cannot be recovered if lost

## Security Considerations

- Always use encryption with steganography for sensitive data
- The DCT method offers better protection against image processing but lower capacity
- Randomization enhances security but requires the same password for decoding
- No steganography technique is 100% undetectable; this tool includes steganalysis to demonstrate

## Project Structure

See [project_structure.md](project_structure.md) for detailed information about the codebase organization.

## Applications in Cybersecurity

- **Covert Communication**: Secret message passing that evades detection
- **Digital Watermarking**: Embed copyright information in media
- **Data Exfiltration Detection**: Identify suspicious steganography usage
- **Digital Forensics**: Analyze media for concealed evidence

## Future Enhancements

- Add support for audio and video steganography
- Implement machine learning-based steganalysis
- Add network steganography techniques
- Enhance resistance against advanced steganalysis tools

## License

This project is licensed under the MIT License - see the LICENSE file for details. 