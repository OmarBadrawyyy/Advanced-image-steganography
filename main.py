import argparse
import sys
import os
from steganography import encode_message, decode_message, calculate_capacity, detect_steganography
from encryption import generate_key, encrypt_message, decrypt_message

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Steganography Tool - Hide encrypted messages in images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py encode --image input.jpg --output stego.png --message "Secret message"
  python main.py decode --image stego.png
  python main.py analyze --image suspicious.png
  python main.py capacity --image input.jpg
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    subparsers.required = True
    
    # Encode command
    encode_parser = subparsers.add_parser("encode", help="Hide a message in an image")
    encode_parser.add_argument("--image", "-i", required=True, help="Input image path")
    encode_parser.add_argument("--output", "-o", required=True, help="Output image path")
    encode_parser.add_argument("--message", "-m", required=True, help="Message to hide")
    encode_parser.add_argument("--password", "-p", help="Optional password for additional security")
    encode_parser.add_argument("--no-encrypt", action="store_true", help="Skip encryption (not recommended)")
    encode_parser.add_argument("--randomize", "-r", action="store_true", help="Use randomized encoding for stronger security")
    encode_parser.add_argument("--method", choices=["lsb", "dct"], default="lsb", 
                              help="Steganography method: LSB (default, higher capacity) or DCT (better against image processing)")
    
    # Decode command
    decode_parser = subparsers.add_parser("decode", help="Extract a hidden message from an image")
    decode_parser.add_argument("--image", "-i", required=True, help="Image containing hidden message")
    decode_parser.add_argument("--password", "-p", help="Password used during encoding (if applicable)")
    decode_parser.add_argument("--key", "-k", help="Encryption key (if message was encrypted)")
    decode_parser.add_argument("--randomize", "-r", action="store_true", help="Use randomized decoding (if used during encoding)")
    decode_parser.add_argument("--method", choices=["lsb", "dct"], default="lsb", 
                              help="Steganography method: should match the method used for encoding")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an image for hidden data")
    analyze_parser.add_argument("--image", "-i", required=True, help="Image to analyze")
    
    # Capacity command
    capacity_parser = subparsers.add_parser("capacity", help="Calculate how much data can be hidden in an image")
    capacity_parser.add_argument("--image", "-i", required=True, help="Image to analyze")
    
    args = parser.parse_args()
    
    try:
        if args.command == "encode":
            # Check if image exists
            if not os.path.exists(args.image):
                print(f"[-] Input image not found: {args.image}")
                return
                
            # Check if output directory exists
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Check capacity
            max_capacity = calculate_capacity(args.image)
            msg_size = len(args.message)
            print(f"[+] Image capacity: {max_capacity} bytes")
            print(f"[+] Message size: {msg_size} bytes")
            
            if msg_size > max_capacity:
                print(f"[-] Error: Message too large for this image")
                return
                
            # Prepare message
            message = args.message
            key = None
            
            # Encrypt if needed
            if not args.no_encrypt:
                key = generate_key()
                print(f"[!] Encryption key (SAVE THIS): {key.decode()}")
                message = encrypt_message(message, key)
                
            # Encode the message
            print(f"[+] Using {args.method.upper()} steganography method")
            
            # Ensure DCT method doesn't use randomization (not supported)
            if args.method == "dct" and args.randomize:
                print("[!] Warning: Randomization is not supported with DCT method. Ignoring.")
                args.randomize = False
                
            result = encode_message(
                args.image, 
                message, 
                args.output, 
                password=args.password,
                use_randomization=args.randomize,
                method=args.method
            )
            
            print(f"[+] Message encoded successfully")
            print(f"[+] Output file: {args.output}")
            print(f"[+] Capacity used: {result['capacity_used_percent']:.2f}%")
            
            if args.randomize:
                print("[+] Randomized encoding: Enabled")
            if args.password:
                print("[+] Integrity verification: Enabled")
                
            # Print method-specific information
            if args.method == "dct":
                print("[+] DCT steganography offers better resistance to image processing")
                print("[!] Remember to use the same method when decoding")
            else:
                print("[+] LSB steganography offers higher capacity")
                
        elif args.command == "decode":
            # Check if image exists
            if not os.path.exists(args.image):
                print(f"[-] Input image not found: {args.image}")
                return
                
            # Decode the message
            print(f"[+] Using {args.method.upper()} steganography method")
            
            # Ensure DCT method doesn't use randomization (not supported)
            if args.method == "dct" and args.randomize:
                print("[!] Warning: Randomization is not supported with DCT method. Ignoring.")
                args.randomize = False
                
            result = decode_message(
                args.image,
                password=args.password,
                use_randomization=args.randomize,
                method=args.method
            )
            
            if result["status"] == "error":
                print(f"[-] Error: {result['message']}")
                return
                
            if result["status"] == "warning":
                print(f"[!] Warning: {result['warning']}")
                
            if result["verified"]:
                print("[+] Message integrity verified")
                
            # Try to decrypt if key is provided
            if args.key:
                try:
                    decrypted = decrypt_message(result["message"], args.key.encode())
                    print(f"\n[+] Decrypted Message:\n{decrypted}")
                except Exception as e:
                    print(f"[-] Decryption failed: {str(e)}")
            else:
                print(f"\n[+] Raw Message (possibly encrypted):\n{result['message']}")
                
        elif args.command == "analyze":
            # Check if image exists
            if not os.path.exists(args.image):
                print(f"[-] Input image not found: {args.image}")
                return
                
            # Analyze the image
            result = detect_steganography(args.image)
            
            if isinstance(result, dict) and "status" in result and result["status"] == "error":
                print(f"[-] Error: {result['message']}")
                return
                
            print(f"[+] Steganography detection results:")
            print(f"[+] Probability of hidden data: {result['probability']:.2f}%")
            print(f"[+] LSB Distribution: {result['lsb_distribution']['zeros_percent']:.2f}% zeros, {result['lsb_distribution']['ones_percent']:.2f}% ones")
            
            # Interpretation guidance
            if result['probability'] > 75:
                print("[!] High probability of hidden data")
            elif result['probability'] > 50:
                print("[!] Medium probability of hidden data")
            else:
                print("[+] Low probability of hidden data")
                
        elif args.command == "capacity":
            # Check if image exists
            if not os.path.exists(args.image):
                print(f"[-] Input image not found: {args.image}")
                return
                
            # Calculate capacity
            capacity = calculate_capacity(args.image)
            print(f"[+] Maximum data capacity: {capacity} bytes")
            print(f"[+] Approximate character capacity: {capacity} characters")
            print(f"[+] Recommended maximum message size: {int(capacity * 0.9)} bytes (90% of max)")
            
    except Exception as e:
        print(f"[-] Error: {str(e)}")

if __name__ == "__main__":
    main()
