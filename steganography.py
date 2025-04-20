from PIL import Image
import os
import hashlib
import hmac
import random
import numpy as np
import cv2
from scipy.fftpack import dct, idct

def _to_bin(data):
    return ''.join(format(ord(char), '08b') for char in data)

def _from_bin(bin_data):
    chars = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def calculate_capacity(image_path):
    """Calculate maximum bytes that can be encoded in the image"""
    try:
        img = Image.open(image_path)
        width, height = img.size
        if img.mode == 'RGB':
            return (width * height * 3) // 8 - 64  # Account for EOF marker and overhead
        elif img.mode == 'RGBA':
            return (width * height * 4) // 8 - 64
        else:
            return (width * height * 3) // 8 - 64  # Convert to RGB and calculate
    except Exception as e:
        raise ValueError(f"Error calculating capacity: {str(e)}")

def generate_hmac(data, key):
    """Generate HMAC for data integrity verification"""
    h = hmac.new(key.encode() if isinstance(key, str) else key, 
                 data.encode() if isinstance(data, str) else data,
                 hashlib.sha256)
    return h.hexdigest()

def verify_hmac(data, signature, key):
    """Verify HMAC for data integrity"""
    calculated = generate_hmac(data, key)
    return hmac.compare_digest(calculated, signature)

def encode_message(image_path, message, output_path, password=None, use_randomization=False, method="lsb"):
    """
    Encode a message into an image with optional features:
    - Password-based integrity verification
    - Randomized encoding for increased security
    - Multiple steganography methods: 'lsb' or 'dct'
    """
    if method == "lsb":
        return encode_lsb(image_path, message, output_path, password, use_randomization)
    elif method == "dct":
        return encode_dct(image_path, message, output_path, password)
    else:
        raise ValueError(f"Unknown steganography method: {method}")

def decode_message(image_path, password=None, use_randomization=False, method="lsb"):
    """
    Decode a message from an image with optional features:
    - Password-based integrity verification
    - Support for randomized encoding
    - Multiple steganography methods: 'lsb' or 'dct'
    """
    if method == "lsb":
        return decode_lsb(image_path, password, use_randomization)
    elif method == "dct":
        return decode_dct(image_path, password)
    else:
        raise ValueError(f"Unknown steganography method: {method}")

def encode_lsb(image_path, message, output_path, password=None, use_randomization=False):
    """
    Encode a message using the LSB (Least Significant Bit) method
    """
    try:
        # Check if message can fit in the image
        max_capacity = calculate_capacity(image_path)
        message_size = len(message)
        
        if message_size > max_capacity:
            raise ValueError(f"Message too large. Max capacity: {max_capacity} bytes, Message size: {message_size} bytes")
        
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Generate integrity signature if password provided
        if password:
            signature = generate_hmac(message, password)
            message = message + "::sig::" + signature
        
        binary_msg = _to_bin(message) + '1111111111111110'  # EOF
        data = list(img.getdata())
        new_data = []

        # Prepare pixel indices for randomized encoding
        indices = list(range(len(data)))
        if use_randomization and password:
            # Seed random with password for deterministic randomization
            random.seed(hashlib.md5(password.encode()).hexdigest())
            random.shuffle(indices)
            pixel_map = {i: idx for i, idx in enumerate(indices)}

        msg_index = 0
        for i, pixel in enumerate(data):
            r, g, b = pixel
            
            # If using randomization, encode bits in pseudorandom order
            pixel_idx = pixel_map[i] if use_randomization and password else i
            if pixel_idx * 3 + 0 < len(binary_msg) and msg_index < len(binary_msg):
                r = (r & ~1) | int(binary_msg[msg_index])
                msg_index += 1
            if pixel_idx * 3 + 1 < len(binary_msg) and msg_index < len(binary_msg):
                g = (g & ~1) | int(binary_msg[msg_index])
                msg_index += 1
            if pixel_idx * 3 + 2 < len(binary_msg) and msg_index < len(binary_msg):
                b = (b & ~1) | int(binary_msg[msg_index])
                msg_index += 1
            new_data.append((r, g, b))

        img.putdata(new_data)
        img.save(output_path, format='PNG')  # Force PNG to avoid compression issues
        return {
            "status": "success",
            "file": output_path,
            "capacity_used_percent": (len(binary_msg) / (max_capacity * 8)) * 100
        }
    except Exception as e:
        raise RuntimeError(f"Encoding failed: {str(e)}")

def decode_lsb(image_path, password=None, use_randomization=False):
    """
    Decode a message using the LSB (Least Significant Bit) method
    """
    try:
        img = Image.open(image_path)
        data = list(img.getdata())
        bin_data = ''
        
        # Prepare pixel indices for randomized decoding
        indices = list(range(len(data)))
        if use_randomization and password:
            # Seed random with password for deterministic randomization
            random.seed(hashlib.md5(password.encode()).hexdigest())
            random.shuffle(indices)
            pixel_map = {idx: i for i, idx in enumerate(indices)}
        
        # If using randomization, sort pixels according to the encoding order
        if use_randomization and password:
            sorted_data = [None] * len(data)
            for i, pixel in enumerate(data):
                sorted_data[pixel_map[i]] = pixel
            data = sorted_data
    
        for pixel in data:
            for color in pixel[:3]:
                bin_data += str(color & 1)
    
        eof = '1111111111111110'
        end = bin_data.find(eof)
        if end != -1:
            bin_data = bin_data[:end]
        else:
            return {"status": "error", "message": "No hidden message found or corrupted data"}

        message = _from_bin(bin_data)
        
        # Check integrity if a signature is present
        if password and "::sig::" in message:
            message_parts = message.split("::sig::")
            if len(message_parts) >= 2:
                original_message = message_parts[0]
                signature = message_parts[1]
                if verify_hmac(original_message, signature, password):
                    return {"status": "success", "message": original_message, "verified": True}
                else:
                    return {"status": "warning", "message": original_message, 
                           "verified": False, "warning": "Message integrity verification failed"}
        
        return {"status": "success", "message": message, "verified": False}
    except Exception as e:
        return {"status": "error", "message": f"Decoding failed: {str(e)}"}

def encode_dct(image_path, message, output_path, password=None):
    """
    Encode a message using the DCT (Discrete Cosine Transform) method
    This method is more resistant to image processing but has lower capacity
    """
    try:
        # Read image
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f"Unable to read image: {image_path}")
            
        # Get image dimensions
        height, width = img.shape[:2]
        
        # Calculate maximum capacity (using 1 bit per 8x8 block)
        block_size = 8
        blocks_h = height // block_size
        blocks_w = width // block_size
        max_bits = blocks_h * blocks_w * 3  # For Y, Cb, Cr channels
        max_bytes = max_bits // 8
        
        # Add signature if password provided
        if password:
            signature = generate_hmac(message, password)
            message = message + "::sig::" + signature
            
        # Convert message to binary
        binary_msg = _to_bin(message) + '1111111111111110'  # EOF marker
        
        if len(binary_msg) > max_bits:
            raise ValueError(f"Message too large. Max capacity: {max_bytes} bytes, Message size: {len(message)} bytes")
        
        # Convert RGB to YCrCb color space (better for DCT)
        ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        
        channels = cv2.split(ycrcb)
        msg_index = 0
        
        # Process each channel
        for c in range(len(channels)):
            channel = channels[c]
            for i in range(0, blocks_h * block_size, block_size):
                for j in range(0, blocks_w * block_size, block_size):
                    if msg_index >= len(binary_msg):
                        break
                        
                    # Extract 8x8 block
                    block = channel[i:i+block_size, j:j+block_size].astype(float)
                    
                    # Apply DCT
                    dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                    
                    # Modify DCT coefficient - use middle frequency
                    # Not using (0,0) as it affects image quality too much
                    # Using (4,5) or (5,4) as they're less perceptible
                    if msg_index < len(binary_msg):
                        bit = int(binary_msg[msg_index])
                        
                        # Make coefficient even for 0, odd for 1
                        if bit == 0:
                            dct_block[4, 5] = int(dct_block[4, 5])
                            if dct_block[4, 5] % 2 == 1:
                                dct_block[4, 5] += 1
                        else:
                            dct_block[4, 5] = int(dct_block[4, 5])
                            if dct_block[4, 5] % 2 == 0:
                                dct_block[4, 5] += 1
                                
                        msg_index += 1
                    
                    # Apply inverse DCT
                    block = idct(idct(dct_block, norm='ortho').T, norm='ortho').T
                    
                    # Update the image channel with the modified block
                    channel[i:i+block_size, j:j+block_size] = block.astype(np.uint8)
            
            # Update the channel
            channels[c] = channel
        
        # Merge channels back
        ycrcb = cv2.merge(channels)
        
        # Convert back to BGR
        img_encoded = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)
        
        # Save the image
        cv2.imwrite(output_path, img_encoded)
        
        return {
            "status": "success",
            "file": output_path,
            "capacity_used_percent": (len(binary_msg) / max_bits) * 100
        }
    except Exception as e:
        raise RuntimeError(f"DCT encoding failed: {str(e)}")

def decode_dct(image_path, password=None):
    """
    Decode a message using the DCT (Discrete Cosine Transform) method
    """
    try:
        # Read image
        img = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if img is None:
            return {"status": "error", "message": f"Unable to read image: {image_path}"}
            
        # Get image dimensions
        height, width = img.shape[:2]
        
        # Convert RGB to YCrCb color space
        ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        
        channels = cv2.split(ycrcb)
        block_size = 8
        blocks_h = height // block_size
        blocks_w = width // block_size
        
        # Extract bits
        binary_data = ""
        
        # Process each channel
        for c in range(len(channels)):
            channel = channels[c]
            for i in range(0, blocks_h * block_size, block_size):
                for j in range(0, blocks_w * block_size, block_size):
                    # Extract 8x8 block
                    block = channel[i:i+block_size, j:j+block_size].astype(float)
                    
                    # Apply DCT
                    dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                    
                    # Get bit from coefficient
                    bit = "1" if int(dct_block[4, 5]) % 2 == 1 else "0"
                    binary_data += bit
                    
                    # Check for EOF marker
                    eof = '1111111111111110'
                    if binary_data.endswith(eof):
                        # Remove EOF marker
                        binary_data = binary_data[:-len(eof)]
                        # Convert binary to text
                        message = _from_bin(binary_data)
                        
                        # Check integrity if a signature is present
                        if password and "::sig::" in message:
                            message_parts = message.split("::sig::")
                            if len(message_parts) >= 2:
                                original_message = message_parts[0]
                                signature = message_parts[1]
                                if verify_hmac(original_message, signature, password):
                                    return {"status": "success", "message": original_message, "verified": True}
                                else:
                                    return {"status": "warning", "message": original_message, 
                                           "verified": False, "warning": "Message integrity verification failed"}
                        
                        return {"status": "success", "message": message, "verified": False}
        
        return {"status": "error", "message": "No hidden message found or corrupted data"}
    except Exception as e:
        return {"status": "error", "message": f"DCT decoding failed: {str(e)}"}

def detect_steganography(image_path):
    """
    Simple statistical analysis to detect potential LSB steganography
    Returns probability score 0-100
    """
    try:
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        data = list(img.getdata())
        lsb_count = {'0': 0, '1': 0}
        
        # Count LSBs distribution
        for pixel in data:
            for color in pixel[:3]:
                lsb_count[str(color & 1)] += 1
                
        total = lsb_count['0'] + lsb_count['1']
        # Perfect distribution would be 50/50
        # Natural images rarely have perfectly uniform LSB distribution
        if total == 0:
            return 0
            
        zero_percent = (lsb_count['0'] / total) * 100
        distribution_score = abs(50 - zero_percent)
        
        # A score close to 0 indicates uniform distribution (suspicious)
        # A score far from 0 indicates natural distribution
        return {
            "probability": max(0, 100 - distribution_score * 2),
            "lsb_distribution": {
                "zeros_percent": zero_percent,
                "ones_percent": 100 - zero_percent
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Detection failed: {str(e)}"} 