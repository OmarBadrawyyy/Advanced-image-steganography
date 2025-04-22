from PIL import Image
import os
import hashlib
import hmac
import random
import numpy as np
import cv2
from scipy.fftpack import dct, idct
import warnings
import struct
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

# Check if scikit-learn is available for ML-based steganalysis
try:
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    warnings.warn("scikit-learn not available. ML-based steganalysis will be disabled.")

def _to_bin(data):
    """Convert string data to binary string"""
    return ''.join(format(ord(char), '08b') for char in data)

def _from_bin(bin_data):
    """Convert binary string to string data"""
    chars = [bin_data[i:i+8] for i in range(0, len(bin_data), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def calculate_capacity(image_path):
    """Calculate maximum data capacity of image in bytes"""
    img = Image.open(image_path)
    width, height = img.size
    mode = img.mode
    
    if mode in ["RGB", "RGBA"]:
        channels = 3  # RGB channels only
    elif mode == "L":
        channels = 1  # Grayscale
    else:
        raise ValueError(f"Unsupported image mode: {mode}")
    
    max_bytes = (width * height * channels) // 8
    return max_bytes - 4  # Reserve 4 bytes for message length

def generate_hmac(data, key):
    """Generate SHA-256 HMAC for data integrity verification"""
    h = hmac.new(key.encode() if isinstance(key, str) else key, 
                 data.encode() if isinstance(data, str) else data,
                 hashlib.sha256)
    return h.hexdigest()

def verify_hmac(data, signature, key):
    """Verify HMAC signature against data"""
    calculated = generate_hmac(data, key)
    return hmac.compare_digest(calculated, signature)

def encode_message(image_path, message, output_path, password=None, use_randomization=False, method="lsb"):
    """Encode a message into an image using specified steganography method"""
    if method == "lsb":
        return encode_lsb(image_path, message, output_path, password, use_randomization)
    elif method == "dct":
        return encode_dct(image_path, message, output_path, password)
    else:
        raise ValueError(f"Unknown steganography method: {method}")

def decode_message(image_path, password=None, use_randomization=False, method="lsb"):
    """Decode a message from an image using specified steganography method"""
    if method == "lsb":
        return decode_lsb(image_path, password, use_randomization)
    elif method == "dct":
        return decode_dct(image_path, password)
    else:
        raise ValueError(f"Unknown steganography method: {method}")

def encode_lsb(image_path, message, output_path, password=None, use_randomization=False):
    """Encode message using LSB (Least Significant Bit) steganography"""
    try:
        max_capacity = calculate_capacity(image_path)
        message_size = len(message)
        
        if message_size > max_capacity:
            raise ValueError(f"Message too large. Max capacity: {max_capacity} bytes, Message size: {message_size} bytes")
        
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        if password:
            signature = generate_hmac(message, password)
            message = message + "::sig::" + signature
        
        binary_msg = _to_bin(message) + '1111111111111110'  # EOF marker
        data = list(img.getdata())
        new_data = []

        indices = list(range(len(data)))
        if use_randomization and password:
            random.seed(hashlib.md5(password.encode()).hexdigest())
            random.shuffle(indices)
            pixel_map = {i: idx for i, idx in enumerate(indices)}

        msg_index = 0
        for i, pixel in enumerate(data):
            r, g, b = pixel
            
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
        img.save(output_path, format='PNG')  # Use PNG to avoid compression artifacts
        return {
            "status": "success",
            "file": output_path,
            "capacity_used_percent": (len(binary_msg) / (max_capacity * 8)) * 100
        }
    except Exception as e:
        raise RuntimeError(f"Encoding failed: {str(e)}")

def decode_lsb(image_path, password=None, use_randomization=False):
    """Decode message using LSB (Least Significant Bit) steganography"""
    try:
        img = Image.open(image_path)
        data = list(img.getdata())
        bin_data = ''
        
        indices = list(range(len(data)))
        if use_randomization and password:
            random.seed(hashlib.md5(password.encode()).hexdigest())
            random.shuffle(indices)
            pixel_map = {idx: i for i, idx in enumerate(indices)}
        
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
    """Encode message using DCT (Discrete Cosine Transform) steganography"""
    try:
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            raise ValueError(f"Unable to read image: {image_path}")
            
        height, width = img.shape
        
        block_size = 8
        blocks_h = height // block_size
        blocks_w = width // block_size
        max_bits = blocks_h * blocks_w
        max_bytes = max_bits // 8
        
        if password:
            signature = generate_hmac(message, password)
            message = signature + message
            
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
            
        # Prepare the message with length prefix
        message_length = len(message_bytes)
        
        # Check if message can fit in image
        if message_length + 4 > max_bytes:  # 4 bytes for length
            raise ValueError(f"Message too large. Max capacity: {max_bytes} bytes, Message size: {message_length} bytes")
        
        # Create header with message length (4 bytes)
        header = struct.pack(">I", message_length)
        
        # Combine header and message
        data_to_hide = header + message_bytes
        
        # Convert to bits
        bits = []
        for byte in data_to_hide:
            if isinstance(byte, int):
                # If byte is already an int (from bytes object)
                bits.extend([int(bit) for bit in format(byte, '08b')])
            else:
                # If byte is a character
                bits.extend([int(bit) for bit in format(ord(byte), '08b')])
        
        # Add EOF marker
        bits.extend([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0])  # 16-bit marker (1111111111111110)
        
        if len(bits) > max_bits:
            raise ValueError(f"Message too large with overhead. Max bits: {max_bits}, Required: {len(bits)}")
        
        # Process each 8x8 block
        bit_index = 0
        for i in range(0, blocks_h * block_size, block_size):
            for j in range(0, blocks_w * block_size, block_size):
                if bit_index < len(bits):
                    # Extract 8x8 block
                    block = img[i:i+block_size, j:j+block_size].astype(float)
                    
                    # Apply DCT
                    dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                    
                    # Modify mid-frequency coefficient (4,5)
                    # Make it even for bit 0, odd for bit 1
                    coef = dct_block[4, 5]
                    if bits[bit_index] == 0:
                        dct_block[4, 5] = 2 * round(coef / 2.0)
                    else:
                        dct_block[4, 5] = 2 * round(coef / 2.0) + 1
                    
                    # Apply inverse DCT
                    block = idct(idct(dct_block, norm='ortho').T, norm='ortho').T
                    
                    # Update the image
                    img[i:i+block_size, j:j+block_size] = block.astype(np.uint8)
                    
                    bit_index += 1
        
        # Save the image
        cv2.imwrite(output_path, img)
        
        return {
            "status": "success",
            "file": output_path,
            "capacity_used_percent": (len(bits) / max_bits) * 100
        }
    except Exception as e:
        raise RuntimeError(f"DCT encoding failed: {str(e)}")

def decode_dct(image_path, password=None):
    """Decode message using DCT (Discrete Cosine Transform) steganography"""
    try:
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return {"status": "error", "message": f"Unable to read image: {image_path}"}
            
        height, width = img.shape
        
        # Extract bits from each 8x8 block
        extracted_bits = []
        
        block_size = 8
        blocks_h = height // block_size
        blocks_w = width // block_size
        
        for i in range(0, blocks_h * block_size, block_size):
            for j in range(0, blocks_w * block_size, block_size):
                # Extract 8x8 block
                block = img[i:i+block_size, j:j+block_size].astype(float)
                
                # Apply DCT
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                
                # Check mid-frequency coefficient (4,5)
                # Even coefficient -> bit 0, odd coefficient -> bit 1
                coef = int(round(dct_block[4, 5]))
                bit = coef % 2
                
                extracted_bits.append(bit)
                
                # Look for EOF marker (16 bits: 1111111111111110)
                if len(extracted_bits) >= 16:
                    last_16 = extracted_bits[-16:]
                    if last_16 == [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0]:
                        # Found EOF marker, remove it and stop extraction
                        extracted_bits = extracted_bits[:-16]
                        break
        
        # Convert bits to bytes
        # Group bits into bytes (8 bits per byte)
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte = 0
                for bit_idx in range(8):
                    byte = (byte << 1) | extracted_bits[i + bit_idx]
                extracted_bytes.append(byte)
        
        if len(extracted_bytes) < 4:
            return {"status": "error", "message": "No hidden message found (insufficient data)"}
        
        # Extract message length from first 4 bytes
        header = bytes(extracted_bytes[:4])
        message_length = struct.unpack(">I", header)[0]
        
        # Check if the message length is valid
        max_length = len(extracted_bytes) - 4
        if message_length == 0 or message_length > max_length:
            return {"status": "error", 
                    "message": f"Invalid message length ({message_length}) or no message found. Total data: {max_length} bytes"}
        
        # Extract the message
        message_bytes = extracted_bytes[4:4+message_length]
        
        # Handle password verification if applicable
        if password:
            try:
                # Get signature and message
                signature_length = 64  # SHA-256 hex digest length
                if len(message_bytes) < signature_length:
                    return {"status": "error", "message": "Message too short for integrity verification"}
                
                signature = message_bytes[:signature_length].decode('utf-8')
                actual_message = message_bytes[signature_length:].decode('utf-8')
                
                # Verify the signature
                if verify_hmac(actual_message, signature, password):
                    return {"status": "success", "message": actual_message, "verified": True}
                else:
                    return {
                        "status": "warning",
                        "warning": "Message integrity verification failed. The message may be corrupted or the password is incorrect.",
                        "message": actual_message,
                        "verified": False
                    }
            except Exception as e:
                return {"status": "error", "message": f"Failed to verify message integrity: {str(e)}"}
        
        # No password, just return the message
        try:
            # Try to decode as UTF-8 text
            decoded_message = message_bytes.decode('utf-8')
            return {"status": "success", "message": decoded_message, "verified": False}
        except UnicodeDecodeError:
            # If not text, return the raw bytes
            return {"status": "success", "message": message_bytes, "verified": False}
    
    except Exception as e:
        return {"status": "error", "message": f"DCT decoding failed: {str(e)}"}

def detect_steganography(image_path):
    """
    Statistical analysis to detect potential LSB steganography
    Returns probability score 0-100
    """
    try:
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        data = list(img.getdata())
        lsb_count = {'0': 0, '1': 0}
        
        for pixel in data:
            for color in pixel[:3]:
                lsb_count[str(color & 1)] += 1
                
        total = lsb_count['0'] + lsb_count['1']
        if total == 0:
            return 0
            
        zero_percent = (lsb_count['0'] / total) * 100
        distribution_score = abs(50 - zero_percent)
        
        return {
            "probability": max(0, 100 - distribution_score * 2),
            "lsb_distribution": {
                "zeros_percent": zero_percent,
                "ones_percent": 100 - zero_percent
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Detection failed: {str(e)}"}

def extract_steganalysis_features(image_path):
    """
    Extract statistical features from an image for steganalysis.
    
    Parameters:
    - image_path: Path to the image
    
    Returns:
    - Array of features or None if extraction fails
    """
    try:
        image = Image.open(image_path)
        
        if image.mode != 'L':
            image = image.convert('L')
        
        img_array = np.array(image)
        
        # Basic statistical features
        mean = np.mean(img_array)
        std = np.std(img_array)
        skewness = np.mean(((img_array - mean) / (std + 1e-10)) ** 3)
        kurtosis = np.mean(((img_array - mean) / (std + 1e-10)) ** 4) - 3
        
        # Histogram features
        hist, _ = np.histogram(img_array, bins=256, range=(0, 255))
        hist = hist / np.sum(hist)  # Normalize
        
        # Entropy
        entropy = -np.sum(hist * np.log2(hist + 1e-10))
        
        h, w = img_array.shape
        
        # Pixel value differences
        diff_h = np.abs(img_array[:, 1:] - img_array[:, :-1]).flatten()
        diff_h_mean = np.mean(diff_h)
        diff_h_std = np.std(diff_h)
        
        diff_v = np.abs(img_array[1:, :] - img_array[:-1, :]).flatten()
        diff_v_mean = np.mean(diff_v)
        diff_v_std = np.std(diff_v)
        
        # LSB features
        lsb = img_array % 2
        lsb_mean = np.mean(lsb)
        lsb_std = np.std(lsb)
        
        # Build feature vector
        features = np.array([
            mean, std, skewness, kurtosis, entropy,
            diff_h_mean, diff_h_std, diff_v_mean, diff_v_std,
            lsb_mean, lsb_std
        ])
        
        # Add histogram bin features
        bins_to_use = [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 255]
        for i in range(len(bins_to_use) - 1):
            bin_start = bins_to_use[i]
            bin_end = bins_to_use[i+1]
            bin_mean = np.mean(hist[bin_start:bin_end+1])
            features = np.append(features, bin_mean)
        
        # Add DCT features
        try:
            dct_coeffs = dct(dct(img_array.T, norm='ortho').T, norm='ortho')
            dct_mean = np.mean(np.abs(dct_coeffs))
            dct_std = np.std(np.abs(dct_coeffs))
            dct_skewness = np.mean(((np.abs(dct_coeffs) - dct_mean) / (dct_std + 1e-10)) ** 3)
            
            features = np.append(features, [dct_mean, dct_std, dct_skewness])
        except:
            features = np.append(features, [0, 0, 0])
        
        return features
        
    except Exception as e:
        print(f"Feature extraction error: {str(e)}")
        return None

def ml_steganalysis(image_path, model_path='stego_model.pkl'):
    """
    Use machine learning to detect steganography
    
    Parameters:
    - image_path: Path to the image to analyze
    - model_path: Path to the trained model
    
    Returns:
    - Analysis results dictionary with probability score 0-100
    """
    if not ML_AVAILABLE:
        return {"status": "error", "message": "scikit-learn is not available"}
    
    try:
        if not os.path.exists(model_path):
            return {
                "status": "error", 
                "message": f"Model not found: {model_path}. Train a model first using train_steganalysis_model()"
            }
        
        model_data = joblib.load(model_path)
        clf = model_data['model']
        scaler = model_data['scaler']
        
        features = extract_steganalysis_features(image_path)
        if features is None:
            return {"status": "error", "message": "Failed to extract features from the image"}
        
        features_scaled = scaler.transform(features.reshape(1, -1))
        
        prediction = clf.predict(features_scaled)[0]
        probability = clf.predict_proba(features_scaled)[0][1] * 100  # Class 1 probability
        
        confidence = "Very low"
        if probability >= 75:
            confidence = "High"
        elif probability >= 50:
            confidence = "Medium"
        elif probability >= 25:
            confidence = "Low"
        
        return {
            "status": "success",
            "probability": probability,
            "prediction": int(prediction),  # 0 = clean, 1 = stego
            "confidence": confidence,
            "message": f"Analysis complete: {probability:.2f}% probability of hidden data"
        }
    
    except Exception as e:
        return {"status": "error", "message": f"Analysis failed: {str(e)}"}

def train_steganalysis_model(clean_dir, stego_dir, model_output_path='stego_model.pkl'):
    """
    Train a machine learning model to detect steganography.
    
    Parameters:
    - clean_dir: Directory containing clean images (without steganography)
    - stego_dir: Directory containing images with hidden data
    - model_output_path: Path to save the trained model
    
    Returns:
    - Dictionary with training results and metrics
    """
    if not ML_AVAILABLE:
        return {"status": "error", "message": "scikit-learn is not available"}
    
    try:
        if not os.path.isdir(clean_dir):
            return {"status": "error", "message": f"Clean images directory not found: {clean_dir}"}
        if not os.path.isdir(stego_dir):
            return {"status": "error", "message": f"Stego images directory not found: {stego_dir}"}
        
        print("Extracting features from clean images...")
        clean_features = []
        clean_files = [f for f in os.listdir(clean_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp'))]
        
        if len(clean_files) == 0:
            return {"status": "error", "message": f"No valid images found in clean directory: {clean_dir}"}
        
        for img_file in clean_files:
            img_path = os.path.join(clean_dir, img_file)
            features = extract_steganalysis_features(img_path)
            if features is not None:
                clean_features.append(features)
        
        print("Extracting features from stego images...")
        stego_features = []
        stego_files = [f for f in os.listdir(stego_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp'))]
        
        if len(stego_files) == 0:
            return {"status": "error", "message": f"No valid images found in stego directory: {stego_dir}"}
        
        for img_file in stego_files:
            img_path = os.path.join(stego_dir, img_file)
            features = extract_steganalysis_features(img_path)
            if features is not None:
                stego_features.append(features)
        
        # Create dataset
        X = np.vstack((clean_features, stego_features))
        y = np.hstack((np.zeros(len(clean_features)), np.ones(len(stego_features))))
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        print("Training model...")
        clf.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = clf.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        # Save model
        model_data = {
            'model': clf,
            'scaler': scaler,
            'metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            },
            'train_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        joblib.dump(model_data, model_output_path)
        
        return {
            "status": "success",
            "model_path": model_output_path,
            "accuracy": accuracy * 100,
            "precision": precision * 100,
            "recall": recall * 100,
            "f1": f1 * 100,
            "clean_samples": len(clean_features),
            "stego_samples": len(stego_features),
            "message": f"Model trained successfully. Accuracy: {accuracy*100:.2f}%"
        }
        
    except Exception as e:
        return {"status": "error", "message": f"Training failed: {str(e)}"} 