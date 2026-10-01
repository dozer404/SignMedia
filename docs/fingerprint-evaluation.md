# Decoded Visual Fingerprint Evaluation

This document evaluates perceptual visual fingerprinting over decoded image and video frame content.

## 1. Normalization Pipeline
1. **Decode**: Raw image/video frame bytes are decoded into uncompressed RGB/Luma pixels.
2. **Resize**: Image is resized to a normalized 16x16 grid.
3. **Algorithm**: Gradient perceptual hashing (`img_hash::HashAlg::Gradient`).
4. **Encoding**: Base64 representation of the 256-bit perceptual hash.

## 2. Distance and Similarity Thresholds
- **Hamming Distance $\le 10$**: High visual similarity (likely recompressed or slightly resized version of same image).
- **Hamming Distance $> 25$**: Unrelated content.
