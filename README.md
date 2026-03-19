# Encryption Toolkit

A professional, interactive cryptography toolkit built with the Web Crypto API. Encrypt, decrypt, hash, sign, and analyze data directly in the browser with zero server dependencies.

## Features

### Encryption & Decryption
- **AES-256-GCM** — Industry-standard symmetric encryption with authenticated encryption
- **RSA-OAEP** — Asymmetric encryption with 2048/4096-bit key pair generation
- **Base64** — Encoding and decoding for data transport

### Hashing & Integrity
- **SHA-256 / SHA-512** — Cryptographic hash generation with optional salt
- **HMAC** — Keyed-hash message authentication codes for data integrity
- **File Hashing** — Drag-and-drop file integrity verification

### Digital Signatures
- **RSA-PSS Signing** — Create and verify digital signatures
- **Key Pair Management** — Generate, export, and import RSA key pairs
- **Signature Verification** — Validate document authenticity

### Password Analysis
- **Strength Meter** — Real-time entropy calculation and scoring
- **Crack Time Estimation** — Estimated brute-force duration at various scales
- **Pattern Detection** — Identifies dictionary words, sequences, and common patterns

### Algorithm Benchmarks
- **Performance Comparison** — Side-by-side speed tests across algorithms
- **Key Size Analysis** — Visual comparison of security levels vs performance
- **Use Case Guide** — Recommendations for selecting the right algorithm

### Steganography Demo
- **Text-in-Image** — Hide and extract messages within canvas-generated images
- **Visual Demonstration** — See how LSB steganography works at the pixel level

## Technologies

- **Web Crypto API** — Native browser cryptography (no external crypto libraries)
- **HTML5 Canvas** — Steganography and visual demonstrations
- **Chart.js** — Algorithm benchmark visualizations
- **CSS Grid & Flexbox** — Responsive layout system
- **Vanilla JavaScript** — Zero framework dependencies

## How to Use

1. Open `index.html` in any modern browser (Chrome, Firefox, Safari, Edge)
2. Select a tool from the tabbed navigation
3. Enter your data and configure parameters
4. Results appear instantly — all processing happens locally in your browser

### AES Encryption
1. Enter plaintext and a passphrase
2. Click "Encrypt" to generate ciphertext
3. Copy the encrypted output — paste it back with the same passphrase to decrypt

### RSA Key Pairs
1. Click "Generate Key Pair" to create public/private keys
2. Encrypt with the public key, decrypt with the private key
3. Export keys in PEM format for external use

### Digital Signatures
1. Generate or import an RSA key pair
2. Enter a message and click "Sign" to create a signature
3. Verify signatures by providing the message, signature, and public key

## Security Notes

- All cryptographic operations use the browser's native Web Crypto API
- No data is transmitted to any server — everything runs locally
- This tool is intended for **educational and development purposes**
- For production systems, use established libraries with proper key management

## Browser Compatibility

- Chrome 60+ / Edge 79+
- Firefox 55+
- Safari 11+
- Requires Web Crypto API and ES6 support

## Use Cases

- **Security Education** — Learn applied cryptography with hands-on tools
- **Development Testing** — Quick encryption/hashing during development
- **Security Auditing** — Password strength assessment and hash verification
- **Digital Forensics** — File integrity verification and signature validation

## File Structure

```
encryption-toolkit/
├── index.html    # Complete single-file application
└── README.md     # Documentation
```

## License

MIT License — provided for educational and professional use.
