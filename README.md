<h1 align="center">Encryption Toolkit</h1>

<p align="center">
  <em>Applied cryptography in the browser — AES-256, RSA, hashing, digital signatures, and steganography, powered by the Web Crypto API.</em>
</p>

<p align="center">
  <a href="https://freddricklogan.github.io/encryption-toolkit/"><img src="https://img.shields.io/badge/Live_Demo-Open_App-2a9d8f?style=for-the-badge&logo=github" alt="Live Demo"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Crypto-Web_Crypto_API-264653" alt="Web Crypto">
  <img src="https://img.shields.io/badge/Ciphers-AES--256_%7C_RSA-2a9d8f" alt="Ciphers">
  <img src="https://img.shields.io/badge/JavaScript-Vanilla_ES6-f7df1e?logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License">
</p>

---

## Overview

**Encryption Toolkit** is a hands-on applied-cryptography workbench that runs entirely in the browser.
It brings the core primitives of modern security — symmetric encryption, public-key encryption,
hashing, digital signatures, and steganography — into one interface so you can encrypt a message,
verify a signature, or hide data in an image and *see how each primitive behaves*.

Crucially, the cryptography is **real**: it uses the browser's native **Web Crypto API** rather than
toy implementations, so the AES and RSA operations are the same primitives production systems rely on.

> **▶ [Launch the live demo](https://freddricklogan.github.io/encryption-toolkit/)**

---

## Why this project

| Skill demonstrated | Where it shows up |
|:--|:--|
| **Applied cryptography** | AES-256 symmetric encryption, RSA public-key encryption |
| **Integrity & authenticity** | SHA hashing and digital signatures |
| **Secure API usage** | Correct use of the Web Crypto `SubtleCrypto` interface |
| **Steganography** | Hiding payloads within image data |
| **Front-end engineering** | Clean, dependency-free interface |

---

## Features

- **AES-256** symmetric encryption / decryption
- **RSA** public-key encryption and key generation
- **SHA** hashing for integrity checks
- **Digital signatures** — sign and verify
- **Steganography** — conceal and reveal data inside images

---

## Tech stack

- **Language:** Vanilla JavaScript (ES6+)
- **Cryptography:** Web Crypto API (`SubtleCrypto`)
- **Runtime:** 100% client-side — no backend, no install

---

## Run locally

```bash
git clone https://github.com/Freddricklogan/encryption-toolkit.git
cd encryption-toolkit
python3 -m http.server 8000
# then visit http://localhost:8000
```

> Cryptographic operations require a secure context; serving over `http://localhost` (or `https://`)
> ensures the Web Crypto API is available.

---

## Author

**Freddrick Logan** — Educational Technologist & Technology Leader
[GitHub](https://github.com/Freddricklogan) · [LinkedIn](https://www.linkedin.com/in/freddricklogan/)

## License

Released under the [MIT License](LICENSE).
