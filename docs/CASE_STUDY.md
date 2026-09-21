# Case Study — Encryption Toolkit

**Repository:** [encryption-toolkit](https://github.com/Freddricklogan/encryption-toolkit) · **Live demo:** [freddricklogan.github.io/encryption-toolkit](https://freddricklogan.github.io/encryption-toolkit/) · **Author:** Freddrick Logan

---

## 1. Who has this problem

Instructors teaching applied cryptography to students who will write it into production code, developers at universities and agencies reaching for Web Crypto without a reference, security reviewers deciding whether a home-grown envelope is sound, and the consultant — I advise on security in higher education — asked to explain why "it encrypts and decrypts" is not "it is right". The primitives are in every browser; the parameters and habits around them are where the mistakes live.

## 2. The problem, as a scenario

A developer copies a browser encryption demo into a student-records tool. The demo derives keys with 100,000 PBKDF2 iterations because that was the number in 2017, compares an HMAC with string equality, generates "random" passwords with a modulo that favours the first letters of the alphabet, and stores ciphertext as three base64 fields with no version and no associated data, so a wrong passphrase and a corrupted record produce the same error. Its steganography extracts a random blob from an untouched image and calls it a message. Every call is the right API; every habit around it is wrong. The previous version of this page was that demo. I wrote it; its audit is in the repository.

## 3. What it costs to leave it alone

Habits copied into systems that hold real records: a KDF a cheap GPU brute-forces, passwords weaker than their length suggests, an authenticated cipher whose associated data is never bound, a support team that cannot tell a typo from tampering. I will not attach a figure — breach costs depend on what leaked, and this page holds nothing. What is certain is that each mistake has a published vector or a known test that catches it, and the old page had none.

## 4. The approach, and the alternative I rejected

I rebuilt the toolkit as pure modules over Web Crypto, each tested against its published vector. The passphrase envelope derives a key-encryption key with PBKDF2 at 600,000 iterations, wraps a random data key with AES-KW, encrypts under AES-256-GCM with associated data bound in, and records its version and iteration count, so a wrong passphrase fails at unwrap and a modified ciphertext or associated data fails at authentication with a different message. HKDF, SHA-2 digests, HMAC with constant-time comparison, RSA-OAEP with its limit stated, RSA-PSS and ECDSA signatures, an entropy analyser with printed assumptions, a rejection-sampled password generator and LSB steganography with a magic header complete the set. The content-security policy sets `connect-src 'none'`; the page cannot transmit anything.

The alternative I rejected was adding more algorithms. Twelve ciphers with no vectors teach breadth and nothing else; eight tools each pinned to a standard teach the discipline that transfers.

## 5. What the code does today

Real: every tool on the page — envelope, HKDF, RSA-OAEP, three digests, HMAC, two signature schemes, analyser and generator, steganography — plus a benchmark that measures this device and says so. Keys are ephemeral; nothing is stored or sent.

Simulated: nothing. The crack-time figures are arithmetic on two stated guess rates, labelled as assumptions.

Worth knowing: the envelope format is this repository's own, not a standard; RSA-OAEP with a 2048-bit key encrypts at most 190 bytes, stated and enforced; the steganography survives lossless PNG only; benchmark numbers belong to the machine running the page.

## 6. Evidence

Measured locally with the commands CI runs: 21 tests passing across six files; 99.34% statement and 93.58% branch coverage of the pure modules; ESLint and html-validate clean. Tests pin AES-256-GCM to NIST GCM test case 16 with associated data, HKDF to RFC 5869 case 1, AES-KW to RFC 3394 §4.6, PBKDF2-HMAC-SHA-256 at 1 and 4096 iterations, SHA-256/384/512 to FIPS 180-4 "abc", HMAC to RFC 4231 case 2; round-trip RSA-OAEP with the 190-byte limit and both signature schemes with tampered messages and wrong keys; force the generator's rejection path and bound its uniformity; round-trip the steganography with capacity, non-mutation and corrupted-length cases. Headless Chrome: zero console errors; a seal at 600,000 iterations in 69 milliseconds, opened with associated data verified, a wrong passphrase named; SHA-256 of "abc" beginning ba7816bf; the RFC 4231 tag generated and verified; ECDSA sign, verify, tamper, invalid; "password123" very weak at 26.9 bits with three patterns, a generated twenty-character password very strong; steganography hidden and revealed, an empty carrier reporting no payload; RSA-2048 round trip; SHA-256 at 964 MiB/s on this machine; five tour steps; no horizontal scroll at 1280 or 400 pixels. The smoke test also caught a real bug — `getRandomValues` refuses more than 65,536 bytes — fixed and recorded in the audit.

## 7. What it would take to run this in production

The primitives are production Web Crypto today. To use the envelope in a product it would need a written format specification, a key-management story for the passphrase or a hardware-backed key, a decision on Argon2id versus PBKDF2, and a review by someone who did not write it. Days for specification and review; the tests carry over.

## 8. Limits and next steps

No Argon2 (Web Crypto has none), a non-standard envelope, RSA limited to short secrets, steganography any statistical test detects. Next: Argon2id via WebAssembly with its own vectors, a JWE-compatible envelope so files interoperate, hybrid RSA-plus-AES for large payloads, and a detection demo showing why LSB is hiding, not encryption.

## 9. Who should look at this

**Hiring manager:** evidence that I implement cryptography to the standard, test it against the standard's vectors, and correct my own earlier mistakes in writing.
**Consulting client:** a review checklist in running code — KDF parameters, associated data, key wrapping, constant-time comparison, unbiased randomness — for any application encrypting in the browser.
**Engineer:** read `src/symmetric.js` and `tests/symmetric.test.js` for the envelope and the NIST and RFC vectors, and `src/password.js` for the rejection sampler.
