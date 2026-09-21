# AUDIT — Encryption Toolkit (pre-refactor)

Audit of the previous single-file `index.html` (~26 kB of inline script,
29 inline `onclick` handlers, 30 `style=` attributes). The cryptography
was real Web Crypto and mostly used correctly; the findings are about
parameters, a biased generator, an unverifiable claim, and code no strict
policy could run. Line numbers refer to the original file.

---

## A. Cryptographic parameters and correctness

### A1 — PBKDF2 at 100,000 iterations
Line 445. Adequate in 2017; OWASP's 2023 guidance for PBKDF2-HMAC-SHA-256
is 600,000. **Fix:** `PBKDF2_ITERATIONS = 600000`, recorded in the
envelope so old envelopes still open and the count is visible on the page.

### A2 — Biased password generator
Line 774: `chars[arr[i] % chars.length]`. A 32-bit draw modulo an
alphabet whose size does not divide 2³² over-selects the first characters.
For 26 letters the bias is small; for a 95-character set it is measurable.
**Fix:** rejection sampling below the largest multiple of the alphabet
size; a test injects draws above the limit and asserts they are skipped;
another checks uniformity over 20,000 draws.

### A3 — Decrypt read the ciphertext from wherever it could find one
Line 474: `document.getElementById('aes-plaintext').value || document.getElementById('aes-output').textContent`
— so "Decrypt" with the plaintext box still full re-parsed the plaintext as
a ciphertext and reported "wrong passphrase". **Fix:** the envelope is
versioned and self-describing (`v2.` prefix, seven fields), parsing
errors are named, and the data key is wrapped with AES-KW so a wrong
passphrase fails at unwrap with its own message, distinct from a modified
ciphertext.

### A4 — No associated data, no key wrapping, no HKDF
The blueprint asked for all three. **Fix:** `sealWithPassphrase()` binds
associated data into AES-GCM, wraps a random data key under a
PBKDF2-derived key-encryption key with AES-KW (RFC 3394), and `hkdf()`
exposes RFC 5869 derivation. Each is tested against its published vector.

### A5 — Entropy estimate rounded before penalties, no pattern penalty
Line 697 floored `length × log2(charset)` and reported patterns without
letting them affect the score. **Fix:** ten bits off per detected pattern,
sequences and common substrings detected, crack-time assumptions stated on
the page as assumptions.

### A6 — Benchmark buffer requested 1 MiB of entropy in one call
The rebuild's first benchmark hit `QuotaExceededError`: `getRandomValues`
refuses more than 65,536 bytes per call. **Fix:** chunked fill (found in
the smoke test, kept here because it is the kind of bug that only appears
when the page is run).

## B. Claims

### B1 — "Steganography — Hide Text in Images"
The implementation (line 55 onwards) was a real LSB embed over a canvas,
but it wrote no header: extraction of an empty carrier produced garbage
of a random length, and nothing said that saving as JPEG would destroy the
payload. **Fix:** a 4-byte magic and length prefix so an empty carrier
returns "no payload"; the page states PNG survives and JPEG does not; the
change fraction is reported; the module is pure and tested for round trip,
capacity, non-mutation and corrupted length.

### B2 — HMAC verification by string equality
Line 620 compared hex strings with `===`. Not exploitable here
(everything is local), but it is the wrong habit. **Fix:** `equalBytes()`
compares in constant time; the tests cover a one-nibble mismatch and a
non-hex tag.

## C. Security and policy

### C1 — No CSP; inline handlers and styles; an unused chart library
29 `onclick` (first at line 118), 30 `style=` (line 115), Chart.js loaded
(line 7) and never used. **Fix:** `default-src 'none'; script-src 'self';
connect-src 'none'` — the page cannot make a network request; listeners in
`src/main.js`; no third-party script at all.

### C2 — Private key material shown
Line 173 rendered a placeholder for the private JWK; earlier revisions
printed it. **Fix:** only the public key is displayed, abbreviated; keys
are ephemeral and never exported.

## D. Structure

### D1 — Nothing testable, no vectors
Every routine read from the DOM. **Fix:** `src/{encoding,symmetric,hashing,asymmetric,password,steg}.js`
are pure and tested — 21 tests including NIST GCM test case 16, RFC 5869
case 1, RFC 3394 §4.6, PBKDF2 (1 and 4096 iterations), FIPS 180-4 "abc"
for SHA-256/384/512, RFC 4231 case 2, RSA-OAEP and signature round trips
with tamper and wrong-key cases, and the generator's rejection path.
