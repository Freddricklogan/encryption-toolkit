/** Wires the crypto modules to the page. Every operation runs in the browser on Web Crypto; nothing is transmitted. */
import { exportJwk, generateRsaOaep, generateSigningKeys, rsaDecrypt, rsaEncrypt, rsaMaxPlaintext, sign, verify } from './asymmetric.js';
import { fromBase64, fromUtf8, toBase64, toHex, utf8 } from './encoding.js';
import { mountExecShell, tokens } from './exec-shell.js';
import { digest, digestText, HASHES, hmacSign, hmacVerify } from './hashing.js';
import { analyze, generatePassword, humanDuration, RATES } from './password.js';
import { capacityBytes, changedFraction, embedText, extractText } from './steg.js';
import { openText, PBKDF2_ITERATIONS, sealText } from './symmetric.js';
import { $, el, setText } from './ui.js';

const state = { ops: 0, lastVerified: null, rsa: null, sig: { kind: 'RSA-PSS', keys: null }, stegBefore: null, bench: null };
let shell;
const out = (id, text, isError = false) => {
  const e = $(id);
  e.textContent = text;
  e.classList.toggle('is-error', isError);
};
const count = () => {
  state.ops += 1;
  shell?.refreshKpis();
};

// --- Tabs ------------------------------------------------------------------------
function initTabs() {
  const buttons = [...document.querySelectorAll('.tab-button')];
  const select = (name) => {
    for (const b of buttons) {
      const on = b.dataset.tab === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', String(on));
      $(`tab-${b.dataset.tab}`).hidden = !on;
    }
  };
  for (const b of buttons) b.addEventListener('click', () => select(b.dataset.tab));
  select('aes');
  return select;
}

// --- AES envelope -------------------------------------------------------------------
async function aesSeal() {
  try {
    const t0 = performance.now();
    const env = await sealText($('aes-pass').value, $('aes-plaintext').value, { aad: $('aes-aad').value, iterations: PBKDF2_ITERATIONS });
    out('aes-output', env);
    setText('aes-time', `${(performance.now() - t0).toFixed(0)} ms, ${PBKDF2_ITERATIONS.toLocaleString()} PBKDF2 iterations`);
    count();
  } catch (err) {
    out('aes-output', err.message, true);
  }
}
async function aesOpen() {
  try {
    const t0 = performance.now();
    const r = await openText($('aes-pass').value, $('aes-plaintext').value);
    out('aes-output', `${r.text}\n\n— associated data verified: "${r.aad}"`);
    setText('aes-time', `${(performance.now() - t0).toFixed(0)} ms`);
    count();
  } catch (err) {
    out('aes-output', err.message, true);
  }
}

// --- RSA -------------------------------------------------------------------------------
async function rsaGen() {
  const bits = parseInt($('rsa-bits').value, 10);
  out('rsa-output', `Generating ${bits}-bit key pair…`);
  const t0 = performance.now();
  state.rsa = await generateRsaOaep(bits);
  const jwk = await exportJwk(state.rsa.publicKey);
  out('rsa-pub', JSON.stringify({ kty: jwk.kty, alg: jwk.alg, e: jwk.e, n: `${jwk.n.slice(0, 64)}… (${jwk.n.length} base64url chars)` }, null, 2));
  out('rsa-output', `Key pair generated in ${(performance.now() - t0).toFixed(0)} ms. OAEP-SHA-256 with a ${bits}-bit modulus can encrypt at most ${rsaMaxPlaintext(bits)} bytes; for anything larger, encrypt a data key and wrap it (see the AES tab).`);
  count();
}
async function rsaEnc() {
  if (!state.rsa) return out('rsa-output', 'Generate a key pair first.', true);
  try {
    const ct = await rsaEncrypt(state.rsa.publicKey, utf8($('rsa-plaintext').value));
    out('rsa-output', toBase64(ct));
    count();
  } catch {
    out('rsa-output', `Encryption failed — the message exceeds ${rsaMaxPlaintext(parseInt($('rsa-bits').value, 10))} bytes for this key.`, true);
  }
  return undefined;
}
async function rsaDec() {
  if (!state.rsa) return out('rsa-output', 'Generate a key pair first.', true);
  try {
    out('rsa-output', fromUtf8(await rsaDecrypt(state.rsa.privateKey, fromBase64($('rsa-plaintext').value))));
    count();
  } catch {
    out('rsa-output', 'Decryption failed — not a ciphertext for this key.', true);
  }
  return undefined;
}

// --- Hashing ----------------------------------------------------------------------------
async function hashLive() {
  const text = $('hash-input').value;
  const rows = await Promise.all(HASHES.map(async (h) => [h, toHex(await digestText(h, text))]));
  const list = $('hash-output');
  list.replaceChildren();
  for (const [h, hex] of rows) list.append(el('dt', { text: h }), el('dd', { text: hex }));
}
async function hashFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const t0 = performance.now();
  const hex = toHex(await digest($('hash-file-algo').value, bytes));
  out('hash-file-output', `${file.name} (${bytes.length.toLocaleString()} bytes)\n${$('hash-file-algo').value}: ${hex}\n${(performance.now() - t0).toFixed(1)} ms`);
  const expected = $('hash-expected').value.trim().toLowerCase();
  if (expected) {
    state.lastVerified = expected === hex;
    out('hash-compare', state.lastVerified ? 'Matches the expected digest.' : 'Does NOT match the expected digest.', !state.lastVerified);
  }
  count();
}

// --- HMAC ---------------------------------------------------------------------------------
async function hmacGen() {
  const tag = await hmacSign($('hmac-algo').value, utf8($('hmac-key').value), utf8($('hmac-msg').value));
  out('hmac-output', toHex(tag));
  count();
}
async function hmacCheck() {
  const ok = await hmacVerify($('hmac-algo').value, utf8($('hmac-key').value), utf8($('hmac-msg').value), $('hmac-tag').value);
  out('hmac-output', ok ? 'Tag verified (constant-time comparison).' : 'Tag does not verify.', !ok);
  count();
}

// --- Signatures ------------------------------------------------------------------------------
async function sigGen() {
  state.sig.kind = $('sig-kind').value;
  state.sig.keys = await generateSigningKeys(state.sig.kind);
  out('sig-output', `${state.sig.kind} key pair generated (${state.sig.kind === 'ECDSA' ? 'P-256, 64-byte signatures' : '2048-bit, 256-byte signatures'}).`);
  count();
}
async function sigSign() {
  if (!state.sig.keys) return out('sig-output', 'Generate keys first.', true);
  const s = await sign(state.sig.kind, state.sig.keys.privateKey, utf8($('sig-msg').value));
  $('sig-value').value = toBase64(s);
  out('sig-output', `Signed ${utf8($('sig-msg').value).length} bytes; signature ${s.length} bytes.`);
  count();
  return undefined;
}
async function sigVerify() {
  if (!state.sig.keys) return out('sig-output', 'Generate keys first.', true);
  try {
    const ok = await verify(state.sig.kind, state.sig.keys.publicKey, fromBase64($('sig-value').value), utf8($('sig-msg').value));
    out('sig-output', ok ? 'Signature valid for this message and key.' : 'Signature INVALID — the message or signature was altered.', !ok);
  } catch {
    out('sig-output', 'Signature is not valid base64.', true);
  }
  count();
  return undefined;
}

// --- Passwords --------------------------------------------------------------------------------
function pwAnalyze() {
  const a = analyze($('pw-input').value);
  $('pw-bar').style.setProperty('width', `${(a.score / 4) * 100}%`);
  $('pw-bar').dataset.score = String(a.score);
  setText('pw-label', a.label);
  setText('pw-entropy', `${a.entropy} bits`);
  setText('pw-charset', String(a.charset));
  setText('pw-length', String(a.length));
  setText('pw-online', humanDuration(a.crackOnline));
  setText('pw-offline', humanDuration(a.crackOffline));
  setText('pw-patterns', a.patterns.length ? a.patterns.join('; ') : 'none detected');
}
function pwGenerate() {
  try {
    const pw = generatePassword(parseInt($('gen-len').value, 10), { lower: $('gen-lower').checked, upper: $('gen-upper').checked, digits: $('gen-digits').checked, symbols: $('gen-symbols').checked });
    out('gen-output', pw);
    $('pw-input').value = pw;
    pwAnalyze();
    count();
  } catch (err) {
    out('gen-output', err.message, true);
  }
}

// --- Benchmarks --------------------------------------------------------------------------------
async function runBench() {
  // getRandomValues refuses more than 65,536 bytes per call; fill 1 MiB in chunks.
  const data = new Uint8Array(1 << 20);
  for (let off = 0; off < data.length; off += 65536) crypto.getRandomValues(data.subarray(off, off + 65536));
  const results = [];
  const time = async (name, n, fn) => {
    const t0 = performance.now();
    for (let i = 0; i < n; i += 1) await fn();
    const ms = (performance.now() - t0) / n;
    results.push({ name, ms, mbps: 1 / (ms / 1000) });
  };
  out('bench-output', 'Running…');
  for (const h of HASHES) await time(h, 8, () => digest(h, data));
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const { aesGcmEncrypt } = await import('./symmetric.js');
  await time('AES-256-GCM', 8, () => aesGcmEncrypt(key, iv, data));
  await time('HMAC-SHA-256', 8, () => hmacSign('SHA-256', key, data));
  state.bench = results;
  const tbody = $('bench-tbody');
  tbody.replaceChildren();
  for (const r of results) {
    const tr = el('tr');
    tr.append(el('td', { text: r.name }), el('td', { text: `${r.ms.toFixed(2)} ms` }), el('td', { text: `${r.mbps.toFixed(0)} MiB/s` }));
    tbody.append(tr);
  }
  out('bench-output', `Measured on this device just now: 1 MiB input, 8 runs each, wall-clock through Web Crypto. Numbers vary by browser and CPU; nothing here is a benchmark of the algorithms themselves.`);
  count();
}

// --- Steganography ---------------------------------------------------------------------------------
function stegDraw() {
  const c = $('steg-canvas');
  const ctx = c.getContext('2d', { willReadFrequently: true });
  const g = ctx.createLinearGradient(0, 0, 256, 256);
  g.addColorStop(0, tokens().panel2);
  g.addColorStop(1, tokens().ok);
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, 256, 256);
  for (let i = 0; i < 40; i += 1) {
    ctx.fillStyle = `hsla(${i * 9}, 70%, 60%, .35)`;
    ctx.beginPath();
    ctx.arc((i * 61) % 256, (i * 37) % 256, 8 + (i % 5) * 6, 0, Math.PI * 2);
    ctx.fill();
  }
  state.stegBefore = ctx.getImageData(0, 0, 256, 256).data.slice();
  setText('steg-capacity', `${capacityBytes(256 * 256).toLocaleString()} bytes`);
}
function stegHide() {
  const ctx = $('steg-canvas').getContext('2d', { willReadFrequently: true });
  const img = ctx.getImageData(0, 0, 256, 256);
  try {
    const after = embedText(img.data, $('steg-message').value);
    img.data.set(after);
    ctx.putImageData(img, 0, 0);
    out('steg-output', `Embedded ${utf8($('steg-message').value).length} bytes. ${(changedFraction(state.stegBefore, after) * 100).toFixed(2)}% of channel values changed, each by at most 1. Export as PNG to keep it; JPEG would destroy it.`);
    count();
  } catch (err) {
    out('steg-output', err.message, true);
  }
}
function stegReveal() {
  const px = $('steg-canvas').getContext('2d', { willReadFrequently: true }).getImageData(0, 0, 256, 256).data;
  const text = extractText(px);
  out('steg-output', text === null ? 'No payload found (no magic header).' : `Extracted: ${text}`, text === null);
  count();
}

// --- Boot ---------------------------------------------------------------------------------------------
async function boot() {
  const selectTab = initTabs();
  $('aes-seal').addEventListener('click', aesSeal);
  $('aes-open').addEventListener('click', aesOpen);
  $('rsa-gen').addEventListener('click', rsaGen);
  $('rsa-enc').addEventListener('click', rsaEnc);
  $('rsa-dec').addEventListener('click', rsaDec);
  $('hash-input').addEventListener('input', hashLive);
  $('hash-file').addEventListener('change', (e) => e.target.files[0] && hashFile(e.target.files[0]));
  $('hmac-gen').addEventListener('click', hmacGen);
  $('hmac-verify').addEventListener('click', hmacCheck);
  $('sig-gen').addEventListener('click', sigGen);
  $('sig-sign').addEventListener('click', sigSign);
  $('sig-verify').addEventListener('click', sigVerify);
  $('pw-input').addEventListener('input', pwAnalyze);
  $('gen-run').addEventListener('click', pwGenerate);
  $('bench-run').addEventListener('click', runBench);
  $('steg-reset').addEventListener('click', stegDraw);
  $('steg-hide').addEventListener('click', stegHide);
  $('steg-reveal').addEventListener('click', stegReveal);
  setText('rates-note', `Crack-time estimates assume ${RATES.online.toLocaleString()} guesses/s online (throttled) and ${RATES.offlineFastHash.toExponential(0)} guesses/s offline against a fast hash; both are stated assumptions, not measurements.`);
  await hashLive();
  pwAnalyze();
  stegDraw();

  shell = mountExecShell({
  theme: 'graphite',
  accent: 'secondary',
    title: 'Encryption Toolkit',
    tagline: 'Applied cryptography in the browser on Web Crypto: AES-256-GCM envelopes with PBKDF2, AES-KW key wrapping and associated data; RSA-OAEP; SHA-2 and HMAC; RSA-PSS and ECDSA signatures; an unbiased password generator; LSB steganography. Tested against NIST and RFC vectors. Nothing leaves the page.',
    repo: 'https://github.com/Freddricklogan/encryption-toolkit',
    pagesUrl: 'https://freddricklogan.github.io/encryption-toolkit/',
    badges: [{ label: 'NIST / RFC vectors', tone: 'accent' }, { label: 'Web Crypto only', dot: true }, { label: 'No network', dot: true }],
    kpis: [
      { label: 'Operations this session', compute: () => state.ops, tone: 'accent' },
      { label: 'PBKDF2 iterations', compute: () => PBKDF2_ITERATIONS.toLocaleString() },
      { label: 'Signature scheme', compute: () => (state.sig.keys ? state.sig.kind : '—') },
      { label: 'Last file digest check', compute: () => (state.lastVerified === null ? '—' : state.lastVerified ? 'match' : 'mismatch'), tone: state.lastVerified === false ? 'danger' : 'ok' },
      { label: 'SHA-256 throughput', compute: () => (state.bench ? `${state.bench[0].mbps.toFixed(0)} MiB/s` : 'run benchmark'), tone: 'muted' }
    ],
    tour: [
      { selector: '#tab-aes', title: 'A versioned envelope, not a bare ciphertext', body: 'PBKDF2 derives a key-encryption key that wraps a random data key (AES-KW); the data key encrypts under AES-GCM with the associated data bound in. Seal the sample text.', action: async () => { selectTab('aes'); await aesSeal(); } },
      { selector: '#aes-output', title: 'Tamper and it fails loudly', body: 'Change one character of the ciphertext or the associated data and decryption reports which check failed — the tests do exactly this.', action: async () => { $('aes-plaintext').value = $('aes-output').textContent; await aesOpen(); } },
      { selector: '#tab-hash', title: 'Digests match FIPS 180-4', body: 'The SHA-256 of "abc" is ba7816bf…; the tests pin all three digests and the RFC 4231 HMAC vector.', action: async () => { selectTab('hash'); $('hash-input').value = 'abc'; await hashLive(); } },
      { selector: '#tab-password', title: 'An unbiased generator', body: 'The old page took a 32-bit draw modulo the alphabet — biased for any alphabet whose size does not divide 2³². This one rejects draws above the largest multiple; a test forces the rejection path.', action: () => { selectTab('password'); pwGenerate(); } },
      { selector: '#tab-steg', title: 'Steganography that says what it survives', body: 'One bit per colour channel with a magic header and a length; PNG keeps it, JPEG destroys it. Hide the sample message and read it back.', action: () => { selectTab('steg'); stegHide(); stegReveal(); } }
    ]
  });
  shell.refreshKpis();
}

boot();
