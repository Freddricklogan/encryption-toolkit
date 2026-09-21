import { describe, expect, it } from 'vitest';
import { fromHex, toHex, utf8 } from '../src/encoding.js';
import { aesGcmDecrypt, aesGcmEncrypt, hkdf, openText, parseEnvelope, pbkdf2, sealText, sealWithPassphrase, unwrapKey, wrapKey } from '../src/symmetric.js';

describe('NIST / RFC vectors', () => {
  it('AES-256-GCM matches NIST GCM spec test case 16 (with AAD)', async () => {
    const key = fromHex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
    const iv = fromHex('cafebabefacedbaddecaf888');
    const pt = fromHex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
    const aad = fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
    const ct = await aesGcmEncrypt(key, iv, pt, aad);
    expect(toHex(ct)).toBe('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b');
    expect(await aesGcmDecrypt(key, iv, ct, aad)).toEqual(pt);
    await expect(aesGcmDecrypt(key, iv, ct, fromHex('00'))).rejects.toThrow();
  });
  it('HKDF-SHA256 matches RFC 5869 test case 1', async () => {
    const okm = await hkdf(fromHex('0b'.repeat(22)), { salt: fromHex('000102030405060708090a0b0c'), info: fromHex('f0f1f2f3f4f5f6f7f8f9'), length: 42 });
    expect(toHex(okm)).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });
  it('AES-KW matches RFC 3394 §4.6 (256-bit KEK, 128-bit key)', async () => {
    const kek = fromHex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    const key = fromHex('00112233445566778899AABBCCDDEEFF');
    const wrapped = await wrapKey(kek, key);
    expect(toHex(wrapped)).toBe('64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7');
    expect(await unwrapKey(kek, wrapped)).toEqual(key);
    await expect(unwrapKey(fromHex('00'.repeat(32)), wrapped)).rejects.toThrow();
  });
  it('PBKDF2-HMAC-SHA256 matches the RFC 6070-style vector (password/salt, 1 iteration)', async () => {
    const dk = await pbkdf2('password', utf8('salt'), { iterations: 1, length: 256 });
    expect(toHex(dk)).toBe('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
    const dk4096 = await pbkdf2('password', utf8('salt'), { iterations: 4096, length: 256 });
    expect(toHex(dk4096)).toBe('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
  });
});

describe('passphrase envelope', () => {
  const fixedRandom = (n) => Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
  it('round-trips text with associated data and is deterministic given a fixed random source', async () => {
    const env = await sealText('correct horse', 'attack at dawn', { aad: 'msg-42', iterations: 1000, random: fixedRandom });
    expect(env.startsWith('v2.')).toBe(true);
    expect(env.split('.')).toHaveLength(7);
    expect(await sealText('correct horse', 'attack at dawn', { aad: 'msg-42', iterations: 1000, random: fixedRandom })).toBe(env);
    const opened = await openText('correct horse', env);
    expect(opened).toEqual({ text: 'attack at dawn', aad: 'msg-42' });
  });
  it('rejects a wrong passphrase, a modified ciphertext and modified associated data with distinct messages', async () => {
    const env = await sealText('pw', 'hello', { aad: 'ctx', iterations: 1000 });
    await expect(openText('nope', env)).rejects.toThrow(/wrong passphrase/);
    const parts = env.split('.');
    const ct = parts[5];
    parts[5] = ct.slice(0, -2) + (ct.endsWith('AA') ? 'AB' : 'AA');
    await expect(openText('pw', parts.join('.'))).rejects.toThrow(/authentication failed/);
    const p2 = env.split('.');
    p2[4] = 'Y3R5'; // "cty"
    await expect(openText('pw', p2.join('.'))).rejects.toThrow(/authentication failed/);
  });
  it('validates the envelope shape and iteration bounds', async () => {
    expect(() => parseEnvelope('v1.a.b.c')).toThrow(/v2 envelope/);
    expect(() => parseEnvelope('v2.a.b.c.d.e.10')).toThrow(/iteration/);
    await expect(sealWithPassphrase('', utf8('x'))).rejects.toThrow(/passphrase/);
    const env = await sealWithPassphrase('p', utf8('x'), { iterations: 1000 });
    expect(parseEnvelope(env).iterations).toBe(1000);
    expect(parseEnvelope(env).wrapped).toHaveLength(40);
  });
});
