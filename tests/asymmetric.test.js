import { describe, expect, it } from 'vitest';
import { utf8 } from '../src/encoding.js';
import { exportJwk, generateRsaOaep, generateSigningKeys, rsaDecrypt, rsaEncrypt, rsaMaxPlaintext, sign, verify } from '../src/asymmetric.js';

describe('RSA-OAEP', () => {
  it('round-trips, enforces the plaintext limit, and rejects odd modulus sizes', async () => {
    const kp = await generateRsaOaep(2048);
    const msg = utf8('a short secret');
    const ct = await rsaEncrypt(kp.publicKey, msg);
    expect(ct).toHaveLength(256);
    expect(await rsaDecrypt(kp.privateKey, ct)).toEqual(msg);
    expect(rsaMaxPlaintext(2048)).toBe(190);
    await expect(rsaEncrypt(kp.publicKey, new Uint8Array(191))).rejects.toThrow();
    await expect(generateRsaOaep(1024)).rejects.toThrow(/modulus/);
    const jwk = await exportJwk(kp.publicKey);
    expect(jwk.kty).toBe('RSA');
    expect(jwk.e).toBe('AQAB');
  }, 30000);
});

describe('signatures', () => {
  it('RSA-PSS and ECDSA P-256 verify a signature and reject a tampered message or the wrong key', async () => {
    for (const kind of ['RSA-PSS', 'ECDSA']) {
      const kp = await generateSigningKeys(kind);
      const other = await generateSigningKeys(kind);
      const msg = utf8('sign me');
      const sig = await sign(kind, kp.privateKey, msg);
      expect(await verify(kind, kp.publicKey, sig, msg)).toBe(true);
      expect(await verify(kind, kp.publicKey, sig, utf8('sign mE'))).toBe(false);
      expect(await verify(kind, other.publicKey, sig, msg)).toBe(false);
      expect(sig.length).toBe(kind === 'ECDSA' ? 64 : 256);
    }
    await expect(generateSigningKeys('DSA')).rejects.toThrow(/kind/);
  }, 30000);
});
