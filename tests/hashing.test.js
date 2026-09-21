import { describe, expect, it } from 'vitest';
import { fromHex, toHex, utf8 } from '../src/encoding.js';
import { digest, digestText, hmacSign, hmacVerify } from '../src/hashing.js';

describe('digests', () => {
  it('match FIPS 180-4 example vectors for "abc"', async () => {
    expect(toHex(await digestText('SHA-256', 'abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(toHex(await digestText('SHA-384', 'abc'))).toBe('cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7');
    expect(toHex(await digestText('SHA-512', 'abc'))).toBe('ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
    expect(toHex(await digest('SHA-256', new Uint8Array(0)))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    await expect(digest('MD5', new Uint8Array(0))).rejects.toThrow(/unsupported/);
  });
});

describe('HMAC', () => {
  it('matches RFC 4231 test case 2 and verifies in constant time', async () => {
    const key = utf8('Jefe');
    const msg = utf8('what do ya want for nothing?');
    expect(toHex(await hmacSign('SHA-256', key, msg))).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    expect(toHex(await hmacSign('SHA-512', key, msg))).toBe('164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737');
    expect(await hmacVerify('SHA-256', key, msg, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')).toBe(true);
    expect(await hmacVerify('SHA-256', key, msg, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3844')).toBe(false);
    expect(await hmacVerify('SHA-256', key, msg, 'not hex')).toBe(false);
    expect(fromHex('5b')).toEqual(Uint8Array.from([0x5b]));
  });
});
