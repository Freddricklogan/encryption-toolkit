import { describe, expect, it } from 'vitest';
import { analyze, charsetSize, generatePassword, humanDuration, patterns, RATES } from '../src/password.js';

describe('analyze', () => {
  it('estimates entropy from the character set and penalises patterns', () => {
    expect(charsetSize('abc')).toBe(26);
    expect(charsetSize('aB1!')).toBe(95);
    expect(analyze('').label).toBe('empty');
    expect(patterns('password123')).toEqual(expect.arrayContaining(['a common password as a substring', 'a word followed by digits']));
    expect(patterns('aaab')).toContain('a character repeated three or more times');
    const weak = analyze('password123');
    const strong = analyze('T7#k9Qm2!vLx4Rp8');
    expect(weak.score).toBeLessThan(strong.score);
    expect(strong.entropy).toBeCloseTo(16 * Math.log2(95), 0);
    expect(strong.label).toBe('very strong');
    expect(weak.crackOffline).toBeLessThan(weak.crackOnline);
    expect(weak.crackOnline).toBeCloseTo(2 ** weak.entropy / 2 / RATES.online, 6);
  });
  it('formats durations', () => {
    expect(humanDuration(0.5)).toBe('instant');
    expect(humanDuration(90)).toBe('1.5 minutes');
    expect(humanDuration(2 * 86400)).toBe('2.0 days');
    expect(humanDuration(1e30)).toBe('over a quadrillion years');
    expect(humanDuration(Infinity)).toBe('beyond estimate');
  });
});

describe('generatePassword', () => {
  it('uses only the selected sets, honours length, and validates', () => {
    const pw = generatePassword(20, { lower: true, digits: true });
    expect(pw).toHaveLength(20);
    expect(pw).toMatch(/^[a-z0-9]+$/);
    expect(() => generatePassword(20, {})).toThrow(/character set/);
    expect(() => generatePassword(4, { lower: true })).toThrow(/length/);
  });
  it('rejects draws above the unbiased limit instead of taking them modulo the alphabet', () => {
    // Alphabet of 26; 2^32 mod 26 = 4, so values in [2^32 − 4, 2^32) must be rejected.
    const seq = [0xffffffff, 0xfffffffe, 0xfffffffd, 0xfffffffc, 25, 0, 1];
    let i = 0;
    const random = (n) => Uint32Array.from({ length: n }, () => seq[i++ % seq.length]);
    expect(generatePassword(8, { lower: true }, random).slice(0, 3)).toBe('zab');
  });
  it('is close to uniform over the alphabet (statistical tolerance)', () => {
    const counts = {};
    for (let k = 0; k < 200; k += 1) for (const c of generatePassword(100, { digits: true })) counts[c] = (counts[c] ?? 0) + 1;
    const values = Object.values(counts);
    expect(values).toHaveLength(10);
    const mean = 20000 / 10;
    for (const v of values) expect(Math.abs(v - mean) / mean).toBeLessThan(0.08);
  });
});
