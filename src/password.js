/** Password strength estimate and an unbiased generator. Pure except for the injected random source. */

export const CHARSETS = { lower: 'abcdefghijklmnopqrstuvwxyz', upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', digits: '0123456789', symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?' };
const COMMON = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'iloveyou', 'monkey', 'dragon', 'football'];

/** Guess rates are stated assumptions, not measurements: online throttled, offline fast hash (per second). */
export const RATES = { online: 100, offlineFastHash: 1e10 };

export function charsetSize(pw) {
  let n = 0;
  if (/[a-z]/.test(pw)) n += 26;
  if (/[A-Z]/.test(pw)) n += 26;
  if (/[0-9]/.test(pw)) n += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) n += 33;
  return n;
}

export function patterns(pw) {
  const found = [];
  const lower = pw.toLowerCase();
  if (pw.length && /^[a-zA-Z]+$/.test(pw)) found.push('letters only');
  if (pw.length && /^[0-9]+$/.test(pw)) found.push('digits only');
  if (/(.)\1{2,}/.test(pw)) found.push('a character repeated three or more times');
  if (/(?:abc|bcd|cde|123|234|345|456|567|678|789|qwe|wer|ert|asd|sdf|zxc)/i.test(pw)) found.push('a keyboard or alphabet sequence');
  if (COMMON.some((c) => lower.includes(c))) found.push('a common password as a substring');
  if (/^\w+\d{1,4}$/.test(pw) && /[a-zA-Z]/.test(pw)) found.push('a word followed by digits');
  return found;
}

/** Entropy in bits assuming uniform choice from the detected character set, penalised by patterns. */
export function analyze(pw) {
  if (!pw) return { length: 0, charset: 0, entropy: 0, patterns: [], score: 0, label: 'empty', crackOnline: 0, crackOffline: 0 };
  const cs = charsetSize(pw);
  const raw = pw.length * Math.log2(cs || 1);
  const found = patterns(pw);
  const entropy = Math.round(Math.max(0, raw - 10 * found.length) * 10) / 10;
  const guesses = 2 ** entropy / 2; // expected guesses: half the keyspace
  const score = entropy < 28 ? 0 : entropy < 36 ? 1 : entropy < 60 ? 2 : entropy < 80 ? 3 : 4;
  const label = ['very weak', 'weak', 'fair', 'strong', 'very strong'][score];
  return { length: pw.length, charset: cs, entropy, patterns: found, score, label, crackOnline: guesses / RATES.online, crackOffline: guesses / RATES.offlineFastHash };
}

export function humanDuration(seconds) {
  if (!Number.isFinite(seconds)) return 'beyond estimate';
  if (seconds < 1) return 'instant';
  const units = [['years', 31557600], ['days', 86400], ['hours', 3600], ['minutes', 60], ['seconds', 1]];
  for (const [name, size] of units) {
    if (seconds >= size) {
      const v = seconds / size;
      if (v > 1e15) return `over a quadrillion ${name}`;
      return `${v >= 100 ? Math.round(v).toLocaleString() : v.toFixed(1)} ${name}`;
    }
  }
  return 'instant';
}

/**
 * Unbiased generator: rejection sampling on 32-bit draws so `alphabet.length` need not divide
 * 2^32 (plain modulo is biased whenever it does not). `random(n)` fills n Uint32 values.
 */
export function generatePassword(length, sets, random = (n) => crypto.getRandomValues(new Uint32Array(n))) {
  const alphabet = Object.entries(CHARSETS).filter(([k]) => sets[k]).map(([, v]) => v).join('');
  if (!alphabet) throw new Error('select at least one character set');
  if (!(Number.isInteger(length) && length >= 8 && length <= 128)) throw new Error('length must be 8–128');
  const limit = Math.floor(0x100000000 / alphabet.length) * alphabet.length;
  let out = '';
  while (out.length < length) {
    const draws = random(length * 2);
    for (const d of draws) {
      if (d < limit) out += alphabet[d % alphabet.length];
      if (out.length === length) break;
    }
  }
  return out;
}
