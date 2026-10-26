// Verifies the from-scratch DES in templates/chat.html against standard test vectors.
// Run from the repository root:  node tests/des_test_vectors.js
const fs = require('fs');
const path = require('path');
globalThis.crypto = require('crypto').webcrypto;

// Extract the DES module from the page and expose the raw block function for ECB tests.
const html = fs.readFileSync(path.join(__dirname, '..', 'templates', 'chat.html'), 'utf8');
const start = html.indexOf('const DES = (() => {');
const end = html.indexOf('})();', start) + 5;
let src = html.slice(start, end).replace('return {',
  'return { _enc:(b,k)=>desBlock(b,generateSubkeys(k)), _dec:(b,k)=>desBlock(b,[...generateSubkeys(k)].reverse()),');
const DES = new Function(src + '; return DES;')();

const hex = s => Uint8Array.from(s.match(/../g).map(h => parseInt(h, 16)));
const toHex = b => Buffer.from(b).toString('hex').toUpperCase();
let failed = 0;
const check = (name, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}: ${got}${ok ? '' : '  (expected ' + want + ')'}`);
};

// Single-block vectors (key, plaintext, ciphertext)
const vectors = [
  ['133457799BBCDFF1', '0123456789ABCDEF', '85E813540F0AB405'], // textbook example (Stallings)
  ['0123456789ABCDEF', '4E6F772069732074', '3FA40E8A984D4815'], // "Now is t"
];
for (const [k, p, c] of vectors) {
  check(`encrypt ${p} with ${k}`, toHex(DES._enc(hex(p), hex(k))), c);
  check(`decrypt ${c} with ${k}`, toHex(DES._dec(hex(c), hex(k))), p);
}

// CBC mode: round trip and randomised IV
const msg = new TextEncoder().encode('Hello, this is a DES-CBC round-trip test!');
const key = crypto.getRandomValues(new Uint8Array(8));
const c1 = DES.encrypt(msg, key), c2 = DES.encrypt(msg, key);
check('CBC round trip', new TextDecoder().decode(DES.decrypt(c1, key)), new TextDecoder().decode(msg));
check('same plaintext twice gives different ciphertext (random IV)', String(toHex(c1) !== toHex(c2)), 'true');

console.log(failed ? `\n${failed} test(s) FAILED` : '\nALL TESTS PASSED');
process.exit(failed ? 1 : 0);
