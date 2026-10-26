# Secure Image Encryption Application

> 🇩🇪 Webanwendung zum verschlüsselten Austausch von Bildern und Nachrichten in Echtzeit – DES selbst implementiert, RSA-Schlüsselaustausch, digitale Signaturen.

Client–server web application for exchanging **encrypted images and messages in real time**.
Team project for CMSE 456 – Network & Information Security, Eastern Mediterranean University (Spring 2026).

**Tech:** Python · Flask · Flask-SocketIO · SQLite · JavaScript (Web Crypto API)

## Highlights

- **DES implemented from scratch in JavaScript** — key schedule (PC-1/PC-2, rotations), 16 Feistel rounds with
  expansion, S-boxes and P-permutation, initial/final permutation, **CBC mode** with a random IV and **PKCS#7** padding.
  Verified against standard DES test vectors (`tests/des_test_vectors.js`).
- **Hybrid cryptosystem** — every message/image gets a fresh DES session key; the session key is exchanged with
  **RSA-2048 (OAEP)**, so the server only ever stores and forwards ciphertext.
- **Digital signatures** — the sender signs the ciphertext with **RSA-SHA256** (RSASSA-PKCS1-v1_5).
- **Key rotation** in the browser every 60 s, with **separate key pairs for signing and encryption** and a key history
  so older messages stay decryptable.
- **Real time** over Socket.IO, **HTTPS/WSS** with a self-signed certificate, and an **admin panel** with a live
  activity log that shows messages arriving only as ciphertext.

## How a message travels

```
Sender's browser                        Server                    Receiver's browser
1. random 8-byte DES session key
2. DES-CBC encrypt the image/text
3. sign the ciphertext (RSA-SHA256)
4. wrap the session key with the
   receiver's RSA public key (OAEP)
   (+ a copy for the sender's history)
5. emit over Socket.IO  ───────────►  6. store ciphertext,  ─────►  7. unwrap session key (private key)
                                         forward if online           8. DES-CBC decrypt
```

## Run locally

```bash
pip install -r requirements.txt cryptography
python gen_cert.py          # creates cert.pem / key.pem for local HTTPS
python app.py
```

Open **https://localhost:5000** (note: http**s**) and accept the self-signed certificate warning
(*Advanced → Proceed*). To chat between two users, use a normal and an incognito window.

Verify the DES implementation:

```bash
node tests/des_test_vectors.js
```

## Known limitations (and how I would fix them)

This was built as a course project; a code review afterwards found the following. Listed openly because knowing a
design's weaknesses is part of security work.

| Limitation | Fix |
|---|---|
| DES (56-bit key) is obsolete — required by the course | AES-256-GCM via the Web Crypto API |
| Users' RSA **private keys are stored on the server** (for message history), so it is not true end-to-end encryption | keep private keys in the browser, or store them encrypted with a key derived from the user's password (PBKDF2/Argon2) |
| Signatures are created, but the receiver never gets the sender's **signing** public key, so they are not verified | publish `pubSign` alongside `pubEnc` and verify on receipt |
| Usernames are inserted into the page with `innerHTML` → **XSS** risk | `textContent` everywhere + username validation |
| Passwords hashed with unsalted SHA-256; default admin account | `werkzeug.security.generate_password_hash` (salted, slow) + admin password from an environment variable |
| Any logged-in user can request any encrypted image by file name | check that the requester is the sender or receiver |
| Key history grows by one key per minute and every old key is tried on decryption | store the key ID with each message |
| The server rotates its own RSA key, which the final design no longer uses | remove the dead code |

## Team

Group 6 — Yusuf Mehmed (Çalışkan), Elif Tarhan, Suleyman Parlan, Sergül Duba.
Lecturer: Prof. Dr. Alexander G. Chefranov.
