# Secure Image Encryption Application

> 🚧 Work in progress — code review and improvements ongoing.

Client–server web application for exchanging encrypted images and messages in real time.
Team project for CMSE 456 – Network & Information Security, Eastern Mediterranean University (Spring 2026).

**Tech:** Python · Flask · Flask-SocketIO · SQLite · JavaScript (Web Crypto API)

## Security features
- DES-CBC encryption of images and messages with a fresh session key per transmission
- RSA-2048 (OAEP) to exchange session keys between users
- RSA-SHA256 digital signatures for authenticity and integrity
- Periodic RSA key rotation, HTTPS/WSS with a self-signed certificate
- Admin panel with live activity log

## Run locally
```bash
pip install -r requirements.txt cryptography
python gen_cert.py
python app.py
```
Open **https://localhost:5000** and accept the self-signed certificate warning (Advanced → Proceed).
