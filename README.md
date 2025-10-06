# WhisperMesh – Secure E2EE Chat (GUI) with Encrypted File Transfer & Overlay

WhisperMesh is a lightweight, Python-based secure messaging app. It ships with a **Tkinter desktop GUI**, **end-to-end encryption** for messages, **encrypted file transfer**, and a **multi-server overlay** so users on different servers can still talk.

---

## Screenshots

> Put your images in `docs/screenshots/` with these names (or change the paths below).

<p align="center">
  <img src="docs/screenshots/gui_main.png" alt="Main GUI Window" width="48%"/>
  <img src="docs/screenshots/e2ee_message.png" alt="End-to-End Encrypted Message" width="48%"/>
</p>

<p align="center">
  <img src="docs/screenshots/file_transfer.png" alt="Encrypted File Transfer with sha256 OK" width="48%"/>
  <img src="docs/screenshots/overlay_servers.png" alt="Two Peered Servers (Overlay)" width="48%"/>
</p>

---

## Features

- **Desktop GUI (Tkinter):** Connect · List Users · **Send (E2EE)** · **Send to All** · **Send File…**
- **Strong crypto:** per-user **RSA-4096** keypair (PEM on disk), **RSA-OAEP (SHA-256)** encryption, **RSASSA-PSS (SHA-256)** signatures
- **Encrypted file transfer:** chunked, each chunk is signed & verified; final **SHA-256 OK**
- **Overlay networking:** peer multiple servers, gossip presence, route across servers, loop suppression, heartbeats
- **Documented PoC backdoors (OFF by default):** `WM_ALLOW_WEAK_KEYS=1`, `WM_TRUST_MAGIC=1` (for controlled demos only)

---

## Tech Stack

**Language:** Python 3.10+  
**GUI:** Tkinter  
**Networking:** websockets  
**Crypto:** cryptography (RSA-4096, OAEP/SHA-256, PSS/SHA-256)




---

## How It Works

1. **Identity & Keys** – Each client has a UUID and generates an **RSA-4096** keypair on first connect (stored under `keys/`).  
2. **Key Distribution** – Server advertises online users and their public keys (DER→base64url). Clients cache keys via **List Users**.  
3. **Messages (E2EE)** – Sender encrypts to recipient’s public key (RSA-OAEP) and signs `{ciphertext, from, to, ts}` (PSS). Server sees only ciphertext + sig.  
4. **Files (E2EE)** – Sender splits file → encrypts & signs **each chunk** → receiver verifies, decrypts, reassembles → checks **sha256** then saves.  
5. **Overlay** – Multiple servers peer via `WM_PEERS`; they gossip presence and forward frames to destination users with loop suppression.

---

## Getting Started

> Ubuntu missing Tkinter?  
> `sudo apt-get install -y python3-tk`

```bash
# 1) Create & activate a virtualenv
python3 -m venv venv
source venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt
