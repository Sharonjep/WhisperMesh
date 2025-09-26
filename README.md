# WhisperMesh

End-to-end encrypted (E2EE) chat with a simple **Tkinter GUI**, encrypted **file transfer**, and a **multi-server overlay** so users on different servers can still talk — all in Python.

> This app demonstrates secure messaging concepts (key management, signatures, routing, and chunked file transfer) in a compact, easy-to-run project.

---

## Features
- **GUI (Tkinter):** Connect · List Users · **Send (E2EE)** · **Send to All** · **Send File…**
- **Public-key crypto:** per-user **RSA-4096** keypair (private key stored as PEM under `keys/`)
- **E2EE messages:** **RSA-OAEP (SHA-256)** encryption + **RSASSA-PSS (SHA-256)** signatures
- **Encrypted file transfer:** chunked; each chunk signed & verified; final **SHA-256 OK**
- **Overlay network:** multiple servers can **peer**; presence gossip, routing, loop suppression, heartbeats
- **Documented PoC backdoors (OFF by default):**
  - `WM_ALLOW_WEAK_KEYS=1` (server) — accept RSA < 4096 (policy-downgrade demo)
  - `WM_TRUST_MAGIC=1` (client) — accept `content_sig="TRUSTME"` (verification-bypass demo)

---

## How it works & how to run

### 1) Setup

**Requirements**
- Python **3.10+**
- On Ubuntu, if Tkinter is missing:
```bash
sudo apt-get install -y python3-tk
