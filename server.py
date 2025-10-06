import os, asyncio, json, time, uuid, websockets
from typing import Dict, Optional
from utils.crypto import ensure_uuid, b64url_der_to_pub

from websockets.legacy.server import WebSocketServerProtocol
from websockets.legacy.client import WebSocketClientProtocol

WM_HOST = os.getenv("WM_HOST", "127.0.0.1")
WM_PORT = int(os.getenv("WM_PORT", "8765"))
SERVER_ID = os.getenv("WM_SERVER_ID", f"server_{WM_PORT}")
PEERS = [p for p in os.getenv("WM_PEERS", "").split(",") if p.strip()]

# [BACKDOOR-S1] Weak-key admission toggle: allows RSA keys >=1024 bits when set.
ALLOW_WEAK = os.getenv("WM_ALLOW_WEAK_KEYS", "0") == "1"

# State tables
local_users: Dict[str, websockets.WebSocketServerProtocol] = {}   # uid -> ws
user_pubkeys: Dict[str, str] = {}                                  # uid -> b64url(pub DER)
user_locations: Dict[str, str] = {}                                # uid -> "local"

servers: Dict[str, websockets.WebSocketClientProtocol] = {}        # server_id -> ws
server_addrs: Dict[str, str] = {}                                  # server_id -> ws url
routes: Dict[str, str] = {}                                        # uid -> server_id
remote_user_pubkeys: Dict[str, str] = {}                           # remote uid -> pub

# anti-loop cache for ROUTE mids (very small TTL; see [AUX])
seen_mids: Dict[str, float] = {}

HEARTBEAT_SECS = 10
MID_TTL_SECS = 60

def norm_id(s: str) -> str:
    # Normalize to UUID form; non-UUIDs will be replaced by a random UUID.
    return ensure_uuid(s)

def prune_seen():
    now = time.time()
    drop = [mid for mid, ts in seen_mids.items() if now - ts > MID_TTL_SECS]
    for mid in drop:
        seen_mids.pop(mid, None)

async def broadcast_local(obj: dict, exclude_user: Optional[str]=None):
    payload = json.dumps(obj)
    await asyncio.gather(*[
        ws.send(payload)
        for uid, ws in local_users.items()
        if uid != (exclude_user or "")
    ], return_exceptions=True)

async def connect_to_peer(url: str):
    # [BACKDOOR-S2] No authentication/TLS; any ws endpoint can impersonate a server.
    while True:
        try:
            ws = await websockets.connect(url)
            hello = {"type": "SERVER_HELLO", "from": SERVER_ID, "payload": {"addr": f"ws://{WM_HOST}:{WM_PORT}"}}
            await ws.send(json.dumps(hello))

            raw = await ws.recv()
            msg = json.loads(raw)
            if msg.get("type") == "SERVER_HELLO":
                remote_id = msg.get("from")
                servers[remote_id] = ws
                server_addrs[remote_id] = (msg.get("payload") or {}).get("addr", url)
                print(f"[peer] connected to {remote_id} @ {url}")
                asyncio.create_task(peer_reader(ws, remote_id))
                asyncio.create_task(peer_heartbeats(ws, remote_id))
                return
        except Exception as e:
            print(f"[peer] failed to connect {url}: {e}")
        await asyncio.sleep(3)

async def peer_reader(ws: websockets.WebSocketClientProtocol, remote_id: str):
    try:
        async for raw in ws:
            try:
                m = json.loads(raw)
            except Exception:
                continue
            t = m.get("type")
            if t == "SERVER_HELLO":
                # trust-on-first-hello; nothing else to do
                pass
            elif t == "SERVER_USER_ADVERTISE":
                p = m.get("payload") or {}
                u, sid, pub = p.get("user_id"), p.get("server_id"), p.get("pub")
                if u and sid:
                    routes[u] = sid
                    if pub: remote_user_pubkeys[u] = pub
                    # Mirror presence to locals
                    adv = {"type":"USER_ADVERTISE","from":SERVER_ID,"to":"*","ts":int(time.time()*1000),
                           "payload":{"user_id": u, "server_id": sid, "pub": pub}}
                    await broadcast_local(adv)
            elif t == "ROUTE":
                # [BACKDOOR-S3] Accept ROUTE from any peer; no MAC/sig on envelope.
                await handle_route(m, via=remote_id)
            elif t == "PING":
                await ws.send(json.dumps({"type":"PONG","ts": int(time.time()*1000)}))
            elif t == "PONG":
                pass
    except websockets.ConnectionClosed:
        pass
    finally:
        if servers.get(remote_id) is ws:
            del servers[remote_id]
        print(f"[peer] {remote_id} disconnected")

async def peer_heartbeats(ws: websockets.WebSocketClientProtocol, remote_id: str):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_SECS)
            await ws.send(json.dumps({"type":"PING","ts":int(time.time()*1000)}))
    except Exception:
        pass

async def advertise_user_to_peers(user_id: str):
    adv = {"type":"SERVER_USER_ADVERTISE","from":SERVER_ID,"ts":int(time.time()*1000),
           "payload":{"user_id": user_id, "server_id": SERVER_ID, "pub": user_pubkeys.get(user_id)}}
    msg = json.dumps(adv)
    await asyncio.gather(*[
        ws.send(msg) for ws in list(servers.values())
    ], return_exceptions=True)

def pick_next_hop(user_id: str) -> Optional[str]:
    sid = routes.get(user_id)
    if sid and sid in servers:
        return sid
    return None

async def forward_route(payload_msg: dict, dest_user: str):
    """Wrap a client-originated message for inter-server routing."""
    prune_seen()
    mid = str(uuid.uuid4())
    route = {"type":"ROUTE", "from": SERVER_ID, "mid": mid, "hops": 0,
             "dest": dest_user, "payload": payload_msg}
    sid = pick_next_hop(dest_user)
    if not sid:
        return False
    try:
        await servers[sid].send(json.dumps(route))
        seen_mids[mid] = time.time()
        return True
    except Exception:
        return False

async def handle_route(route_msg: dict, via: str):
    """Handle a ROUTE message from a peer; deliver or forward with loop suppression."""
    mid = route_msg.get("mid")
    if not mid:
        return
    prune_seen()
    if mid in seen_mids:
        return  # [AUX] basic replay suppression; short TTL
    seen_mids[mid] = time.time()

    dest = route_msg.get("dest")
    payload = route_msg.get("payload") or {}
    mtype = payload.get("type")

    if dest in local_users:
        # [BACKDOOR-S3] The server *forges* an app-frame as if from SERVER_ID and
        # delivers payload directly to clients without end-to-end auth on envelope.
        deliver_type = mtype
        inner = payload
        target_ws = local_users[dest]
        if deliver_type in ("MSG_DIRECT","FILE_START","FILE_CHUNK","FILE_END"):
            out = {"type": deliver_type, "from": SERVER_ID, "to": dest,
                   "ts": int(time.time()*1000), "payload": inner.get("payload", {})}
            await target_ws.send(json.dumps(out))
        return

    sid = pick_next_hop(dest)
    if sid and sid != via:
        route_msg["hops"] = int(route_msg.get("hops", 0)) + 1
        try:
            await servers[sid].send(json.dumps(route_msg))
        except Exception:
            pass

async def handle_client(ws: websockets.WebSocketServerProtocol, hello: dict):
    uid = None
    try:
        uid = norm_id(hello.get("from", ""))
        if uid in local_users:
            await ws.send(json.dumps({"type":"ERROR",
                                      "payload":{"code":"NAME_IN_USE","detail":f"{uid} already connected"}}))
            await ws.close(code=1000, reason="Duplicate user")
            return

        # Validate (or accept weak) public key from client
        pub_in_hello = (hello.get("payload") or {}).get("pub")
        if pub_in_hello:
            try:
                pub = b64url_der_to_pub(pub_in_hello)
                key_bits = getattr(pub, "key_size", 0)
                # Require RSA-4096 unless [BACKDOOR-S1] permits weak keys (>=1024)
                if key_bits != 4096 and not (ALLOW_WEAK and key_bits >= 1024):
                    await ws.send(json.dumps({"type":"ERROR",
                                              "payload":{"code":"WEAK_KEY","detail":f"RSA-{key_bits} not allowed"}}))
                    await ws.close(code=1008, reason="Weak key"); return
                user_pubkeys[uid] = pub_in_hello
            except Exception:
                await ws.send(json.dumps({"type":"ERROR",
                                          "payload":{"code":"BAD_PUBKEY","detail":"Invalid public key"}}))
                await ws.close(code=1008, reason="Bad pubkey"); return

        local_users[uid] = ws
        user_locations[uid] = "local"
        routes[uid] = SERVER_ID
        print(f"[+] {uid} connected")

        now_ms = int(time.time()*1000)

        # announce existing locals
        for other_uid in list(local_users.keys()):
            if other_uid == uid: continue
            adv = {"type":"USER_ADVERTISE","from":SERVER_ID,"to":uid,"ts":now_ms,
                   "payload":{"user_id":other_uid,"server_id":SERVER_ID,"pub": user_pubkeys.get(other_uid)}}
            await ws.send(json.dumps(adv))

        # announce known remotes
        for ru in list(routes.keys()):
            if ru == uid: continue
            if ru in local_users: continue
            adv = {"type":"USER_ADVERTISE","from":SERVER_ID,"to":uid,"ts":now_ms,
                   "payload":{"user_id":ru,"server_id":routes.get(ru),"pub": remote_user_pubkeys.get(ru)}}
            await ws.send(json.dumps(adv))

        # broadcast this user to locals & peers
        adv_local = {"type":"USER_ADVERTISE","from":SERVER_ID,"to":"*","ts":now_ms,
                     "payload":{"user_id":uid,"server_id":SERVER_ID,"pub": user_pubkeys.get(uid)}}
        await broadcast_local(adv_local, exclude_user=uid)
        await advertise_user_to_peers(uid)

        async for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                await ws.send(json.dumps({"type":"ERROR","payload":{"code":"BAD_JSON"}})); continue

            mtype = msg.get("type")
            if mtype == "LIST":
                all_users = set(local_users.keys()) | set(routes.keys())
                users_sorted = sorted(all_users)
                pubmap = {u: (user_pubkeys.get(u) if u in local_users else remote_user_pubkeys.get(u))
                          for u in users_sorted}
                await ws.send(json.dumps({"type":"LIST_RESULT",
                                          "payload":{"users": users_sorted, "pubkeys": pubmap}}))

            elif mtype == "GET_PUBKEY":
                target = norm_id((msg.get("payload") or {}).get("user",""))
                pub = user_pubkeys.get(target) or remote_user_pubkeys.get(target)
                await ws.send(json.dumps({"type":"PUBKEY_RESULT",
                                          "payload":{"user": target, "pub": pub}}))

            elif mtype in ("MSG_DIRECT","FILE_START","FILE_CHUNK","FILE_END"):
                target = norm_id(msg.get("to",""))
                if target in local_users:
                    out = {"type": mtype, "from": SERVER_ID, "to": target,
                           "ts": int(time.time()*1000), "payload": (msg.get("payload") or {})}
                    await local_users[target].send(json.dumps(out))
                else:
                    # [BACKDOOR-S3] Forward un-authenticated envelopes across servers
                    ok = await forward_route({"type": mtype, "from": SERVER_ID, "to": target,
                                              "payload": (msg.get("payload") or {})}, target)
                    if not ok:
                        await ws.send(json.dumps({"type":"ERROR",
                                                  "payload":{"code":"USER_NOT_FOUND","detail":target}}))

            elif mtype == "USER_KEY_UPDATE":
                # [BACKDOOR-S4] Accepts any USER_KEY_UPDATE sent on this socket without
                # verifying that the sender controls the referenced key/user.
                new_pub = (msg.get("payload") or {}).get("pub")
                if new_pub:
                    user_pubkeys[uid] = new_pub
                    await advertise_user_to_peers(uid)

            else:
                await ws.send(json.dumps({"type":"ERROR",
                                          "payload":{"code":"UNKNOWN_TYPE","detail": mtype}}))

    except websockets.ConnectionClosed:
        pass
    finally:
        if uid and local_users.get(uid) is ws:
            del local_users[uid]
            user_locations.pop(uid, None)
            user_pubkeys.pop(uid, None)
            routes.pop(uid, None)
            print(f"[-] {uid} disconnected")

async def handle_incoming(ws: websockets.WebSocketServerProtocol):
    """First frame decides: client or server."""
    try:
        first_raw = await ws.recv()
        first = json.loads(first_raw)
    except Exception:
        await ws.close(code=1002, reason="Bad initial frame")
        return

    if first.get("type") == "USER_HELLO":
        await handle_client(ws, first)
        return

    if first.get("type") == "SERVER_HELLO":
        # [BACKDOOR-S2] Accept arbitrary server peers (no auth), reflect hello
        remote_id = first.get("from")
        servers[remote_id] = ws
        server_addrs[remote_id] = (first.get("payload") or {}).get("addr", "")
        await ws.send(json.dumps({"type":"SERVER_HELLO","from":SERVER_ID,
                                  "payload":{"addr": f"ws://{WM_HOST}:{WM_PORT}"}}))
        print(f"[peer] accepted {remote_id}")
        await asyncio.gather(peer_reader(ws, remote_id), return_exceptions=True)
        return

    await ws.close(code=1002, reason="Unknown first frame")

async def main():
    print(f"WhisperMesh {SERVER_ID} on ws://{WM_HOST}:{WM_PORT}")
    server_task = websockets.serve(handle_incoming, WM_HOST, WM_PORT)

    # Optional outbound peer dials (again, unauthenticated)  [BACKDOOR-S2]
    peer_tasks = []
    for url in PEERS:
        url = url.strip()
        if url:
            peer_tasks.append(asyncio.create_task(connect_to_peer(url)))

    async with server_task:
        await asyncio.gather(asyncio.Future(), *peer_tasks)

if __name__ == "__main__":
    asyncio.run(main())
