import os, sys, json, time, hashlib, pathlib, subprocess, asyncio, threading, queue, uuid, urllib.parse
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import websockets

from utils.crypto import (
    ensure_uuid, get_or_create_user_keys, pub_to_b64url_der, b64url_der_to_pub,
    rsa_encrypt, rsa_decrypt, sign, verify, canonical_json
)

CONFIG_PATH = os.path.join(pathlib.Path.home(), ".whispermesh.json")
DOWNLOADS_DIR = "downloads"
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

ui_queue: "queue.Queue[dict]" = queue.Queue()
TRUST_MAGIC = os.getenv("WM_TRUST_MAGIC", "0") == "1"   
DEBUG_WIREFRAMES = False                                 

def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {"last_id":"", "auto_connect": False, "server_url": "ws://127.0.0.1:8765"}

def save_config(cfg: dict):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f)
    except Exception:
        pass

class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WhisperMesh")
        self.geometry("980x620")
        self.resizable(True, True)

        self.cfg = load_config()
        self.user_id = tk.StringVar(value=self.cfg.get("last_id",""))
        self.server_url = tk.StringVar(value=self.cfg.get("server_url","ws://127.0.0.1:8765"))
        self.target_id = tk.StringVar()
        self.status = tk.StringVar(value="disconnected")
        self.auto_connect_var = tk.BooleanVar(value=self.cfg.get("auto_connect", False))

        self.pubkeys: dict[str, str] = {}      
        self.recv_files: dict[str, dict] = {} 

        self.priv = None
        self.pub_b64 = None
        self.ws = None
        self.loop = None
        self.async_thread = None
        self.connected = False

       
        top = ttk.Frame(self, padding=8); top.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(top, text="Server:").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.server_url, width=28).pack(side=tk.LEFT, padx=(4, 10))
        ttk.Label(top, text="Your ID (UUID):").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.user_id, width=36).pack(side=tk.LEFT, padx=(4, 10))
        ttk.Button(top, text="Connect", command=self.on_connect).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="List Users", command=self.on_list).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Start Server", command=self.on_start_server).pack(side=tk.LEFT, padx=10)
        ttk.Button(top, text="New Window", command=self.on_new_window).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(top, text="Auto-connect", variable=self.auto_connect_var,
                        command=self.on_toggle_auto).pack(side=tk.LEFT, padx=10)
        ttk.Label(top, textvariable=self.status, foreground="#555").pack(side=tk.RIGHT)

        
        main = ttk.Frame(self, padding=(8, 0, 8, 8)); main.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        left = ttk.Frame(main); left.pack(side=tk.LEFT, fill=tk.Y)
        ttk.Label(left, text="Online users").pack(anchor="w")
        self.users_list = tk.Listbox(left, height=25); self.users_list.pack(fill=tk.Y, expand=False)
        self.users_list.bind("<<ListboxSelect>>", self.on_pick_user)

        right = ttk.Frame(main); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
        self.chat_view = tk.Text(right, height=22, state="disabled", wrap="word"); self.chat_view.pack(fill=tk.BOTH, expand=True)

        compose = ttk.Frame(right); compose.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(compose, text="To (UUID):").pack(side=tk.LEFT)
        ttk.Entry(compose, textvariable=self.target_id, width=44).pack(side=tk.LEFT, padx=(4, 10))
        self.msg_entry = ttk.Entry(compose); self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", lambda e: self.on_send())
        ttk.Button(compose, text="Send (E2EE)", command=self.on_send).pack(side=tk.LEFT, padx=6)
        ttk.Button(compose, text="Send to All", command=self.on_send_all).pack(side=tk.LEFT, padx=6)
        ttk.Button(compose, text="Send File…", command=self.on_send_file).pack(side=tk.LEFT, padx=6)

       
        self.after(100, self.poll_ui_queue)
        if self.auto_connect_var.get() and self.user_id.get().strip():
            self.after(300, self.on_connect)

   
    def on_toggle_auto(self):
        self.cfg["auto_connect"] = bool(self.auto_connect_var.get()); save_config(self.cfg)

    def on_new_window(self):
        subprocess.Popen([sys.executable, os.path.abspath(__file__)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def on_start_server(self):
        url = self.server_url.get().strip()
        parsed = urllib.parse.urlparse(url)
        port = parsed.port or 8765
        host = parsed.hostname or "127.0.0.1"
        target = f"ws://{host}:{port}"

        async def probe():
            try:
                ws = await websockets.connect(target); await ws.close(); return True
            except Exception:
                return False

        def start_proc():
            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            ok = loop.run_until_complete(probe()); loop.close()
            if ok:
                messagebox.showinfo("WhisperMesh", "Server already running.")
                return
            env = os.environ.copy()
            env["WM_HOST"] = host
            env["WM_PORT"] = str(port)
            env["WM_SERVER_ID"] = env.get("WM_SERVER_ID", f"server_{port}")
            # auto-peer to introducer if not default port
            if port != 8765 and "WM_PEERS" not in env:
                env["WM_PEERS"] = "ws://127.0.0.1:8765"
            try:
                subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.py")],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
                messagebox.showinfo("WhisperMesh", f"Server started on {target}")
            except Exception as e:
                messagebox.showerror("WhisperMesh", f"Failed to start server:\n{e}")

        threading.Thread(target=start_proc, daemon=True).start()

    def on_connect(self):
        uid = ensure_uuid(self.user_id.get()); self.user_id.set(uid)
        self.cfg["last_id"] = uid; self.cfg["server_url"] = self.server_url.get().strip(); save_config(self.cfg)
        if self.connected:
            messagebox.showinfo("WhisperMesh", "Already connected."); return
        self.status.set("connecting…")
        self.async_thread = threading.Thread(target=self._start_async_loop, args=(uid,), daemon=True)
        self.async_thread.start()

    def on_list(self):
        if not self.connected or self.ws is None:
            messagebox.showwarning("WhisperMesh", "Connect first."); return
        asyncio.run_coroutine_threadsafe(self._send_json({"type":"LIST"}), self.loop)

    def on_pick_user(self, _evt=None):
        try:
            sel = self.users_list.curselection()
            if not sel: return
            self.target_id.set(self.users_list.get(sel[0]))
        except Exception:
            pass

    def on_send(self):
        if not self.connected or self.ws is None:
            messagebox.showwarning("WhisperMesh", "Connect first."); return
        target = ensure_uuid(self.target_id.get()); self.target_id.set(target)
        
        if target == self.user_id.get():
            messagebox.showwarning("WhisperMesh", "Pick another user (you're targeting yourself).")
            return
        text = self.msg_entry.get().strip()
        if not text: return
        self._encrypt_and_send_text(target, text)
        self.msg_entry.delete(0, tk.END)

    def on_send_all(self):
        if not self.connected or self.ws is None:
            messagebox.showwarning("WhisperMesh", "Connect first."); return
        text = self.msg_entry.get().strip()
        if not text: return
        me = self.user_id.get()
        for i in range(self.users_list.size()):
            uid = self.users_list.get(i)
            if uid == me: continue
            self._encrypt_and_send_text(uid, text)
        self.append_chat(f"[broadcast] sent to all: (encrypted) {text}")
        self.msg_entry.delete(0, tk.END)

    def on_send_file(self):
        if not self.connected or self.ws is None:
            messagebox.showwarning("WhisperMesh", "Connect first."); return
        target = ensure_uuid(self.target_id.get()); self.target_id.set(target)
       
        if target == self.user_id.get():
            messagebox.showwarning("WhisperMesh", "Pick another user (you're targeting yourself).")
            return
        target_pub_b64 = self.pubkeys.get(target)
        if not target_pub_b64:
            asyncio.run_coroutine_threadsafe(
                self._send_json({"type":"GET_PUBKEY","payload":{"user":target}}), self.loop)
            messagebox.showinfo("WhisperMesh", "Fetching recipient public key. Try again shortly.")
            return
        path = filedialog.askopenfilename(title="Select a file to send")
        if not path: return
        name = os.path.basename(path)
        data = open(path, "rb").read()
        size = len(data)
        sha = hashlib.sha256(data).hexdigest()
        fid = str(uuid.uuid4())
        chunk_size = 300  
       
        meta = {"fid": fid, "name": name, "size": size, "sha256": sha}
        meta_sig = sign(self.priv, canonical_json({"from": self.user_id.get(), "to": target, "ts": int(time.time()*1000), "file": meta}))
        asyncio.run_coroutine_threadsafe(self._send_json({
            "type": "FILE_START",
            "from": self.user_id.get(), "to": target,
            "payload": {"from": self.user_id.get(), "to": target, "ts": int(time.time()*1000),
                        "file": meta, "meta_sig": meta_sig}
        }), self.loop)
        self.append_chat(f"[file] sending {name} ({size} bytes)…")

      
        pub = b64url_der_to_pub(target_pub_b64)
        total = (size + chunk_size - 1) // chunk_size
        for idx in range(total):
            part = data[idx*chunk_size : (idx+1)*chunk_size]
            ct = rsa_encrypt(pub, part)
            signed = {"ciphertext": ct, "from": self.user_id.get(), "to": target, "ts": int(time.time()*1000),
                      "file": {"fid": fid, "name": name, "index": idx, "total": total}}
            sig = sign(self.priv, canonical_json(signed))
            asyncio.run_coroutine_threadsafe(self._send_json({
                "type":"FILE_CHUNK","from": self.user_id.get(), "to": target,
                "payload": {**signed, "content_sig": sig}
            }), self.loop)

      
        asyncio.run_coroutine_threadsafe(self._send_json({
            "type":"FILE_END","from": self.user_id.get(), "to": target,
            "payload": {"from": self.user_id.get(), "to": target, "ts": int(time.time()*1000),
                        "file": meta}
        }), self.loop)
        self.append_chat(f"[file] {name} sent ({total} chunks).")

   
    def _encrypt_and_send_text(self, target: str, text: str):
        target_pub_b64 = self.pubkeys.get(target)
        if not target_pub_b64:
            asyncio.run_coroutine_threadsafe(
                self._send_json({"type":"GET_PUBKEY","payload":{"user":target}}), self.loop)
            messagebox.showinfo("WhisperMesh", "Fetching recipient public key. Try Send again in a moment.")
            return
        ts = int(time.time() * 1000); sender = self.user_id.get()
        ct = rsa_encrypt(b64url_der_to_pub(target_pub_b64), text.encode("utf-8"))
        signed_obj = {"ciphertext": ct, "from": sender, "to": target, "ts": ts}
        sig_b64 = sign(self.priv, canonical_json(signed_obj))
        payload = {"ciphertext": ct, "content_sig": sig_b64, "from": sender, "to": target, "ts": ts}
        asyncio.run_coroutine_threadsafe(self._send_json(
            {"type":"MSG_DIRECT","from":sender,"to":target,"payload":payload}), self.loop)
        self.append_chat(f"you → {target}: (encrypted) {text}")

    def _start_async_loop(self, uid: str):
        self.priv, pub = get_or_create_user_keys(uid); self.pub_b64 = pub_to_b64url_der(pub)
        self.loop = asyncio.new_event_loop(); asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._async_connect(uid))
        try: self.loop.run_forever()
        finally: self.loop.close()

    async def _async_connect(self, uid: str):
        try:
            url = self.server_url.get().strip() or "ws://127.0.0.1:8765"
            self.ws = await websockets.connect(url)
            hello = {"type":"USER_HELLO","from":uid,"to":"server","ts":int(time.time()*1000),
                     "payload":{"pub": self.pub_b64}}
            await self.ws.send(json.dumps(hello))
            
            self.connected = True
            self.pubkeys[uid] = self.pub_b64
            ui_queue.put({"type":"STATUS","value":"connected"})
            asyncio.create_task(self._receiver())
        except Exception as e:
            ui_queue.put({"type":"ERROR","value":f"connect failed: {e}"}); self.connected = False

    async def _send_json(self, obj: dict):
        try: await self.ws.send(json.dumps(obj))
        except Exception as e: ui_queue.put({"type":"ERROR","value":f"send failed: {e}"})

    async def _receiver(self):
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    if DEBUG_WIREFRAMES:
                        ui_queue.put({"type":"LOG","value":"<bad json>"})
                    continue
                t = msg.get("type")
                if t == "USER_ADVERTISE":
                    p = msg["payload"]; user = p["user_id"]; pub = p.get("pub")
                    if pub: self.pubkeys[user] = pub
                    ui_queue.put({"type":"PRESENCE","user":user})

                elif t == "LIST_RESULT":
                    payload = msg["payload"]
                    users = payload["users"]; pkmap = payload.get("pubkeys") or {}
                    for u, p in pkmap.items():
                        if p: self.pubkeys[u] = p
                    ui_queue.put({"type":"LIST","users":users})

                elif t == "PUBKEY_RESULT":
                    p = msg["payload"]; u, pub = p.get("user"), p.get("pub")
                    if u and pub:
                        self.pubkeys[u] = pub
                        ui_queue.put({"type":"LOG","value":f"[info] received pubkey for {u}"})

                elif t == "USER_DELIVER":
                    self._handle_dm(msg["payload"])

                elif t in ("FILE_START","FILE_CHUNK","FILE_END"):
                    self._handle_file(t, msg["payload"])

                elif t == "ERROR":
                    p = msg.get("payload") or {}
                    if p.get("code") == "NAME_IN_USE":
                        new_id = str(uuid.uuid4())
                        self.user_id.set(new_id)
                        self.cfg["last_id"] = new_id
                        save_config(self.cfg)
                        ui_queue.put({"type":"LOG","value":f"[info] ID in use; switching to {new_id} and reconnecting..."})
                       
                        self.after(200, self.on_connect)
                    else:
                        ui_queue.put({"type":"LOG","value":f"[error] {p}"})

                else:
                    if DEBUG_WIREFRAMES:
                        ui_queue.put({"type":"LOG","value":f"[frame] {str(msg)[:300]}..."})
        except Exception as e:
            ui_queue.put({"type":"ERROR","value":f"receiver stopped: {e}"})
        finally:
            self.connected = False; ui_queue.put({"type":"STATUS","value":"disconnected"})

  
    def _handle_dm(self, p: dict):
        if "ciphertext" in p:
            try:
                sender, ts, ct, sig = p.get("from","?"), p.get("ts"), p["ciphertext"], p.get("content_sig","")
                ok = True
                if not (TRUST_MAGIC and sig == "TRUSTME"):
                    ok = False
                    sender_pub_b64 = self.pubkeys.get(sender)
                    if sender_pub_b64:
                        ok = verify(b64url_der_to_pub(sender_pub_b64),
                                    canonical_json({"ciphertext": ct, "from": sender, "to": p.get("to"), "ts": ts}),
                                    sig)
                if not ok:
                    ui_queue.put({"type":"LOG","value":"[error] signature invalid"}); return
                plaintext = rsa_decrypt(self.priv, ct).decode("utf-8", errors="replace")
                ui_queue.put({"type":"DM","sender":sender, "text":plaintext})
            except Exception as e:
                ui_queue.put({"type":"LOG","value":f"[error] decrypt/verify failed: {e}"})
        elif "plaintext" in p:
            ui_queue.put({"type":"DM","sender":p.get("sender","?"), "text":p.get("plaintext","")})

    def _handle_file(self, kind: str, p: dict):
        if kind == "FILE_START":
            meta = p.get("file") or {}
            fid, name, size, sha_hex = meta.get("fid"), meta.get("name"), meta.get("size"), meta.get("sha256")
            if not fid or not name:
                ui_queue.put({"type":"LOG","value":"[file] bad FILE_START"}); return
            self.recv_files[fid] = {
                "meta": meta, "buf": bytearray(), "received": 0, "hasher": hashlib.sha256()
            }
            ui_queue.put({"type":"LOG","value":f"[file] incoming {name} ({size} bytes)…"})

        elif kind == "FILE_CHUNK":
            try:
                sender = p.get("from","?")
                ct, sig = p["ciphertext"], p.get("content_sig","")
                finfo = p.get("file") or {}
                fid, idx, total = finfo.get("fid"), finfo.get("index"), finfo.get("total")

                ok = True
                if not (TRUST_MAGIC and sig == "TRUSTME"):
                    sender_pub_b64 = self.pubkeys.get(sender)
                    if sender_pub_b64:
                    
                        file_json = {"fid": fid, "index": idx, "total": total}
                        name_in = finfo.get("name")
                        if name_in:
                            file_json["name"] = name_in
                        msg_json = {
                            "ciphertext": ct,
                            "from": sender,
                            "to": p.get("to"),
                            "ts": p.get("ts"),
                            "file": file_json,
                        }
                        ok = verify(b64url_der_to_pub(sender_pub_b64), canonical_json(msg_json), sig)
                    else:
                        ok = False
                if not ok:
                    ui_queue.put({"type":"LOG","value":"[file] invalid chunk signature"}); return

                chunk = rsa_decrypt(self.priv, ct)
                rf = self.recv_files.setdefault(fid, {"meta":{"fid":fid,"name":"unknown","size":0,"sha256":None},
                                                      "buf": bytearray(), "received": 0, "hasher": hashlib.sha256()})
                rf["buf"] += chunk; rf["hasher"].update(chunk); rf["received"] += 1
                if total: ui_queue.put({"type":"LOG","value":f"[file] chunk {idx+1}/{total} ({len(chunk)} bytes)"})
            except Exception as e:
                ui_queue.put({"type":"LOG","value":f"[file] chunk error: {e}"})

        elif kind == "FILE_END":
            meta = p.get("file") or {}
            fid, name, size, sha_hex = meta.get("fid"), meta.get("name"), meta.get("size"), meta.get("sha256")
            rf = self.recv_files.get(fid)
            if not rf:
                ui_queue.put({"type":"LOG","value":"[file] unknown transfer"}); return
            data = bytes(rf["buf"]); calc = rf["hasher"].hexdigest()
            ok = (sha_hex is None) or (sha_hex == calc)
            outdir = DOWNLOADS_DIR; os.makedirs(outdir, exist_ok=True)
            out = os.path.join(outdir, name or f"{fid}.bin")
            base, ext = os.path.splitext(out); c = 1
            while os.path.exists(out): out = f"{base}({c}){ext}"; c += 1
            open(out, "wb").write(data); del self.recv_files[fid]
            ui_queue.put({"type":"LOG","value":f"[file] saved to {out} — sha256 {'OK' if ok else 'MISMATCH'}"})

   
    def poll_ui_queue(self):
        try:
            while True:
                item = ui_queue.get_nowait(); kind = item.get("type")
                if kind == "STATUS": self.status.set(item.get("value",""))
                elif kind == "PRESENCE": self._add_user_once(item["user"]); self.append_chat(f"[presence] {item['user']} joined")
                elif kind == "LIST": self._set_users(item["users"])
                elif kind == "DM": self.append_chat(f"{item['sender']}: {item['text']}")
                elif kind == "LOG": self.append_chat(item["value"])
                elif kind == "ERROR": self.append_chat(f"[error] {item['value']}")
        except queue.Empty:
            pass
        self.after(100, self.poll_ui_queue)

    def _add_user_once(self, user: str):
        current = set(self.users_list.get(0, tk.END))
        if user not in current:
            self.users_list.insert(tk.END, user)

    def _set_users(self, users):
        self.users_list.delete(0, tk.END)
        for u in users:
            self.users_list.insert(tk.END, u)

    def append_chat(self, text: str):
        self.chat_view.configure(state="normal")
        self.chat_view.insert(tk.END, text + "\n")
        self.chat_view.see(tk.END)
        self.chat_view.configure(state="disabled")

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
