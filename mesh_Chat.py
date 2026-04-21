import socket
import threading
import json
import time
import uuid
import sys
import os
import base64
import subprocess
import random
import customtkinter as ctk
import config
from datetime import datetime
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from plyer import notification


# --- UTILS ---
def get_my_bt_mac():
    """Attempts to retrieve the local Bluetooth MAC address on Windows."""
    try:
        cmd = subprocess.check_output("ipconfig /all", shell=True).decode()
        is_bt = False
        for line in cmd.split('\n'):
            if "Bluetooth" in line: is_bt = True
            if is_bt and "Physical Address" in line:
                return line.split(":")[-1].strip().replace("-", ":")
    except: pass
    return "UNKNOWN_MAC"

# --- BACKEND ENGINE ---
class MeshCore:
    def __init__(self, log_cb, msg_cb, peer_cb, file_cb):
        self.log = log_cb
        self.on_msg = msg_cb
        self.on_peer = peer_cb
        self.on_file = file_cb
        
        self.my_bt_mac = get_my_bt_mac()
        self.peers = {} 
        self.saved_macs = {} 
        self.routing_table = {}  # {dest_id: next_hop_peer_id}
        self.session_keys = {}   # {peer_id: aes_key}
        self.seen_packets = set() # To prevent routing loops
        self.running = True
        
        # 1. PERSISTENCE: Load Identity and MACs
        self.load_identity()
        self.load_macs()
        
        # Threads
        threading.Thread(target=self.wifi_server, daemon=True).start()
        threading.Thread(target=self.wifi_beacon_rx, daemon=True).start()
        threading.Thread(target=self.wifi_beacon_tx, daemon=True).start()
        try: threading.Thread(target=self.bt_server, daemon=True).start()
        except: pass

    def load_identity(self):
        """Loads persistent user ID and RSA keys, or creates new ones."""
        if os.path.exists(config.IDENTITY_FILE):
            try:
                with open(config.IDENTITY_FILE, 'r') as f:
                    data = json.load(f)
                    self.my_id = data.get("id")
                    priv_pem = data.get("priv_key")
                    if not priv_pem: raise ValueError("Keys missing")
                    self.priv_key = serialization.load_pem_private_key(
                        priv_pem.encode(),
                        password=None
                    )
            except Exception as e:
                # Still use self.log, which is now safe during init
                self.log(f"Identity upgrade/load needed: {e}")
                self.create_new_identity()
        else:
            self.create_new_identity()
            
        self.pub_key = self.priv_key.public_key()
        self.pub_key_bytes = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def create_new_identity(self):
        """Generates a new identity with RSA keys."""
        self.my_id = str(uuid.uuid4())[:8].upper()
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config.RSA_KEY_SIZE
        )
        priv_pem = self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        with open(config.IDENTITY_FILE, 'w') as f:
            json.dump({"id": self.my_id, "priv_key": priv_pem}, f)

    def load_macs(self):
        if os.path.exists("flux_nodes.db"):
            try:
                with open("flux_nodes.db", 'r') as f: self.saved_macs = json.load(f)
            except: pass

    def save_mac(self, pid, mac):
        if mac == "UNKNOWN_MAC" or not mac: return
        self.saved_macs[pid] = mac
        with open("flux_nodes.db", 'w') as f: json.dump(self.saved_macs, f)

    def force_rescan(self):
        """Broadcasts presence immediately."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(f"MESH:{self.my_id}".encode(), ('<broadcast>', config.WIFI_UDP_PORT))
            s.close()
            self.log("MANUAL BEACON SENT")
        except Exception as e:
            self.log(f"RESCAN ERROR: {e}")

    def handle_client(self, sock, conn_type, remote_addr=""):
        peer_id = None
        try:
            # 1. Handshake with Public Key
            hello = {
                "type": "HELLO", 
                "sender": self.my_id, 
                "bt_mac": self.my_bt_mac, 
                "pub_key": self.pub_key_bytes
            }
            self.send_packet(sock, hello, encrypt=False)
            
            while self.running:
                pkt = self.recv_packet(sock)
                if not pkt: break
                
                # 2. Multi-hop Routing check
                target_id = pkt.get('to')
                if target_id and target_id != self.my_id:
                    self.forward_packet(pkt)
                    continue
                
                # 3. Prevent duplicate processing
                sid = pkt.get('sid') # Sequence identifier
                if sid in self.seen_packets: continue
                if sid: self.seen_packets.add(sid)

                if pkt['type'] == 'HELLO':
                    peer_id = pkt['sender']
                    rmt_mac = pkt.get('bt_mac', "UNKNOWN_MAC")
                    rmt_pub_bytes = pkt.get('pub_key')
                    
                    if rmt_mac != "UNKNOWN_MAC": self.save_mac(peer_id, rmt_mac)
                    
                    self.peers[peer_id] = {
                        'type': conn_type, 
                        'sock': sock, 
                        'pub_key': serialization.load_pem_public_key(rmt_pub_bytes.encode())
                    }
                    self.routing_table[peer_id] = peer_id
                    self.on_peer() 
                    self.log(f"LINK ESTABLISHED :: {peer_id}")
                    
                elif pkt['type'] == 'MSG':
                    content = pkt['content']
                    if pkt.get('encrypted'):
                        try: content = self.decrypt_payload(content)
                        except: content = "[DECRYPTION ERROR]"
                    self.on_msg({**pkt, 'content': content})
                    
                elif pkt['type'] == 'FILE':
                    if pkt.get('encrypted'):
                        try: pkt['data'] = self.decrypt_payload(pkt['data'])
                        except: pass
                    self.on_file(pkt)
        except Exception as e:
            pass
        finally:
            if peer_id in self.peers:
                del self.peers[peer_id]
                self.on_peer()
                self.log(f"LINK SEVERED :: {peer_id}")
            sock.close()

    def send_packet(self, sock, pkt, encrypt=True):
        try:
            if encrypt and pkt.get('type') in ['MSG', 'FILE']:
                # For this demo, we encrypt sensitive fields using the target's public key
                # Note: In a real app, we'd use RSA to exchange an AES key.
                # Here we simulate E2EE by RSA encrypting the payload.
                target_id = pkt.get('to')
                if target_id in self.peers and self.peers[target_id].get('pub_key'):
                    pkt['content'] = self.encrypt_payload(pkt.get('content', ''), self.peers[target_id]['pub_key'])
                    if 'data' in pkt: pkt['data'] = self.encrypt_payload(pkt['data'], self.peers[target_id]['pub_key'])
                    pkt['encrypted'] = True

            d = json.dumps(pkt).encode()
            sock.send(f"{len(d):<10}".encode() + d)
        except: pass

    def recv_packet(self, sock):
        try:
            head = sock.recv(10)
            if not head: return None
            size = int(head.decode().strip())
            data = b""
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk: return None
                data += chunk
            return json.loads(data.decode())
        except: return None

    def forward_packet(self, pkt):
        """Relays a packet to the next hop."""
        pkt['ttl'] = pkt.get('ttl', config.ROUTING_TTL) - 1
        if pkt['ttl'] <= 0: return
        
        target = pkt['to']
        next_hop = self.routing_table.get(target)
        
        if next_hop in self.peers:
            self.log(f"RELAYING PACKET: {pkt['sender']} -> {target} via {next_hop}")
            self.send_packet(self.peers[next_hop]['sock'], pkt, encrypt=False) # Already encrypted
        else:
            # Flooding: send to all peers if we don't know the route
            for peer_id, pdata in self.peers.items():
                if peer_id != pkt['sender']:
                    self.send_packet(pdata['sock'], pkt, encrypt=False)

    def encrypt_payload(self, text, public_key):
        """Simulates E2EE using RSA. For large payloads, hybrid encryption should be used."""
        try:
            return base64.b64encode(public_key.encrypt(
                text.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )).decode()
        except: return text

    def decrypt_payload(self, cipher_b64):
        try:
            return self.priv_key.decrypt(
                base64.b64decode(cipher_b64),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()
        except: return "[DECRYPTION FAILURE]"

    def send_msg(self, text, target_id):
        pkt = {
            "type": "MSG", 
            "sender": self.my_id, 
            "to": target_id,
            "content": text, 
            "ts": datetime.now().strftime("%H:%M"),
            "sid": str(uuid.uuid4())[:8],
            "ttl": config.ROUTING_TTL
        }
        # Try finding a route
        next_hop = self.routing_table.get(target_id)
        if next_hop in self.peers:
            self.send_packet(self.peers[next_hop]['sock'], pkt)
            return True
        # If no route, attempt flooding
        self.forward_packet(pkt)
        return True

    def send_file(self, filepath, target_id):
        try:
            with open(filepath, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            pkt = {
                "type": "FILE", 
                "sender": self.my_id, 
                "to": target_id,
                "filename": os.path.basename(filepath), 
                "data": b64, 
                "ts": datetime.now().strftime("%H:%M"),
                "sid": str(uuid.uuid4())[:8],
                "ttl": config.ROUTING_TTL
            }
            next_hop = self.routing_table.get(target_id)
            if next_hop in self.peers:
                self.send_packet(self.peers[next_hop]['sock'], pkt)
                return True
            self.forward_packet(pkt)
            return True
        except: return False

    def wifi_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', config.WIFI_TCP_PORT))
        s.listen(5)
        while self.running:
            c, a = s.accept()
            threading.Thread(target=self.handle_client, args=(c, "WIFI", a[0]), daemon=True).start()

    def wifi_beacon_tx(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while self.running:
            try: s.sendto(f"MESH:{self.my_id}".encode(), ('<broadcast>', config.WIFI_UDP_PORT))
            except: pass
            time.sleep(config.BEACON_INTERVAL)

    def wifi_beacon_rx(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', config.WIFI_UDP_PORT))
        known = set()
        while self.running:
            try:
                data, addr = s.recvfrom(1024)
                if data.decode().startswith("MESH:") and data.decode().split(":")[1] != self.my_id:
                    if addr[0] not in known:
                        known.add(addr[0])
                        self.log(f"SIGNAL DETECTED :: {addr[0]}")
                        self.connect_wifi(addr[0])
            except: pass

    def connect_wifi(self, ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, config.WIFI_TCP_PORT))
            threading.Thread(target=self.handle_client, args=(s, "WIFI", ip), daemon=True).start()
        except: pass

    def bt_server(self):
        try:
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            s.bind((socket.BDADDR_ANY, config.BT_CHANNEL))
            s.listen(1)
            while self.running:
                c, a = s.accept()
                threading.Thread(target=self.handle_client, args=(c, "BT", "RELAY"), daemon=True).start()
        except Exception as e:
            print(f"BT Server Error (Expected if no BT adapter): {e}")

    def connect_bt(self, mac):
        try:
            self.log(f"ATTEMPTING BT LINK -> {mac}")
            s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            s.connect((mac, config.BT_CHANNEL))
            threading.Thread(target=self.handle_client, args=(s, "BT", "RELAY"), daemon=True).start()
        except Exception as e:
            self.log(f"BT FAIL: {e}")

# --- ANIMATED GUI ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(config.APP_NAME)
        self.geometry("1100x700")
        self.configure(fg_color=config.C_BG_VOID)
        ctk.set_appearance_mode("Dark")
        
        self.core = MeshCore(self.log_anim, self.on_message, self.update_peers, self.on_file)
        self.active_peer = None
        self.pulse_val = 0
        self.pulse_dir = 1
        self.boot_step = 0

        # FONT
        self.f_main = ("Segoe UI", 12)
        self.f_bold = ("Segoe UI", 12, "bold")
        self.f_mono = ("Consolas", 11)

        # BOOT SCREEN
        self.boot_frame = ctk.CTkFrame(self, fg_color=config.C_BG_VOID)
        self.boot_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        self.boot_bar = ctk.CTkProgressBar(self.boot_frame, width=400, height=4, progress_color=config.C_CYAN)
        self.boot_bar.place(relx=0.5, rely=0.5, anchor="center")
        self.boot_bar.set(0)
        
        self.boot_lbl = ctk.CTkLabel(self.boot_frame, text="INITIALIZING...", font=self.f_mono, text_color=config.C_CYAN)
        self.boot_lbl.place(relx=0.5, rely=0.45, anchor="center")
        
        self.after(50, self.run_boot)

    # --- ANIMATIONS ---
    def run_boot(self):
        if self.boot_step < 100:
            self.boot_step += 4 # Sped up for development
            self.boot_bar.set(self.boot_step / 100)
            
            states = ["LOADING KERNEL", "READING IDENTITY", "LOADING MAC DATABASE", "ESTABLISHING UPLINK"]
            if self.boot_step % 25 == 0:
                self.boot_lbl.configure(text=states[int(self.boot_step/25)-1])
            
            self.after(20, self.run_boot)
        else:
            self.boot_frame.destroy()
            self.build_ui()

    def pulse_border(self):
        if not self.active_peer: 
            self.after(100, self.pulse_border)
            return

        self.pulse_val += 0.1 * self.pulse_dir
        if self.pulse_val >= 1 or self.pulse_val <= 0: self.pulse_dir *= -1
        
        ctype = self.core.peers.get(self.active_peer, {}).get('type', "WIFI")
        base_col = config.C_CYAN if ctype == "WIFI" else config.C_PINK
        
        if self.pulse_val > 0.8:
            self.main_view.configure(border_color=base_col)
        else:
            self.main_view.configure(border_color=config.C_PANEL)

        self.after(50, self.pulse_border)

    # --- UI BUILDER ---
    def build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. SIDEBAR (The Radar)
        self.sidebar = ctk.CTkFrame(self, width=280, fg_color=config.C_PANEL, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Profile
        self.prof_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.prof_frame.pack(fill="x", padx=20, pady=30)
        ctk.CTkLabel(self.prof_frame, text="OPERATOR", font=("Arial", 10, "bold"), text_color="gray").pack(anchor="w")
        ctk.CTkLabel(self.prof_frame, text=self.core.my_id, font=("Arial", 24, "bold"), text_color="white").pack(anchor="w")
        ctk.CTkLabel(self.prof_frame, text=f"SEC_KEY: ENABLED", font=self.f_mono, text_color=config.C_CYAN).pack(anchor="w")

        # Peer Radar List
        ctk.CTkLabel(self.sidebar, text="ACTIVE NODES (DIRECT)", font=("Arial", 11, "bold"), text_color="gray").pack(anchor="w", padx=20, pady=(20,10))
        self.peer_list = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        self.peer_list.pack(fill="both", expand=True, padx=5)

        # Rescan Button
        self.btn_scan = ctk.CTkButton(self.sidebar, text="RESCAN NETWORK", fg_color="#1a1a1a", border_color="#333", border_width=1,
                                     hover_color="#222", text_color=config.C_CYAN, command=self.rescan_action)
        self.btn_scan.pack(fill="x", side="bottom", padx=20, pady=5)

        # Manual Link
        self.btn_man = ctk.CTkButton(self.sidebar, text="NODE DATABASE", fg_color="#111", border_color="#333", border_width=1, 
                                     hover_color="#222", text_color="white", command=self.manual_dialog_new)
        self.btn_man.pack(fill="x", side="bottom", padx=20, pady=5)

        # 2. MAIN VIEW (The Deck)
        self.main_view = ctk.CTkFrame(self, fg_color=config.C_BG_VOID, corner_radius=0, border_width=2, border_color=config.C_PANEL)
        self.main_view.grid(row=0, column=1, sticky="nsew")
        self.main_view.grid_rowconfigure(1, weight=1)
        self.main_view.grid_columnconfigure(0, weight=1)

        # Header HUD (Glassmorphism feel)
        self.header = ctk.CTkFrame(self.main_view, height=60, fg_color=config.C_GLASS, corner_radius=0)
        self.header.grid(row=0, column=0, sticky="ew")
        
        self.lbl_target = ctk.CTkLabel(self.header, text="UPLINK IDLE", font=("Arial", 16, "bold"), text_color="gray")
        self.lbl_target.pack(side="left", padx=25, pady=20)
        
        self.status_dot = ctk.CTkLabel(self.header, text="●", font=("Arial", 20), text_color="#222")
        self.status_dot.pack(side="right", padx=25)

        # Chat Feed
        self.feed = ctk.CTkScrollableFrame(self.main_view, fg_color="transparent")
        self.feed.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        
        # Terminal Log (Bottom - Premium Look)
        self.term_frame = ctk.CTkFrame(self.main_view, height=120, fg_color="#050505", border_width=1, border_color="#1a1a1a")
        self.term_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))
        self.term_log = ctk.CTkTextbox(self.term_frame, font=self.f_mono, text_color=config.C_CYAN, fg_color="transparent", state="disabled")
        self.term_log.pack(fill="both", expand=True, padx=5, pady=5)

        # Input
        self.input_frame = ctk.CTkFrame(self.main_view, height=60, fg_color="transparent")
        self.input_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=10)
        
        self.entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter secure message or /cmd...", 
                                  fg_color="#111", border_color="#333", text_color="white", height=45)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry.bind("<Return>", self.send_ui)
        
        self.btn_send = ctk.CTkButton(self.input_frame, text="TRANSMIT", width=100, height=45, fg_color=config.C_CYAN, text_color="black", hover_color="#00c0cc", command=self.send_ui)
        self.btn_send.pack(side="right")
        self.btn_file = ctk.CTkButton(self.input_frame, text="VAULT", width=80, height=45, fg_color="#222", hover_color="#333", command=self.send_file_ui)
        self.btn_file.pack(side="right", padx=(0,5))

        self.pulse_border()

    # --- LOGIC ---
    def update_peers(self):
        for w in self.peer_list.winfo_children(): w.destroy()
        if not self.core.peers:
            ctk.CTkLabel(self.peer_list, text="SCANNING...", font=self.f_mono, text_color="#444").pack(pady=20)
            return

        for pid, data in self.core.peers.items():
            ctype = data['type']
            color = config.C_CYAN if ctype == "WIFI" else config.C_PINK
            
            card = ctk.CTkButton(self.peer_list, text=f"{pid}\n{ctype} LINK ACTIVE", font=("Arial", 11, "bold"),
                                 fg_color="#111", border_color=color, border_width=1, hover_color="#1a1a1a",
                                 anchor="w", height=50, command=lambda p=pid: self.select_peer(p))
            card.pack(fill="x", pady=4)

    def rescan_action(self):
        """NEW: Clears UI and broadcasts beacon"""
        self.log_anim("INITIATING NETWORK RESCAN...")
        self.core.force_rescan()
        # Visual feedback: Flash the list
        for w in self.peer_list.winfo_children(): w.destroy()
        ctk.CTkLabel(self.peer_list, text="BROADCASTING...", font=self.f_mono, text_color=C_CYAN).pack(pady=20)

    def select_peer(self, pid):
        self.active_peer = pid
        ctype = self.core.peers[pid]['type']
        color = config.C_CYAN if ctype == "WIFI" else config.C_PINK
        
        self.lbl_target.configure(text=f"CONNECTED: {pid}", text_color="white")
        self.status_dot.configure(text_color=color)
        self.main_view.configure(border_width=2, border_color=color)
        self.btn_send.configure(fg_color=color)

    def send_ui(self, event=None):
        txt = self.entry.get()
        if not txt: return
        self.entry.delete(0, "end")
        
        # Handle Commands
        if txt.startswith("/"):
            self.handle_cmd(txt[1:])
            return

        if not self.active_peer:
            self.log_anim("ERR: NO TARGET SELECTED")
            return

        if self.core.send_msg(txt, self.active_peer):
            self.render_bubble(txt, "ME")
        else:
            self.log_anim("ERR: SEND FAILED")

    def handle_cmd(self, cmd):
        cmd = cmd.lower()
        if cmd == "clear":
            for w in self.feed.winfo_children(): w.destroy()
            self.log_anim("CHAT FEED PURGED")
        elif cmd == "status":
            self.log_anim(f"ID: {self.core.my_id} | PEERS: {len(self.core.peers)}")
        else:
            self.log_anim(f"UNKNOWN COMMAND: {cmd}")

    def send_file_ui(self):
        if not self.active_peer: return
        path = filedialog.askopenfilename()
        if path:
            self.render_bubble(f"UPLOADING: {os.path.basename(path)}", "ME")
            self.core.send_file(path, self.active_peer)

    def on_message(self, pkt):
        if self.active_peer == pkt['sender']:
            self.render_bubble(pkt['content'], pkt['sender'])
        else:
            self.log_anim(f"MSG RECEIVED FROM {pkt['sender']}")
            notification.notify(
                title=f"New Secure Message",
                message=f"From: {pkt['sender']}",
                app_name="Mesh_chat",
                timeout=5
            )

    def on_file(self, pkt):
        if messagebox.askyesno("INCOMING DATA", f"Accept file '{pkt['filename']}' from {pkt['sender']}?"):
            raw = base64.b64decode(pkt['data'])
            with open(f"recvd_{pkt['filename']}", "wb") as f: f.write(raw)
            self.render_bubble(f"FILE SAVED: {pkt['filename']}", pkt['sender'])

    def render_bubble(self, text, sender):
        is_me = (sender == "ME")
        align = "e" if is_me else "w"
        col = "#1a1a1a" if is_me else "#0a0a0a"
        border = config.C_CYAN if is_me else "#333"
        
        f = ctk.CTkFrame(self.feed, fg_color="transparent")
        f.pack(fill="x", pady=4)
        
        bub = ctk.CTkFrame(f, fg_color=col, border_color=border, border_width=1, corner_radius=12)
        bub.pack(anchor=align, padx=20)
        
        ctk.CTkLabel(bub, text=text, font=("Arial", 12), text_color="white", wraplength=400).pack(padx=15, pady=8)
        self.feed._parent_canvas.yview_moveto(1.0)

    def log_anim(self, text):
        print(f"DEBUG: {text}") # Still log to console
        if not hasattr(self, 'term_log') or self.term_log is None:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self.term_log.configure(state="normal")
        self.term_log.insert("end", f"[{ts}] {text}\n")
        self.term_log.see("end")
        self.term_log.configure(state="disabled")

    # --- NEW: ADVANCED MANUAL OVERRIDE ---
    def manual_dialog_new(self):
        top = ctk.CTkToplevel(self)
        top.title("NODE DATABASE")
        top.geometry("400x500")
        top.configure(fg_color=config.C_BG_VOID)
        
        ctk.CTkLabel(top, text="KNOWN NODES", font=self.f_bold, text_color="gray").pack(pady=10)
        
        scroll = ctk.CTkScrollableFrame(top, fg_color="#111")
        scroll.pack(fill="both", expand=True, padx=10, pady=5)
        
        # List saved MACs
        if not self.core.saved_macs:
            ctk.CTkLabel(scroll, text="NO DATA IN DB", text_color="#444").pack(pady=20)
        
        for pid, mac in self.core.saved_macs.items():
            btn = ctk.CTkButton(scroll, text=f"{pid}\n{mac}", fg_color="#222", hover_color=config.C_PINK,
                                command=lambda m=mac, t=top: self.trigger_manual_connect(m, t))
            btn.pack(fill="x", pady=2)
            
        ctk.CTkLabel(top, text="RAW MAC INPUT", font=self.f_bold, text_color="gray").pack(pady=10)
        e = ctk.CTkEntry(top, placeholder_text="AA:BB:CC:DD:EE:FF")
        e.pack(fill="x", padx=10)
        
        btn_go = ctk.CTkButton(top, text="UPLINK", fg_color=config.C_PINK, text_color="white",
                               command=lambda: self.trigger_manual_connect(e.get(), top))
        btn_go.pack(pady=10)

    def trigger_manual_connect(self, mac, window):
        if mac:
            window.destroy()
            self.log_anim(f"MANUAL OVERRIDE: {mac}")
            threading.Thread(target=self.core.connect_bt, args=(mac,), daemon=True).start()

if __name__ == "__main__":
    app = App()
    app.mainloop()