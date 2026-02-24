
import socket
import threading
import json
import base64
import argparse
import os
import hashlib
import hmac
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

RELAY_HOST = '127.0.0.1'
RELAY_PORT = 9000


def gen_or_load_keys(client_id):
    priv_file = f"{client_id}_priv.pem"
    pub_file = f"{client_id}_pub.pem"
    if os.path.exists(priv_file) and os.path.exists(pub_file):
        priv = RSA.import_key(open(priv_file, 'rb').read())
        pub = RSA.import_key(open(pub_file, 'rb').read())
    else:
        key = RSA.generate(2048)
        with open(priv_file, 'wb') as f:
            f.write(key.export_key('PEM'))
        with open(pub_file, 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
        priv, pub = key, key.publickey()
    return priv, pub


class Client:
    def __init__(self, client_id, relay_host, relay_port):
        self.id = client_id.lower()
        self.relay_host = relay_host
        self.relay_port = relay_port

        self.priv, self.pub = gen_or_load_keys(self.id)
        self.relay_pub = None  # learned during registration

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.fileobj = None

        # per-peer session state
        self.session_keys = {}        # peer_id -> bytes
        self.nonce_store = {}         # peer_id -> {'Na': ..., 'Nb': ...}
        self.seq_numbers = {}         # peer_id -> last sent seq
        self.recv_highest_seq = {}    # peer_id -> highest received seq (for replay protection)

        self.session_peer = None      # convenience for CLI
        self.last_sent_msg = {}       # peer_id -> last full 'forward' message (for replay demo)

    # --------- networking helpers ----------

    def connect(self):
        self.sock.connect((self.relay_host, self.relay_port))
        self.fileobj = self.sock.makefile('r')
        threading.Thread(target=self._listen, daemon=True).start()
        print(f"[local] Connected to relay at {self.relay_host}:{self.relay_port}")

    def _listen(self):
        while True:
            line = self.fileobj.readline()
            if not line:
                break
            try:
                msg = json.loads(line.strip())
                self.handle_relay_msg(msg)
            except Exception as e:
                print("[error] Listener exception:", e)

    def _send_json(self, obj):
        data = json.dumps(obj) + "\n"
        self.sock.sendall(data.encode())

    # -------------- Registration & Relay Auth --------------

    def register(self):
        """Register this client ID + public key with the relay."""
        pub_pem = self.pub.export_key('PEM').decode()
        signed = (self.id + pub_pem).encode()
        sig = base64.b64encode(
            pkcs1_15.new(self.priv).sign(SHA256.new(signed))
        ).decode()
        msg = {
            "type": "register",
            "id": self.id,
            "pubkey": pub_pem,
            "signature": sig
        }
        self._send_json(msg)
        print("[local] Registration sent.")

    def auth_relay(self):
        """Authenticate the relay using a nonce it signs with its private key."""
        nonce = base64.b64encode(os.urandom(16)).decode()
        msg = {"type": "auth_nonce", "nonce": nonce}
        self._send_json(msg)
        print("[local] auth_nonce sent; waiting for signed response from relay.")

    # -------------- Session Establishment (Client-Client) --------------

    def start_session(self, peer_id):
        peer_id = peer_id.lower()
        if peer_id in self.session_keys:
            print(f"[session] Already established with {peer_id}")
            self.session_peer = peer_id
            return

        Na = base64.b64encode(os.urandom(16)).decode()
        self.nonce_store[peer_id] = {'Na': Na}
        payload = {"payload_type": "session_init", "Na": Na}
        msg = self._make_forward_msg(peer_id, payload)
        self._send_json(msg)
        print(f"[session] Sent session_init to {peer_id}")

    # -------------- Encrypted Messaging --------------

    def _derive_keystream(self, key: bytes, seq: int) -> bytes:
        """Simple stream: HMAC_K(seq) used as repeating keystream."""
        return hmac.new(key, str(seq).encode(), digestmod=hashlib.sha256).digest()

    def _encrypt_and_mac(self, key: bytes, seq: int, plaintext: str):
        keystream = self._derive_keystream(key, seq)
        plain = plaintext.encode()
        cipher = bytes([plain[i] ^ keystream[i % len(keystream)] for i in range(len(plain))])
        cipher_b64 = base64.b64encode(cipher).decode()
        mac = hmac.new(key, (str(seq) + '|' + cipher_b64).encode(), hashlib.sha256).digest()
        mac_b64 = base64.b64encode(mac).decode()
        return cipher_b64, mac_b64

    def send_message(self, peer_id, text: str):
        peer_id = peer_id.lower()
        if peer_id not in self.session_keys:
            print(f"[send] No active session with {peer_id}")
            return
        key = self.session_keys[peer_id]
        seq = self.seq_numbers.get(peer_id, 0) + 1
        self.seq_numbers[peer_id] = seq

        cipher_b64, mac_b64 = self._encrypt_and_mac(key, seq, text)
        payload = {
            "payload_type": "message",
            "seq": seq,
            "cipher": cipher_b64,
            "mac": mac_b64
        }
        msg = self._make_forward_msg(peer_id, payload)
        self._send_json(msg)
        self.last_sent_msg[peer_id] = msg
        print(f"[send] to {peer_id} seq={seq}")

    def send_tampered(self, peer_id, text: str):
        """Send a message with an intentionally corrupted MAC to demonstrate tamper handling."""
        peer_id = peer_id.lower()
        if peer_id not in self.session_keys:
            print(f"[tamper] No active session with {peer_id}")
            return
        key = self.session_keys[peer_id]
        seq = self.seq_numbers.get(peer_id, 0) + 1
        self.seq_numbers[peer_id] = seq

        cipher_b64, mac_b64 = self._encrypt_and_mac(key, seq, text)
        mac_bytes = bytearray(base64.b64decode(mac_b64))
        if mac_bytes:
            mac_bytes[0] ^= 0x01  # flip one bit
        tampered_mac_b64 = base64.b64encode(bytes(mac_bytes)).decode()

        payload = {
            "payload_type": "message",
            "seq": seq,
            "cipher": cipher_b64,
            "mac": tampered_mac_b64
        }
        msg = self._make_forward_msg(peer_id, payload)
        self._send_json(msg)
        print(f"[tamper] Sent message to {peer_id} with corrupted MAC (seq={seq}).")

    def replay_last(self, peer_id):
        """Replay the last ciphertext sent to a peer (same seq, cipher, MAC)."""
        peer_id = peer_id.lower()
        last = self.last_sent_msg.get(peer_id)
        if not last:
            print(f"[replay] No previous message to {peer_id} to replay.")
            return
        self._send_json(last)
        seq = last.get("payload", {}).get("seq")
        print(f"[replay] Re-sent last message to {peer_id} with seq={seq} (should trigger replay protection).")

    # -------------- Signing Helper --------------

    def _make_forward_msg(self, peer_id, payload):
        """Create a signed 'forward' message for the relay."""
        to_sign = {
            "from": self.id,
            "to": peer_id,
            "payload": payload
        }
        signed_bytes = json.dumps(to_sign, sort_keys=True).encode()
        signature = base64.b64encode(
            pkcs1_15.new(self.priv).sign(SHA256.new(signed_bytes))
        ).decode()
        msg = {
            "type": "forward",
            "from": self.id,
            "to": peer_id,
            "payload": payload,
            "signature": signature
        }
        return msg

    # -------------- Relay Message Handling --------------

    def handle_relay_msg(self, msg):
        mtype = msg.get("type")

        if mtype == "register_ack":
            status = msg.get("status")
            print("[relay] register_ack:", msg)
            if status == "ok":
                relay_pub_pem = msg.get("relay_pubkey")
                sig_b64 = msg.get("signature")
                if relay_pub_pem and sig_b64:
                    try:
                        base = {
                            "type": msg["type"],
                            "status": msg["status"],
                            "relay_pubkey": relay_pub_pem
                        }
                        data = json.dumps(base).encode()
                        pub = RSA.import_key(relay_pub_pem.encode())
                        h = SHA256.new(data)
                        pkcs1_15.new(pub).verify(h, base64.b64decode(sig_b64.encode()))
                        self.relay_pub = pub
                        print("[relay] Relay public key stored & signature verified.")
                    except Exception as e:
                        print("[relay] WARNING: failed to verify relay signature:", e)

        elif mtype == "auth_nonce_signed":
            print("[relay] auth_nonce_signed:", msg)
            if not self.relay_pub:
                print("[auth] No relay public key stored; cannot verify signature.")
                return
            sig_b64 = msg.get("signature")
            base = {
                "type": msg.get("type"),
                "nonce": msg.get("nonce")
            }
            try:
                data = json.dumps(base).encode()
                h = SHA256.new(data)
                pkcs1_15.new(self.relay_pub).verify(h, base64.b64decode(sig_b64.encode()))
                print("[auth] Relay signature over nonce verified successfully.")
            except Exception as e:
                print("[auth] Relay signature verification FAILED:", e)

        elif mtype == "incoming":
            fr = msg.get("from", "").lower()
            payload = msg.get("payload", {})
            ptype = payload.get("payload_type")

            print(f"[incoming] from {fr}: {json.dumps(payload)}")

            # --- Session Init — responder side ---
            if ptype == "session_init":
                Na_b64 = payload.get("Na")
                if not Na_b64:
                    print("[session] Missing Na in session_init; ignoring.")
                    return
                self.nonce_store[fr] = {"Na": Na_b64}
                Nb = base64.b64encode(os.urandom(16)).decode()
                self.nonce_store[fr]["Nb"] = Nb

                # sign (self.id || fr || Na || Nb)
                signed_msg = (self.id + fr + Na_b64 + Nb).encode()
                sig = base64.b64encode(
                    pkcs1_15.new(self.priv).sign(SHA256.new(signed_msg))
                ).decode()

                reply_payload = {
                    "payload_type": "session_response",
                    "Nb": Nb,
                    "signature": sig
                }
                reply = self._make_forward_msg(fr, reply_payload)
                self._send_json(reply)
                print(f"[session] Replied to session_init from {fr} with Nb.")

                # Derive session key on responder side
                key = hashlib.sha256((Na_b64 + Nb + fr + self.id).encode()).digest()
                self.session_keys[fr] = key
                self.session_peer = fr
                self.seq_numbers[fr] = 0
                self.recv_highest_seq[fr] = 0
                print(f"[session] Session key established with {fr} (responder).")

            # --- Session Response — initiator side ---
            elif ptype == "session_response":
                Nb = payload.get("Nb")
                sig_b64 = payload.get("signature")
                fr_id = fr
                Na = self.nonce_store.get(fr_id, {}).get("Na")
                if not Na or not Nb or not sig_b64:
                    print("[session] Incomplete session_response; cannot derive key.")
                    return

                # (We could verify responder's signature here if we had their public key.)
                key = hashlib.sha256((Na + Nb + self.id + fr_id).encode()).digest()
                self.session_keys[fr_id] = key
                self.session_peer = fr_id
                self.seq_numbers[fr_id] = 0
                self.recv_highest_seq[fr_id] = 0
                print(f"[session] Session key established with {fr_id} (initiator).")

            # --- Encrypted message reception ---
            elif ptype == "message":
                key = self.session_keys.get(fr)
                if not key:
                    print("[message] No session key for", fr)
                    return

                seq = payload.get("seq")
                cipher_b64 = payload.get("cipher")
                mac_b64 = payload.get("mac")

                if seq is None or cipher_b64 is None or mac_b64 is None:
                    print("[message] Malformed message payload; missing fields.")
                    return

                # Replay protection: enforce strictly increasing sequence numbers
                last_seq = self.recv_highest_seq.get(fr, 0)
                try:
                    seq_int = int(seq)
                except ValueError:
                    print(f"[message] Invalid seq value from {fr}: {seq}")
                    return

                if seq_int <= last_seq:
                    print(f"[replay] Detected replay or out-of-order message from {fr}: "
                          f"seq={seq_int}, last_seen={last_seq}. Dropping.")
                    return

                self.recv_highest_seq[fr] = seq_int

                # MAC verification
                mac = base64.b64decode(mac_b64)
                expected = hmac.new(
                    key,
                    (str(seq_int) + "|" + cipher_b64).encode(),
                    hashlib.sha256
                ).digest()
                if not hmac.compare_digest(mac, expected):
                    print("[message] MAC verification FAILED. Possible tampering.")
                    return

                # Decrypt
                keystream = self._derive_keystream(key, seq_int)
                ciphertext = base64.b64decode(cipher_b64)
                plain = bytes([c ^ keystream[i % len(keystream)] for i, c in enumerate(ciphertext)])
                try:
                    decoded = plain.decode()
                except UnicodeDecodeError:
                    decoded = repr(plain)
                print(f"[message] from {fr} (seq={seq_int}): {decoded}")

        elif mtype == "forward_ack":
            status = msg.get("status")
            if status != "ok":
                print("[relay] forward_ack (non-ok):", msg)

        else:
            print("[relay] Unknown message from relay:", msg)


# ----------------- MAIN LOOP ----------------- #

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--relay-host", default=RELAY_HOST)
    parser.add_argument("--relay-port", type=int, default=RELAY_PORT)
    args = parser.parse_args()

    c = Client(args.id, args.relay_host, args.relay_port)
    c.connect()

    print("Commands: register | auth | start_session <peer> | "
          "send <message> | send_tampered <message> | replay [peer] | quit")

    try:
        while True:
            cmd = input("> ").strip()
            if not cmd:
                continue
            parts = cmd.split(" ", 1)
            op = parts[0]
            arg = parts[1] if len(parts) > 1 else None

            if op == "register":
                c.register()
            elif op == "auth":
                c.auth_relay()
            elif op == "start_session" and arg:
                c.start_session(arg.strip())
            elif op == "send" and arg:
                target = c.session_peer
                if not target:
                    print("[cli] No active session. Use start_session <peer> first.")
                else:
                    c.send_message(target, arg)
            elif op == "send_tampered" and arg:
                target = c.session_peer
                if not target:
                    print("[cli] No active session. Use start_session <peer> first.")
                else:
                    c.send_tampered(target, arg)
            elif op == "replay":
                if arg:
                    c.replay_last(arg.strip())
                else:
                    if not c.session_peer:
                        print("[cli] No active session; please specify a peer: replay <peer>.")
                    else:
                        c.replay_last(c.session_peer)
            elif op == "quit":
                break
            else:
                print("[cli] Unknown command.")
    except KeyboardInterrupt:
        print("\n[exit]")
