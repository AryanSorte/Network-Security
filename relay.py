import socket
import threading
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

HOST = '0.0.0.0'
PORT = 9000

# clients: id -> { 'pubkey_pem': str, 'conn': socket }
clients = {}
clients_lock = threading.Lock()

RELAY_PRIVKEY_FILE = 'relay_priv.pem'
RELAY_PUBKEY_FILE = 'relay_pub.pem'


def load_or_make_relay_keys():
    try:
        with open(RELAY_PRIVKEY_FILE, 'rb') as f:
            priv = RSA.import_key(f.read())
        with open(RELAY_PUBKEY_FILE, 'rb') as f:
            pub = RSA.import_key(f.read())
        print("[relay] Loaded existing relay keys.")
    except Exception:
        print("[relay] Generating relay RSA keypair...")
        priv = RSA.generate(2048)
        pub = priv.publickey()
        with open(RELAY_PRIVKEY_FILE, 'wb') as f:
            f.write(priv.export_key('PEM'))
        with open(RELAY_PUBKEY_FILE, 'wb') as f:
            f.write(pub.export_key('PEM'))
        print("[relay] Saved relay keys.")
    return priv, pub


RELAY_PRIV, RELAY_PUB = load_or_make_relay_keys()


def sign_bytes(b: bytes) -> str:
    h = SHA256.new(b)
    signature = pkcs1_15.new(RELAY_PRIV).sign(h)
    return base64.b64encode(signature).decode()


def verify_signature(pub_pem: str, message_bytes: bytes, signature_b64: str) -> bool:
    try:
        pub = RSA.import_key(pub_pem.encode())
        h = SHA256.new(message_bytes)
        sig = base64.b64decode(signature_b64.encode())
        pkcs1_15.new(pub).verify(h, sig)
        return True
    except Exception:
        return False


def handle_client(conn, addr):
    print(f"[connect] New connection from {addr}")
    try:
        fileobj = conn.makefile('r')
        while True:
            line = fileobj.readline()
            if not line:
                break
            try:
                msg = json.loads(line.strip())
            except json.JSONDecodeError:
                print(f"[error] Invalid JSON from {addr}: {line!r}")
                continue

            mtype = msg.get('type')
            if mtype == 'register':
                client_id = msg.get('id')
                pubkey = msg.get('pubkey')
                signature = msg.get('signature')
                signed = (client_id + pubkey).encode()

                if not client_id or not pubkey or not signature:
                    conn.sendall((json.dumps({
                        "type": "register_ack",
                        "status": "failed",
                        "reason": "missing fields"
                    }) + "\n").encode())
                    print(f"[reg] Registration failed: missing fields from {addr}")
                    continue

                # verify that the registering client owns the private key
                if verify_signature(pubkey, signed, signature):
                    with clients_lock:
                        clients[client_id] = {'pubkey_pem': pubkey, 'conn': conn}
                    ack = {
                        "type": "register_ack",
                        "status": "ok",
                        "relay_pubkey": RELAY_PUB.export_key('PEM').decode()
                    }
                    ack_bytes = json.dumps(ack).encode()
                    ack['signature'] = sign_bytes(ack_bytes)
                    conn.sendall((json.dumps(ack) + "\n").encode())
                    print(f"[reg] {client_id} registered successfully.")
                else:
                    conn.sendall((json.dumps({
                        "type": "register_ack",
                        "status": "failed",
                        "reason": "bad signature"
                    }) + "\n").encode())
                    print(f"[reg] Registration failed for {client_id}: bad signature.")

            elif mtype == 'auth_nonce':
                nonce_b64 = msg.get('nonce')
                if not nonce_b64:
                    conn.sendall((json.dumps({
                        "type": "auth_nonce_signed",
                        "status": "failed",
                        "reason": "missing nonce"
                    }) + "\n").encode())
                    print("[auth] Missing nonce in auth request.")
                    continue

                reply = {
                    "type": "auth_nonce_signed",
                    "nonce": nonce_b64
                }
                reply_bytes = json.dumps(reply).encode()
                reply['signature'] = sign_bytes(reply_bytes)
                conn.sendall((json.dumps(reply) + "\n").encode())
                print("[auth] Signed nonce for client.")

            elif mtype == 'forward':
                from_id = msg.get('from')
                to_id = msg.get('to')
                payload = msg.get('payload')
                signature_b64 = msg.get('signature')

                if not from_id or not to_id or payload is None:
                    conn.sendall((json.dumps({
                        "type": "forward_ack",
                        "status": "failed",
                        "reason": "missing fields"
                    }) + "\n").encode())
                    print("[fwd] Forward failed: missing fields.")
                    continue

                with clients_lock:
                    sender_rec = clients.get(from_id)
                    rec = clients.get(to_id)

                if not sender_rec:
                    conn.sendall((json.dumps({
                        "type": "forward_ack",
                        "status": "failed",
                        "reason": "unknown sender"
                    }) + "\n").encode())
                    print(f"[fwd] Unknown sender id={from_id}")
                    continue

                if not signature_b64:
                    conn.sendall((json.dumps({
                        "type": "forward_ack",
                        "status": "failed",
                        "reason": "missing signature"
                    }) + "\n").encode())
                    print(f"[fwd] Missing signature from {from_id}")
                    continue

                # Verify client signature over (from, to, payload)
                to_sign = {
                    "from": from_id,
                    "to": to_id,
                    "payload": payload
                }
                signed_bytes = json.dumps(to_sign, sort_keys=True).encode()
                if not verify_signature(sender_rec['pubkey_pem'], signed_bytes, signature_b64):
                    conn.sendall((json.dumps({
                        "type": "forward_ack",
                        "status": "failed",
                        "reason": "bad signature"
                    }) + "\n").encode())
                    print(f"[fwd] Dropped message from {from_id}: bad signature.")
                    continue

                if rec and rec.get('conn'):
                    try:
                        rec['conn'].sendall((json.dumps({
                            "type": "incoming",
                            "from": from_id,
                            "payload": payload
                        }) + "\n").encode())
                        conn.sendall((json.dumps({
                            "type": "forward_ack",
                            "status": "ok"
                        }) + "\n").encode())
                        print(f"[fwd] {from_id} -> {to_id}")
                    except Exception as e:
                        conn.sendall((json.dumps({
                            "type": "forward_ack",
                            "status": "failed",
                            "reason": "delivery error"
                        }) + "\n").encode())
                        print(f"[fwd] Error delivering to {to_id}: {e}")
                else:
                    conn.sendall((json.dumps({
                        "type": "forward_ack",
                        "status": "failed",
                        "reason": "recipient not found"
                    }) + "\n").encode())
                    print(f"[fwd] Recipient {to_id} not found.")
            else:
                print(f"[warn] Unknown message type from {addr}: {mtype}")

    except Exception as e:
        print("[error] Client handler exception:", e)
    finally:
        # clean up disconnected client from registry
        with clients_lock:
            to_remove = [cid for cid, rec in clients.items() if rec.get('conn') == conn]
            for cid in to_remove:
                del clients[cid]
                print(f"[reg] Removed disconnected client {cid}")
        print(f"[disconnect] Connection closed: {addr}")


def start_relay():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"[relay] Listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    finally:
        s.close()


if __name__ == '__main__':
    start_relay()
