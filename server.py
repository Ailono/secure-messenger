#!/usr/bin/python3
"""
Relay server for secure messenger.
- Routes encrypted messages between clients (server never sees plaintext)
- TLS encryption for transport (set SSL_CERT / SSL_KEY env vars)
- Username spoofing prevented: 'from' field set server-side
"""

import socket, ssl, threading, json, logging, os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [SERVER] %(message)s')

clients = {}  # username -> socket
lock = threading.Lock()


def handle_client(conn, addr):
    username = None
    try:
        data = conn.recv(4096).decode('utf-8')
        msg = json.loads(data)

        if msg.get('type') == 'register':
            username = msg['username']
            with lock:
                clients[username] = conn
            logging.info(f"{username} connected from {addr}")
            conn.sendall(json.dumps({'type': 'ack'}).encode('utf-8'))

            while True:
                raw = conn.recv(8192)
                if not raw:
                    break
                packet = json.loads(raw.decode('utf-8'))

                if packet['type'] == 'message':
                    recipient = packet['to']
                    # Enforce correct sender — client cannot spoof 'from'
                    packet['from'] = username
                    payload = json.dumps(packet).encode('utf-8')
                    with lock:
                        if recipient in clients:
                            clients[recipient].sendall(payload)
                        else:
                            conn.sendall(json.dumps({'type': 'error', 'msg': 'user offline'}).encode('utf-8'))

                elif packet['type'] == 'key_exchange':
                    recipient = packet['to']
                    packet['from'] = username
                    payload = json.dumps(packet).encode('utf-8')
                    with lock:
                        if recipient in clients:
                            clients[recipient].sendall(payload)

    except Exception as e:
        logging.error(f"Error with {username or addr}: {e}")
    finally:
        if username:
            with lock:
                clients.pop(username, None)
            logging.info(f"{username} disconnected")
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    cert = os.environ.get('SSL_CERT')
    key  = os.environ.get('SSL_KEY')

    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(cert, key)
        srv = ctx.wrap_socket(srv, server_side=True)
        logging.info("TLS enabled (TLS 1.3)")
    else:
        logging.warning("SSL_CERT/SSL_KEY not set — running WITHOUT TLS (dev only)")

    srv.bind(('0.0.0.0', 9999))
    srv.listen(10)
    logging.info("Server listening on port 9999")

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
