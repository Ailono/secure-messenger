#!/usr/bin/python3
"""Relay server for secure messenger. Routes encrypted messages between clients."""

import socket, threading, json, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [SERVER] %(message)s')

clients = {}  # username -> socket
lock = threading.Lock()


def handle_client(conn, addr):
    username = None
    try:
        # First message: registration {"type":"register","username":"alice"}
        data = conn.recv(4096).decode('utf-8')
        msg = json.loads(data)
        
        if msg.get('type') == 'register':
            username = msg['username']
            with lock:
                clients[username] = conn
            logging.info(f"{username} connected from {addr}")
            conn.sendall(json.dumps({'type': 'ack'}).encode('utf-8'))
            
            # Listen for messages
            while True:
                raw = conn.recv(8192)
                if not raw:
                    break
                packet = json.loads(raw.decode('utf-8'))
                
                if packet['type'] == 'message':
                    recipient = packet['to']
                    with lock:
                        if recipient in clients:
                            clients[recipient].sendall(raw)
                            logging.info(f"{username} -> {recipient}")
                        else:
                            conn.sendall(json.dumps({'type':'error','msg':'user offline'}).encode('utf-8'))
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
    srv.bind(('0.0.0.0', 9999))
    srv.listen(10)
    logging.info("Server listening on port 9999")
    
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
