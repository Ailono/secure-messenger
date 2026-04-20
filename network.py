#!/usr/bin/python3
"""Network communication module."""

import socket, ssl, threading, queue, logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

message_queue = queue.Queue()


def build_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Build a TLS 1.3 mutual-auth SSL context."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations('ca.pem')
    return ctx


def exchange_keys(sender_id: str, recipient_host: str, local_private_key, peer_public_key) -> bytes:
    """
    Perform ECDH key exchange over a TLS connection.
    Returns the derived shared secret bytes.
    """
    shared_secret = local_private_key.exchange(ec.ECDH(), peer_public_key)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    return derived


def send_packet(host: str, port: int, payload: bytes, ssl_ctx: ssl.SSLContext):
    """Send a raw payload over a TLS socket."""
    with socket.create_connection((host, port), timeout=10) as raw:
        with ssl_ctx.wrap_socket(raw, server_hostname=host) as conn:
            conn.sendall(len(payload).to_bytes(4, 'big') + payload)
            logger.info("Packet sent to %s:%d", host, port)


def listen(port: int, ssl_ctx: ssl.SSLContext):
    """Listen for incoming encrypted messages and enqueue them."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', port))
        srv.listen(5)
        logger.info("Listening on port %d", port)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_handle_client, args=(conn, addr, ssl_ctx), daemon=True).start()


def _handle_client(conn, addr, ssl_ctx: ssl.SSLContext):
    try:
        with ssl_ctx.wrap_socket(conn, server_side=True) as sconn:
            length = int.from_bytes(sconn.recv(4), 'big')
            data = sconn.recv(length)
            message_queue.put(data)
            logger.info("Received message from %s", addr)
    except Exception as e:
        logger.error("Error handling client %s: %s", addr, e)
