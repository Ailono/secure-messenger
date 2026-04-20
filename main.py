#!/usr/bin/python3
"""Secure Messenger core application."""

import sys, time, json, logging, argparse
import crypto_utils, database, network

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


def send_message(sender_id: str, recipient_id: str, recipient_host: str, message: str) -> dict:
    """Encrypt and send a message to a recipient."""
    # Generate ephemeral key pair for this session
    private_key, public_key = crypto_utils.generate_keypair()

    # In a real deployment, the peer's public key is fetched from a key server.
    # Here we generate a placeholder to demonstrate the flow.
    peer_private, peer_public = crypto_utils.generate_keypair()

    shared_secret = crypto_utils.compute_shared_secret(private_key, peer_public)
    keys = crypto_utils.derive_keys(shared_secret)

    encrypted_data = crypto_utils.encrypt(message, keys['encryption_key'])

    record = {
        'sender': sender_id,
        'recipient': recipient_id,
        'data': json.dumps(encrypted_data),
        'timestamp': time.time(),
    }

    database.store_message(record)
    logger.info("Message from %s to %s stored and ready to send.", sender_id, recipient_id)
    return record


def main():
    parser = argparse.ArgumentParser(description='Secure Messenger')
    parser.add_argument('--username', required=True)
    parser.add_argument('--password', required=True)
    # auth-token intentionally not logged or stored in plaintext
    parser.add_argument('--auth-token', required=True, dest='auth_token')
    args = parser.parse_args()

    database.init_db()
    database.purge_old_messages(days=30)

    logger.info("Messenger started for user: %s", args.username)

    # Example: send a test message to self
    record = send_message(args.username, args.username, 'localhost', 'Hello, secure world!')
    logger.info("Sent record: %s", record)


if __name__ == '__main__':
    main()
