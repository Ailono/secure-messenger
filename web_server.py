#!/usr/bin/python3
"""
Web relay server — secure by design:
  - Passwords hashed with bcrypt
  - JWT session tokens (HS256, 1h expiry)
  - Server only relays/stores encrypted blobs — plaintext never seen
  - Rate limiting on auth endpoints
  - Sender enforced server-side from JWT
  - Offline message delivery on reconnect
  - FCM push notifications for offline users
  - Message status: sent / delivered / read
"""

import asyncio, json, logging, pathlib, os, time, secrets
import database
import bcrypt
import jwt
import aiohttp
from aiohttp import web

logging.basicConfig(level=logging.INFO, format='%(asctime)s [WEB] %(message)s')

clients = {}        # username -> WebSocketResponse
WEB_DIR = pathlib.Path(__file__).parent / 'web'

JWT_SECRET = os.environ.get('JWT_SECRET') or secrets.token_hex(32)
JWT_ALG    = 'HS256'
JWT_TTL    = 3600

# FCM V1 via service account
_FIREBASE_SA = None
_fcm_project_id = None
try:
    _sa_json = os.environ.get('FIREBASE_SERVICE_ACCOUNT', '')
    if _sa_json:
        _FIREBASE_SA = json.loads(_sa_json)
        _fcm_project_id = _FIREBASE_SA.get('project_id')
except Exception:
    pass

_auth_attempts: dict = {}
RATE_LIMIT  = 10
RATE_WINDOW = 60


def _rate_ok(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _auth_attempts.get(ip, []) if now - t < RATE_WINDOW]
    _auth_attempts[ip] = attempts
    if len(attempts) >= RATE_LIMIT:
        return False
    _auth_attempts[ip].append(now)
    return True


def _make_token(username: str) -> str:
    return jwt.encode(
        {'sub': username, 'exp': int(time.time()) + JWT_TTL},
        JWT_SECRET, algorithm=JWT_ALG
    )


def _verify_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])['sub']


# ── FCM V1 push ───────────────────────────────────────────────────────────────

async def _get_fcm_access_token() -> str | None:
    if not _FIREBASE_SA:
        return None
    try:
        import google.oauth2.service_account as sa
        import google.auth.transport.requests as ga_requests
        credentials = sa.Credentials.from_service_account_info(
            _FIREBASE_SA,
            scopes=['https://www.googleapis.com/auth/firebase.messaging']
        )
        credentials.refresh(ga_requests.Request())
        return credentials.token
    except Exception as e:
        logging.warning(f'FCM token error: {e}')
        return None


async def _send_fcm(to_token: str, sender: str):
    if not _FIREBASE_SA or not to_token:
        return
    access_token = await asyncio.get_event_loop().run_in_executor(None, _get_fcm_access_token_sync)
    if not access_token:
        return
    payload = {
        'message': {
            'token': to_token,
            'notification': {
                'title': sender,
                'body': '🔒 Новое зашифрованное сообщение',
            },
            'data': {'sender': sender},
            'android': {'priority': 'high'},
        }
    }
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(
                f'https://fcm.googleapis.com/v1/projects/{_fcm_project_id}/messages:send',
                json=payload,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json',
                },
                timeout=aiohttp.ClientTimeout(total=5),
            )
    except Exception as e:
        logging.warning(f'FCM send error: {e}')


def _get_fcm_access_token_sync():
    if not _FIREBASE_SA:
        return None
    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request
        credentials = service_account.Credentials.from_service_account_info(
            _FIREBASE_SA,
            scopes=['https://www.googleapis.com/auth/firebase.messaging']
        )
        credentials.refresh(Request())
        return credentials.token
    except Exception as e:
        logging.warning(f'FCM token sync error: {e}')
        return None


# ── Auth endpoints ────────────────────────────────────────────────────────────

async def handle_register(request: web.Request):
    if not _rate_ok(request.remote):
        return web.json_response({'error': 'Too many requests'}, status=429)
    body = await request.json()
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    if not username or not password:
        return web.json_response({'error': 'Missing fields'}, status=400)
    if len(username) > 32 or len(password) < 8:
        return web.json_response({'error': 'Invalid username or password too short'}, status=400)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if not database.register_user(username, pw_hash):
        return web.json_response({'error': 'Username taken'}, status=409)
    return web.json_response({'token': _make_token(username)})


async def handle_login(request: web.Request):
    if not _rate_ok(request.remote):
        return web.json_response({'error': 'Too many requests'}, status=429)
    body = await request.json()
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    stored = database.get_user_hash(username)
    dummy = b'$2b$12$' + b'x' * 53
    valid = bcrypt.checkpw(password.encode(), stored.encode() if stored else dummy) and stored is not None
    if not valid:
        return web.json_response({'error': 'Invalid credentials'}, status=401)
    return web.json_response({'token': _make_token(username)})


# ── REST ──────────────────────────────────────────────────────────────────────

async def handle_users(request: web.Request):
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    all_users = [u for u in database.get_all_users() if u != username]
    online = list(clients.keys())
    return web.json_response({'users': all_users, 'online': online})


async def handle_conversations(request: web.Request):
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    convs = database.get_conversations(username)
    online = list(clients.keys())
    return web.json_response({'conversations': convs, 'online': online})


async def handle_history(request: web.Request):
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    peer = request.match_info['peer']
    messages = database.get_history(username, peer)
    # Mark messages from peer as delivered when history is fetched
    database.mark_delivered_bulk(peer, username)
    return web.json_response({'messages': messages})


async def handle_delete_conversation(request: web.Request):
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    peer = request.match_info['peer']
    database.delete_conversation(username, peer)
    return web.json_response({'ok': True})


async def handle_fcm_token(request: web.Request):
    """Save FCM token for push notifications."""
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    body = await request.json()
    fcm_token = body.get('fcm_token', '')
    if fcm_token:
        database.save_fcm_token(username, fcm_token)
    return web.json_response({'ok': True})


async def handle_get_pubkey(request: web.Request):
    """Get stored public key for a user (for offline messaging)."""
    try:
        _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    username = request.match_info['username']
    pubkey = database.get_public_key(username)
    if not pubkey:
        return web.json_response({'error': 'No key'}, status=404)
    return web.json_response({'pubkey': pubkey})


# ── Chat requests ─────────────────────────────────────────────────────────────

SUPPORT_BOT = 'SecureBot'


def _bot_message(recipient: str, text: str):
    import json as _json
    payload = _json.dumps({'bot': True, 'text': text})
    database.store_message(SUPPORT_BOT, recipient, payload)


async def handle_chat_request(request: web.Request):
    try:
        sender = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    body = await request.json()
    recipient = body.get('to', '').strip()
    if not recipient or recipient == sender:
        return web.json_response({'error': 'Invalid recipient'}, status=400)
    if not database.get_user_hash(recipient):
        return web.json_response({'error': 'User not found'}, status=404)
    if database.are_contacts(sender, recipient):
        return web.json_response({'status': 'already_contacts'})
    ok = database.send_chat_request(sender, recipient)
    if not ok:
        return web.json_response({'status': 'already_sent'})
    _bot_message(recipient,
        f'👤 Пользователь *{sender}* хочет начать с вами переписку. Принять запрос?')
    if recipient in clients:
        await clients[recipient].send_str(json.dumps({
            'type': 'chat_request', 'from': sender,
        }))
    return web.json_response({'status': 'sent'})


async def handle_chat_request_respond(request: web.Request):
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    body = await request.json()
    sender = body.get('from', '').strip()
    action = body.get('action', '')
    if action not in ('accept', 'decline'):
        return web.json_response({'error': 'Invalid action'}, status=400)
    status = 'accepted' if action == 'accept' else 'declined'
    database.update_chat_request(sender, username, status)
    if action == 'accept':
        _bot_message(username, f'✅ Вы приняли запрос от *{sender}*. Можете начать общение!')
        _bot_message(sender, f'✅ Пользователь *{username}* принял ваш запрос!')
        if sender in clients:
            await clients[sender].send_str(json.dumps({'type': 'request_accepted', 'by': username}))
    else:
        _bot_message(username, f'❌ Вы отклонили запрос от *{sender}*.')
        _bot_message(sender, f'❌ Пользователь *{username}* отклонил ваш запрос.')
        if sender in clients:
            await clients[sender].send_str(json.dumps({'type': 'request_declined', 'by': username}))
    return web.json_response({'status': status})


# ── WebSocket ─────────────────────────────────────────────────────────────────

async def broadcast_users():
    user_list = list(clients.keys())
    for uname, ws in list(clients.items()):
        try:
            await ws.send_str(json.dumps({
                'type': 'online',
                'users': [u for u in user_list if u != uname]
            }))
        except Exception:
            pass


async def websocket_handler(request: web.Request):
    token = request.rel_url.query.get('token', '')
    try:
        username = _verify_token(token)
    except Exception:
        return web.Response(status=401, text='Unauthorized')

    ws = web.WebSocketResponse()
    await ws.prepare(request)
    clients[username] = ws
    logging.info(f'{username} connected')
    await ws.send_str(json.dumps({'type': 'ack', 'username': username}))
    await broadcast_users()

    # Deliver pending offline messages
    pending = database.get_pending_messages(username)
    for msg in pending:
        await ws.send_str(json.dumps({
            'type': 'message',
            'from': msg['sender'],
            'data': msg['ciphertext'],
            'id':   msg['id'],
        }))
        database.mark_delivered(msg['id'])

    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                break
            packet = json.loads(msg.data)
            ptype = packet.get('type')
            packet['from'] = username  # enforce sender

            if ptype in ('key_exchange', 'key_ratchet'):
                to = packet.get('to')
                if ptype == 'key_exchange':
                    database.save_public_key(username, packet.get('pubkey', ''))
                if to and to in clients:
                    await clients[to].send_str(json.dumps(packet))

            elif ptype == 'message':
                to = packet.get('to')
                if not to:
                    continue
                msg_id = database.store_message(username, to, packet.get('data', ''))
                packet['id'] = msg_id
                # Confirm to sender: message stored
                await ws.send_str(json.dumps({'type': 'status', 'id': msg_id, 'status': 'sent'}))
                if to in clients:
                    # Peer online — deliver immediately
                    await clients[to].send_str(json.dumps(packet))
                    database.mark_delivered(msg_id)
                    await ws.send_str(json.dumps({'type': 'status', 'id': msg_id, 'status': 'delivered'}))
                else:
                    # Peer offline — send FCM push
                    fcm_token = database.get_fcm_token(to)
                    if fcm_token:
                        asyncio.create_task(_send_fcm(fcm_token, username))

            elif ptype == 'read':
                # Recipient tells sender their messages were read
                peer = packet.get('peer')
                if peer:
                    database.mark_read(peer, username)
                    if peer in clients:
                        await clients[peer].send_str(json.dumps({
                            'type': 'status_bulk', 'from': username, 'status': 'read'
                        }))

    except Exception as e:
        logging.error(f'WS error ({username}): {e}')
    finally:
        clients.pop(username, None)
        logging.info(f'{username} disconnected')
        await broadcast_users()
        await ws.close()

    return ws


# ── Static ────────────────────────────────────────────────────────────────────

async def index(request):
    resp = web.FileResponse(WEB_DIR / 'index.html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return resp


# ── App ───────────────────────────────────────────────────────────────────────

database.init_db()

app = web.Application()
app.router.add_get('/',                       index)
app.router.add_post('/register',              handle_register)
app.router.add_post('/login',                 handle_login)
app.router.add_get('/users',                  handle_users)
app.router.add_get('/conversations',          handle_conversations)
app.router.add_get('/history/{peer}',         handle_history)
app.router.add_delete('/conversation/{peer}', handle_delete_conversation)
app.router.add_get('/pubkey/{username}',       handle_get_pubkey)
app.router.add_post('/fcm_token',             handle_fcm_token)
app.router.add_post('/chat_request',          handle_chat_request)
app.router.add_post('/chat_request/respond',  handle_chat_request_respond)
app.router.add_get('/ws',                     websocket_handler)
app.router.add_static('/web',                 WEB_DIR)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    if not os.environ.get('JWT_SECRET'):
        print('WARNING: JWT_SECRET not set — using random key')
    web.run_app(app, host='0.0.0.0', port=port)
