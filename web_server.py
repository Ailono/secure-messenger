#!/usr/bin/python3
"""
Web relay server — secure by design:
  - Passwords hashed with bcrypt
  - JWT session tokens (HS256, 1h expiry)
  - Server only relays/stores encrypted blobs — plaintext never seen
  - Rate limiting on auth endpoints
  - Sender enforced server-side from JWT
"""

import asyncio, json, logging, pathlib, os, time, secrets
import database
import bcrypt
import jwt
from aiohttp import web

logging.basicConfig(level=logging.INFO, format='%(asctime)s [WEB] %(message)s')

clients = {}        # username -> WebSocketResponse
WEB_DIR = pathlib.Path(__file__).parent / 'web'

JWT_SECRET = os.environ.get('JWT_SECRET') or secrets.token_hex(32)
JWT_ALG    = 'HS256'
JWT_TTL    = 3600

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


# ── REST: users & history ─────────────────────────────────────────────────────

async def handle_users(request: web.Request):
    """All registered users (for People tab)."""
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    all_users = [u for u in database.get_all_users() if u != username]
    online = list(clients.keys())
    return web.json_response({'users': all_users, 'online': online})


async def handle_conversations(request: web.Request):
    """Chats tab — conversations this user has had."""
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    convs = database.get_conversations(username)
    online = list(clients.keys())
    return web.json_response({'conversations': convs, 'online': online})


async def handle_history(request: web.Request):
    """Encrypted message history between two users."""
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    peer = request.match_info['peer']
    messages = database.get_history(username, peer)
    return web.json_response({'messages': messages})


async def handle_delete_conversation(request: web.Request):
    try:
        username = _verify_token(request.rel_url.query.get('token', ''))
    except Exception:
        return web.json_response({'error': 'Unauthorized'}, status=401)
    peer = request.match_info['peer']
    database.delete_conversation(username, peer)
    return web.json_response({'ok': True})


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

    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                break
            packet = json.loads(msg.data)
            ptype = packet.get('type')
            packet['from'] = username  # enforce sender

            if ptype in ('key_exchange', 'key_ratchet', 'message'):
                to = packet.get('to')
                if to and to in clients:
                    if ptype == 'message':
                        database.store_message(username, to, packet.get('data', ''))
                    await clients[to].send_str(json.dumps(packet))
                else:
                    await ws.send_str(json.dumps({'type': 'error', 'msg': f'{to} offline'}))

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
    return web.FileResponse(WEB_DIR / 'index.html')


# ── App ───────────────────────────────────────────────────────────────────────

database.init_db()

app = web.Application()
app.router.add_get('/',                    index)
app.router.add_post('/register',           handle_register)
app.router.add_post('/login',              handle_login)
app.router.add_get('/users',               handle_users)
app.router.add_get('/conversations',       handle_conversations)
app.router.add_get('/history/{peer}',      handle_history)
app.router.add_delete('/conversation/{peer}', handle_delete_conversation)
app.router.add_get('/ws',                  websocket_handler)
app.router.add_static('/web',              WEB_DIR)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    if not os.environ.get('JWT_SECRET'):
        print('WARNING: JWT_SECRET not set — using random key')
    web.run_app(app, host='0.0.0.0', port=port)
