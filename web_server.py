#!/usr/bin/python3
"""
Web relay server — secure by design:
  - Passwords hashed with bcrypt (never stored in plaintext)
  - JWT session tokens (HS256, 1h expiry)
  - Server only relays encrypted blobs; plaintext never reaches server
  - Key-exchange packets include Ed25519 signature so MITM is detectable
  - Rate limiting on auth endpoints
"""

import asyncio, json, logging, pathlib, os, time, secrets
import database
import bcrypt
import jwt
from aiohttp import web

logging.basicConfig(level=logging.INFO, format='%(asctime)s [WEB] %(message)s')

clients = {}        # username -> WebSocketResponse
WEB_DIR = pathlib.Path(__file__).parent / 'web'

# Secret for JWT — load from env in production, generate random for dev
JWT_SECRET = os.environ.get('JWT_SECRET') or secrets.token_hex(32)
JWT_ALG    = 'HS256'
JWT_TTL    = 3600  # 1 hour

# Simple in-memory rate limiter: ip -> [timestamps]
_auth_attempts: dict[str, list] = {}
RATE_LIMIT = 10   # max attempts
RATE_WINDOW = 60  # per 60 seconds


def _rate_ok(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _auth_attempts.get(ip, []) if now - t < RATE_WINDOW]
    _auth_attempts[ip] = attempts
    if len(attempts) >= RATE_LIMIT:
        return False
    _auth_attempts[ip].append(now)
    return True


def _make_token(username: str) -> str:
    payload = {'sub': username, 'exp': int(time.time()) + JWT_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _verify_token(token: str):
    """Returns username or raises."""
    data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    return data['sub']


# ── HTTP auth endpoints ───────────────────────────────────────────────────────

async def handle_register(request: web.Request):
    ip = request.remote
    if not _rate_ok(ip):
        return web.json_response({'error': 'Too many requests'}, status=429)

    body = await request.json()
    username = (body.get('username') or '').strip()
    password = (body.get('password') or '')

    if not username or not password:
        return web.json_response({'error': 'Missing fields'}, status=400)
    if len(username) > 32 or len(password) < 8:
        return web.json_response({'error': 'Invalid username or password too short'}, status=400)

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if not database.register_user(username, pw_hash):
        return web.json_response({'error': 'Username taken'}, status=409)

    token = _make_token(username)
    logging.info(f'Registered: {username}')
    return web.json_response({'token': token})


async def handle_login(request: web.Request):
    ip = request.remote
    if not _rate_ok(ip):
        return web.json_response({'error': 'Too many requests'}, status=429)

    body = await request.json()
    username = (body.get('username') or '').strip()
    password = (body.get('password') or '')

    stored = database.get_user_hash(username)
    # Always run bcrypt to prevent timing attacks
    dummy = b'$2b$12$' + b'x' * 53
    check_hash = stored.encode() if stored else dummy
    valid = bcrypt.checkpw(password.encode(), check_hash) and stored is not None

    if not valid:
        return web.json_response({'error': 'Invalid credentials'}, status=401)

    token = _make_token(username)
    logging.info(f'Login: {username}')
    return web.json_response({'token': token})


# ── WebSocket ─────────────────────────────────────────────────────────────────

async def broadcast_users():
    user_list = list(clients.keys())
    for uname, ws in list(clients.items()):
        try:
            await ws.send_str(json.dumps({
                'type': 'users',
                'users': [u for u in user_list if u != uname]
            }))
        except Exception:
            pass


async def websocket_handler(request: web.Request):
    # Authenticate via token in query string: /ws?token=...
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

            # Force correct sender — client cannot spoof 'from'
            packet['from'] = username

            if ptype in ('key_exchange', 'key_ratchet', 'message'):
                to = packet.get('to')
                if to and to in clients:
                    # Store encrypted blob for offline delivery
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


# ── Static / index ────────────────────────────────────────────────────────────

async def index(request):
    return web.FileResponse(WEB_DIR / 'index.html')


# ── App setup ─────────────────────────────────────────────────────────────────

database.init_db()

app = web.Application()
app.router.add_get('/',            index)
app.router.add_post('/register',   handle_register)
app.router.add_post('/login',      handle_login)
app.router.add_get('/ws',          websocket_handler)
app.router.add_static('/web',      WEB_DIR)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f'Server: http://0.0.0.0:{port}')
    if not os.environ.get('JWT_SECRET'):
        print('WARNING: JWT_SECRET not set — using random key (sessions reset on restart)')
    web.run_app(app, host='0.0.0.0', port=port)
