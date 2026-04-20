#!/usr/bin/python3
"""Web-based relay server. Serves the HTML client and relays messages via WebSocket."""

import asyncio, json, logging, pathlib, os
from aiohttp import web

logging.basicConfig(level=logging.INFO, format='%(asctime)s [WEB] %(message)s')

clients = {}   # username -> WebSocketResponse
WEB_DIR = pathlib.Path(__file__).parent / 'web'


async def broadcast_users():
    """Send updated online users list to all connected clients."""
    user_list = list(clients.keys())
    for username, ws in list(clients.items()):
        try:
            await ws.send_str(json.dumps({'type': 'users', 'users': [u for u in user_list if u != username]}))
        except Exception:
            pass


async def index(request):
    return web.FileResponse(WEB_DIR / 'index.html')


async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    username = None
    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                break
            packet = json.loads(msg.data)
            ptype = packet.get('type')

            if ptype == 'register':
                username = packet['username']
                clients[username] = ws
                logging.info(f'{username} connected')
                await ws.send_str(json.dumps({'type': 'ack'}))
                await broadcast_users()

            elif ptype in ('key_exchange', 'message'):
                to = packet.get('to')
                if to and to in clients:
                    await clients[to].send_str(json.dumps(packet))
                else:
                    await ws.send_str(json.dumps({'type': 'error', 'msg': f'{to} offline'}))

    except Exception as e:
        logging.error(f'WS error ({username}): {e}')
    finally:
        if username:
            clients.pop(username, None)
            logging.info(f'{username} disconnected')
            await broadcast_users()
        await ws.close()

    return ws


app = web.Application()
app.router.add_get('/', index)
app.router.add_get('/ws', websocket_handler)
app.router.add_static('/web', WEB_DIR)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f'Open http://<your-ip>:{port} on any device')
    web.run_app(app, host='0.0.0.0', port=port)
