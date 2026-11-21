#!/usr/bin/env python3
"""Evaluate JS in a Chrome's first page tab over the DevTools protocol.

    adb forward tcp:9222 localabstract:chrome_devtools_remote
    python3 -I android-cdp.py 'document.title'          # expression
    python3 -I android-cdp.py -f probe.js               # file

Android Chrome through adb on port 9222 by default; CDP_PORT=9333 reaches a
desktop Chrome started with --remote-debugging-port=9333 instead.

Stdlib only (no websocket package on this Mac). Awaits promises and returns
the value as JSON.
"""
import base64, json, os, socket, struct, sys, urllib.request

PORT = os.environ.get('CDP_PORT', '9222')

def tab_ws():
    tabs = json.load(urllib.request.urlopen(f'http://localhost:{PORT}/json'))
    page = next(t for t in tabs if t['type'] == 'page')
    return page['webSocketDebuggerUrl']

def connect(url):
    rest = url.split('://', 1)[1]
    hostport, path = rest.split('/', 1)
    host, port = hostport.split(':')
    s = socket.create_connection((host, int(port)), timeout=120)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f'GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\n'
               f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
    head = b''
    while b'\r\n\r\n' not in head:
        head += s.recv(1)
    if b' 101 ' not in head.split(b'\r\n')[0]:
        raise SystemExit(head.decode(errors='replace'))
    s.settimeout(None)
    return s

def send(s, text):
    data = text.encode()
    mask = os.urandom(4)
    n = len(data)
    hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else
                            bytes([0x80 | 126]) + struct.pack('>H', n) if n < 65536 else
                            bytes([0x80 | 127]) + struct.pack('>Q', n))
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

def recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf

def recv(s):
    msg = b''
    while True:
        b0, b1 = recv_exact(s, 2)
        n = b1 & 0x7f
        if n == 126:
            n = struct.unpack('>H', recv_exact(s, 2))[0]
        elif n == 127:
            n = struct.unpack('>Q', recv_exact(s, 8))[0]
        msg += recv_exact(s, n)
        if b0 & 0x80:
            return msg.decode()

def main():
    args = sys.argv[1:]
    expr = open(args[1]).read() if args[0] == '-f' else args[0]
    s = connect(tab_ws())
    send(s, json.dumps({'id': 1, 'method': 'Runtime.evaluate', 'params': {
        'expression': expr, 'awaitPromise': True, 'returnByValue': True}}))
    while True:
        m = json.loads(recv(s))
        if m.get('id') == 1:
            # Both exits print a non-JSON line, so a caller parsing stdout+stderr
            # as the value fails loudly rather than reading an error as a result.
            if 'error' in m:
                raise SystemExit('CDP error: ' + m['error'].get('message', json.dumps(m['error'])))
            r = m['result']
            if 'exceptionDetails' in r:
                d = r['exceptionDetails']
                raise SystemExit('JS exception: ' + d.get('exception', {}).get('description', d.get('text', ''))[:2000])
            print(json.dumps(r['result'].get('value'), indent=1))
            return

main()
