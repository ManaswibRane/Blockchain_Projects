#!/usr/bin/env python3
"""
Chain Lens API server - pure Python stdlib, zero external dependencies.
Endpoints:
  GET  /api/health
  POST /api/analyze          (JSON body: fixture)
  POST /api/analyze/block    (multipart: blk_file, rev_file, xor_file)
  GET  /                     (web UI)
"""
import sys
import os
import json
import traceback
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add project root to path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence default access log

    # ------------------------------------------------------------------ #
    #  Routing
    # ------------------------------------------------------------------ #

    def do_OPTIONS(self):
        self._cors(200)

    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/api/health':
            self._json(200, {'ok': True})
        elif path in ('/', '/index.html'):
            self._html()
        else:
            self._json(404, {'ok': False, 'error': {'code': 'NOT_FOUND', 'message': path}})

    def do_POST(self):
        path = self.path.split('?')[0]
        if path in ('/api/analyze', '/api/analyze/fixture'):
            self._handle_analyze()
        elif path == '/api/analyze/block':
            self._handle_block()
        else:
            self._json(404, {'ok': False, 'error': {'code': 'NOT_FOUND', 'message': path}})

    # ------------------------------------------------------------------ #
    #  Handlers
    # ------------------------------------------------------------------ #

    def _handle_analyze(self):
        try:
            body = self._read_body()
            fixture = json.loads(body)
        except Exception as e:
            self._json(400, {'ok': False, 'error': {'code': 'INVALID_JSON', 'message': str(e)}})
            return
        try:
            from services.analyzer import analyze_transaction
            result = analyze_transaction(fixture)
        except Exception as e:
            self._json(500, {'ok': False, 'error': {'code': 'INTERNAL_ERROR', 'message': traceback.format_exc()}})
            return
        self._json(200 if result.get('ok') else 400, result)

    def _handle_block(self):
        try:
            ct = self.headers.get('Content-Type', '')
            boundary = None
            for part in ct.split(';'):
                p = part.strip()
                if p.startswith('boundary='):
                    boundary = p[9:].strip('"').encode()
            if not boundary:
                raise ValueError('No multipart boundary found')

            body = self._read_body()
            files = _parse_multipart(body, boundary)

            blk_data = files.get('blk_file', b'')
            rev_data = files.get('rev_file', b'')
            xor_data = files.get('xor_file', b'')

            from core.block_parser import parse_block_file, xor_decode
            blk = xor_decode(blk_data, xor_data)
            rev = xor_decode(rev_data, xor_data)
            results = parse_block_file(blk, rev)
        except Exception as e:
            self._json(400, {'ok': False, 'error': {'code': 'BLOCK_ERROR', 'message': traceback.format_exc()}})
            return
        self._json(200, {'ok': True, 'blocks': results})

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length)

    def _json(self, status: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _html(self):
        html_path = _ROOT / 'templates' / 'index.html'
        if html_path.exists():
            body = html_path.read_bytes()
        else:
            body = b'<h1>Chain Lens</h1><p>templates/index.html not found</p>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors(self, status: int):
        self.send_response(status)
        self._cors_headers()
        self.end_headers()

    def _cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')


# ------------------------------------------------------------------ #
#  Multipart parser (no external deps)
# ------------------------------------------------------------------ #

def _parse_multipart(body: bytes, boundary: bytes) -> dict:
    files = {}
    delimiter = b'--' + boundary
    parts = body.split(delimiter)
    for part in parts[1:]:
        if part.startswith(b'--'):
            break
        # Split headers / body
        if b'\r\n\r\n' in part:
            raw_headers, data = part.split(b'\r\n\r\n', 1)
        elif b'\n\n' in part:
            raw_headers, data = part.split(b'\n\n', 1)
        else:
            continue
        data = data.rstrip(b'\r\n')
        # Extract field name from Content-Disposition
        name = None
        for line in raw_headers.decode('utf-8', errors='replace').splitlines():
            if 'Content-Disposition' in line:
                for seg in line.split(';'):
                    seg = seg.strip()
                    if seg.startswith('name='):
                        name = seg[5:].strip('"\'')
        if name:
            files[name] = data
    return files


# ------------------------------------------------------------------ #
#  Entry point
# ------------------------------------------------------------------ #

def run():
    port = int(os.environ.get('PORT', 3000))
    server = HTTPServer(('0.0.0.0', port), Handler)
    server.serve_forever()


if __name__ == '__main__':
    run()