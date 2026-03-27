#!/usr/bin/env python3
import os, sys, json, glob, tempfile, shutil, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PORT = int(os.environ.get('PORT', 3000))

try:
    from flask import Flask, jsonify, send_from_directory, request
except ImportError:
    print("Flask not found. pip install flask", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__, static_folder='src/web/public')
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')


# ── Force JSON errors (never return HTML) ────────────────────────────────────
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def json_error(e):
    return jsonify({"ok": False, "error": {"code": str(e.code), "message": str(e)}}), e.code


@app.after_request
def add_cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return r


# ── Health ────────────────────────────────────────────────────────────────────
@app.route('/api/health')
def health():
    return jsonify({"ok": True})


# ── List analyzed files ───────────────────────────────────────────────────────
@app.route('/api/blocks')
def list_blocks():
    os.makedirs(OUT_DIR, exist_ok=True)
    stems = []
    for path in sorted(glob.glob(os.path.join(OUT_DIR, '*.json'))):
        stem = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path) as f:
                d = json.load(f)
            stems.append({
                'stem': stem,
                'file': d.get('file', stem + '.dat'),
                'block_count': d.get('block_count', 0),
                'total_txs': d.get('analysis_summary', {}).get('total_transactions_analyzed', 0),
                'flagged': d.get('analysis_summary', {}).get('flagged_transactions', 0),
            })
        except Exception:
            stems.append({'stem': stem, 'file': stem + '.dat',
                          'block_count': 0, 'total_txs': 0, 'flagged': 0})
    return jsonify({"ok": True, "blocks": stems})


# ── Get single block analysis ─────────────────────────────────────────────────
@app.route('/api/blocks/<stem>')
def get_block(stem):
    safe = ''.join(c for c in stem if c.isalnum() or c in '-_')
    path = os.path.join(OUT_DIR, f'{safe}.json')
    if not os.path.isfile(path):
        return jsonify({"ok": False, "error": {"code": "NOT_FOUND",
                        "message": f"No analysis for {safe}"}}), 404
    with open(path) as f:
        return jsonify(json.load(f))


# ── Get single tx ─────────────────────────────────────────────────────────────
@app.route('/api/blocks/<stem>/tx/<txid>')
def get_tx(stem, txid):
    safe = ''.join(c for c in stem if c.isalnum() or c in '-_')
    path = os.path.join(OUT_DIR, f'{safe}.json')
    if not os.path.isfile(path):
        return jsonify({"ok": False, "error": {"code": "NOT_FOUND",
                        "message": "Block not found"}}), 404
    with open(path) as f:
        data = json.load(f)
    for block in data.get('blocks', []):
        for tx in block.get('transactions', []):
            if tx.get('txid') == txid:
                return jsonify({"ok": True, "tx": tx,
                                "block_hash": block.get('block_hash')})
    return jsonify({"ok": False, "error": {"code": "TX_NOT_FOUND",
                    "message": f"tx {txid} not found"}}), 404


# ── Upload + analyze block files ─────────────────────────────────────────────
@app.route('/api/analyze/block', methods=['POST'])
def analyze_block():
    tmp = None
    try:
        blk_file = request.files.get('blk_file')
        rev_file = request.files.get('rev_file')
        xor_file = request.files.get('xor_file')

        if not blk_file or not rev_file or not xor_file:
            return jsonify({"ok": False, "error": {
                "code": "MISSING_FILES",
                "message": "blk_file, rev_file and xor_file are all required"
            }}), 400

        # Sanitize filename — strip any directory component (Windows paths)
        blk_name = os.path.basename(blk_file.filename or 'blk.dat').replace('\\', '/').split('/')[-1]
        rev_name = os.path.basename(rev_file.filename or 'rev.dat').replace('\\', '/').split('/')[-1]
        xor_name = os.path.basename(xor_file.filename or 'xor.dat').replace('\\', '/').split('/')[-1]

        tmp = tempfile.mkdtemp()
        blk_path = os.path.join(tmp, blk_name)
        rev_path = os.path.join(tmp, rev_name)
        xor_path = os.path.join(tmp, xor_name)

        blk_file.save(blk_path)
        rev_file.save(rev_path)
        xor_file.save(xor_path)

        # Read files
        with open(xor_path, 'rb') as f: xor_key  = f.read()
        with open(blk_path, 'rb') as f: blk_raw  = f.read()
        with open(rev_path, 'rb') as f: rev_raw  = f.read()

        # XOR decode
        from core.block_parser import parse_block_file, xor_decode
        blk_data = xor_decode(blk_raw, xor_key)
        rev_data = xor_decode(rev_raw, xor_key)

        # Parse
        parsed_blocks = parse_block_file(blk_data, rev_data)
        if not parsed_blocks:
            return jsonify({"ok": False, "error": {
                "code": "NO_BLOCKS",
                "message": "No valid blocks found in blk file. Check magic bytes / file format."
            }})

        # Derive stem from blk filename (strip .dat extension)
        blk_stem = os.path.splitext(blk_name)[0]

        # Build + write reports
        from src.output.json_report import build_json_report, write_json_report
        from src.output.md_report import write_markdown_report

        os.makedirs(OUT_DIR, exist_ok=True)
        json_out = os.path.join(OUT_DIR, f'{blk_stem}.json')
        md_out   = os.path.join(OUT_DIR, f'{blk_stem}.md')

        report = build_json_report(blk_name, parsed_blocks)
        write_json_report(report, json_out)
        write_markdown_report(report, md_out)

        return jsonify({"ok": True, "stem": blk_stem,
                        "json_output": json_out, "md_output": md_out,
                        "report": report})

    except Exception:
        tb = traceback.format_exc()
        # Log to stderr (suppressed in prod) but always return JSON
        print(tb, file=sys.stderr)
        return jsonify({"ok": False, "error": {
            "code": "ANALYSIS_ERROR",
            "message": tb.strip().split('\n')[-1]  # last line = actual error
        }}), 500

    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


# ── Serve frontend SPA ────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'src', 'web', 'public')
    if path and os.path.isfile(os.path.join(static_dir, path)):
        return send_from_directory(static_dir, path)
    return send_from_directory(static_dir, 'index.html')


if __name__ == '__main__':
    pass  # URL printed by web.sh
    app.run(host='0.0.0.0', port=PORT, debug=False)