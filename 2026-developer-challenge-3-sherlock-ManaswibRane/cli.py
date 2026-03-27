#!/usr/bin/env python3
"""
CLI chain analyzer for Bitcoin block files.
Usage: python cli.py --block <blk.dat> <rev.dat> <xor.dat>
"""
import sys
import os
import json
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.block_parser import parse_block_file, xor_decode
from src.output.json_report import build_json_report, write_json_report
from src.output.md_report import write_markdown_report


def error_exit(code: str, message: str):
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Bitcoin Chain Analyzer')
    parser.add_argument('--block', nargs=3, metavar=('BLK', 'REV', 'XOR'),
                        help='blk.dat rev.dat xor.dat files to analyze')
    args = parser.parse_args()

    if not args.block:
        error_exit('MISSING_ARGS', 'Usage: cli.sh --block <blk.dat> <rev.dat> <xor.dat>')

    blk_path, rev_path, xor_path = args.block

    # Validate files exist
    for path, label in [(blk_path, 'blk'), (rev_path, 'rev'), (xor_path, 'xor')]:
        if not os.path.isfile(path):
            error_exit('FILE_NOT_FOUND', f'{label} file not found: {path}')

    # Read files
    try:
        with open(xor_path, 'rb') as f:
            xor_key = f.read()
    except Exception as e:
        error_exit('XOR_READ_ERROR', f'Failed to read xor.dat: {e}')

    try:
        with open(blk_path, 'rb') as f:
            blk_raw = f.read()
    except Exception as e:
        error_exit('BLK_READ_ERROR', f'Failed to read blk file: {e}')

    try:
        with open(rev_path, 'rb') as f:
            rev_raw = f.read()
    except Exception as e:
        error_exit('REV_READ_ERROR', f'Failed to read rev file: {e}')

    # XOR decode
    try:
        blk_data = xor_decode(blk_raw, xor_key)
        rev_data = xor_decode(rev_raw, xor_key)
    except Exception as e:
        error_exit('XOR_DECODE_ERROR', f'XOR decoding failed: {e}')

    # Parse blocks
    try:
        parsed_blocks = parse_block_file(blk_data, rev_data)
    except Exception as e:
        error_exit('PARSE_ERROR', f'Block parsing failed: {e}')

    if not parsed_blocks:
        error_exit('NO_BLOCKS', 'No valid blocks found in blk file')

    # Derive output paths
    blk_basename = os.path.basename(blk_path)
    blk_stem = os.path.splitext(blk_basename)[0]

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')
    os.makedirs(out_dir, exist_ok=True)

    json_out = os.path.join(out_dir, f'{blk_stem}.json')
    md_out = os.path.join(out_dir, f'{blk_stem}.md')

    # Build and write reports
    try:
        report = build_json_report(blk_basename, parsed_blocks)
        write_json_report(report, json_out)
        write_markdown_report(report, md_out)
    except Exception as e:
        import traceback
        error_exit('REPORT_ERROR', f'Report generation failed: {traceback.format_exc()}')

    print(json.dumps({"ok": True, "json_output": json_out, "md_output": md_out}))
    sys.exit(0)


if __name__ == '__main__':
    main()