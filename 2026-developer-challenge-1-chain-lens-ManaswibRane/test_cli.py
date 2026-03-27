#!/usr/bin/env python3
"""
Run this directly on Windows to diagnose issues:
  python3 test_cli.py fixtures/transactions/multi_input_segwit.json
"""
import sys
import subprocess
import os

fixture = sys.argv[1] if len(sys.argv) > 1 else "fixtures/transactions/multi_input_segwit.json"

print(f"Python: {sys.version}")
print(f"CWD: {os.getcwd()}")
print(f"Script: {__file__}")
print(f"Fixture: {fixture}")
print()

# Import test
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from chain_lens.services.analyzer import analyze_transaction
    print("✓ Import OK")
except Exception as e:
    print(f"✗ Import FAILED: {e}")
    import traceback; traceback.print_exc()
    sys.exit(1)

# Parse test
try:
    import json
    fixture_data = json.loads(open(fixture, encoding='utf-8').read())
    result = analyze_transaction(fixture_data)
    print(f"✓ Analysis OK: txid={result.get('txid','?')[:16]}...")
    print(json.dumps(result, indent=2))
except Exception as e:
    print(f"✗ Analysis FAILED: {e}")
    import traceback; traceback.print_exc()
    sys.exit(1)