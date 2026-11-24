#!/usr/bin/env python3
"""Punto de entrada portable: python3 cripto.py --help."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent/'src'))
from ecc_engine.cli import main

if __name__ == '__main__':
    raise SystemExit(main())
