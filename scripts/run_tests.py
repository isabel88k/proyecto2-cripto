#!/usr/bin/env python3
"""Ejecutar suite desde cualquier carpeta, sin variables de entorno manuales."""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
environment = os.environ.copy()
environment['PYTHONPATH'] = str(root/'src') + os.pathsep + environment.get('PYTHONPATH', '')
raise SystemExit(subprocess.call([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                                cwd=root, env=environment))
