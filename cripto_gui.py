#!/usr/bin/env python3
"""Lanzador portable de la interfaz gráfica Tkinter: python3 cripto_gui.py."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from ecc_engine.gui import launch_gui

if __name__ == '__main__':
    raise SystemExit(launch_gui())
