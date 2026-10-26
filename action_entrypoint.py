#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""GitHub Action entry point for mobsfscan.

Run by absolute path rather than with `python -m` so that Python puts this
file's directory, not the scanned workspace, first on sys.path.
"""
from mobsfscan.__main__ import main


if __name__ == '__main__':
    main()
