#!/usr/bin/env python3
"""
vault_guardian.py
=================
Entry point for the Vault Guardian tray application.

This is the file the systemd user service (and the user) launches. It simply
delegates to tray_app.main() after making sure the app directory is on the
import path (so it works whether invoked by absolute path or from PATH).
"""

import os
import sys

# Ensure sibling modules import correctly regardless of CWD.
_APP_DIR = os.path.dirname(os.path.realpath(__file__))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from tray_app import main  # noqa: E402

if __name__ == "__main__":
    main()
